#!/usr/bin/env bash
set -euo pipefail

command -v python3 >/dev/null 2>&1 || { printf '%s\n' 'Error: python3 is required.' >&2; exit 1; }
exec python3 - "$@" <<'PY'
import argparse
import fcntl
import json
import signal
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

parser = argparse.ArgumentParser(description='Restore a HyperDNS uninstall backup. Install HyperDNS first. The service is left stopped after restoration.')
parser.add_argument('archive', type=Path, help='hyperdns-backup-*.tar.gz (uninstall format only)')
parser.add_argument('--yes', '-y', action='store_true', help='confirm replacement without a prompt; current data is still backed up')
parser.add_argument('--check', action='store_true', help='validate archive layout without changing files or stopping the service')
parser.add_argument('--data-dir', type=Path, help='data-only restore to an existing disposable/offline directory; no service control')
args = parser.parse_args()
NAMES = ('config.json', 'data.db', 'master.key', 'certs')
MAX_BYTES = 2 * 1024**3
MAX_MEMBERS = 10000


def fail(message):
    raise ValueError(message)


def plain_tree(path):
    if path.is_symlink():
        fail('Links are not allowed in restore destinations.')
    mode = path.stat().st_mode
    if stat.S_ISDIR(mode):
        for child in path.iterdir():
            plain_tree(child)
    elif not stat.S_ISREG(mode):
        fail('Only regular files and directories may be backed up.')


def private_tree(path):
    if path.is_dir():
        path.chmod(0o700)
        for child in path.iterdir():
            private_tree(child)
    else:
        path.chmod(0o600)


def stage_archive(archive, stage):
    if not archive.is_file():
        fail('Backup archive does not exist or is not a file.')
    seen = set()
    entries = []
    total = 0
    with tarfile.open(archive, 'r:gz') as source:
        for member in source:
            if len(entries) >= MAX_MEMBERS:
                fail('Archive has too many members.')
            name = member.name
            if name.startswith('./'):
                name = name[2:]
            name = name.rstrip('/')
            if name in ('', '.') and member.isdir():
                continue
            parts = name.split('/')
            if any(part in ('', '.', '..') for part in parts) or '\\' in name:
                fail('Archive contains an unsafe path.')
            if parts[0] not in NAMES or (len(parts) > 1 and parts[0] != 'certs'):
                fail('Not an uninstall backup: unexpected archive member.')
            if name in seen:
                fail('Archive contains duplicate members.')
            if not (member.isfile() or member.isdir()) or (parts[0] != 'certs' and not member.isfile()):
                fail('Archive links, special files and invalid directories are not supported.')
            if name == 'certs' and not member.isdir():
                fail('certs must be a directory.')
            seen.add(name)
            entries.append((member, name))
            total += member.size
            if member.size < 0 or total > MAX_BYTES:
                fail('Archive exceeds the 2 GiB restore limit.')
        if not {'data.db', 'master.key'}.issubset(seen):
            fail('Backup must contain both data.db and master.key; never restore them separately.')
        # Copy bytes, not archive metadata: owners, links and modes are not trusted.
        for member, name in entries:
            output = stage / name
            if member.isdir():
                output.mkdir(parents=True, exist_ok=True, mode=0o700)
            else:
                output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with source.extractfile(member) as src, output.open('xb') as dst:
                    shutil.copyfileobj(src, dst)
                if output.stat().st_size != member.size:
                    fail('Archive file is truncated.')
        for name in ('data.db', 'master.key'):
            if not (stage / name).stat().st_size:
                fail('Database and key must not be empty.')
        if (stage / 'config.json').exists():
            with (stage / 'config.json').open() as config:
                if not isinstance(json.load(config), dict):
                    fail('config.json must contain a JSON object.')
    private_tree(stage)


def run():
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix='hyperdns-restore-check-') as scratch:
        staged = Path(scratch)
        stage_archive(args.archive, staged)
        print('Archive layout validated. This does not verify database integrity or that its key decrypts it.', flush=True)
        if args.check:
            return
        data_only = args.data_dir is not None
        target = Path(os.path.abspath(args.data_dir or '/opt/hyperdns'))
        if data_only and target == Path('/opt/hyperdns'):
            fail('Use the default mode for /opt/hyperdns so its service is stopped safely.')
        if not data_only and os.geteuid() != 0:
            fail('Run with sudo or as root.')
        if target == Path('/') or not target.is_dir():
            fail('Restore directory must already exist. Install HyperDNS first.')
        for ancestor in (target, *target.parents):
            if ancestor.is_symlink():
                fail('Restore directory and its parents must not be symlinks.')
        lock_fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(lock_fd)
            fail('Another restore is already using this directory.')
        for name in NAMES:
            path = target / name
            if path.exists() or path.is_symlink():
                plain_tree(path)
                if (name == 'certs') != path.is_dir():
                    fail('Destination has an unexpected file type.')
        if not data_only:
            if not (target / 'hyperdns').is_file():
                fail('Install the HyperDNS binary before restoring.')
            state = subprocess.check_output(['systemctl', 'show', 'hyperdns', '--property=LoadState', '--value'], text=True).strip()
            if state != 'loaded':
                fail('Install the HyperDNS systemd service before restoring.')
        print('Target: ' + str(target), flush=True)
        print('Replaces archived data and settings. Missing optional config/certs are left unchanged.', flush=True)
        if data_only:
            print('Data-only mode: no service control. Ensure nothing is using this directory.', flush=True)
        if not args.yes:
            try:
                with open('/dev/tty', 'r+') as tty:
                    tty.write('Type RESTORE to replace current data (a rollback backup will be kept): ')
                    tty.flush()
                    if tty.readline().strip() != 'RESTORE':
                        fail('Cancelled; no destination files changed.')
            except OSError:
                fail('No terminal available. Use --yes only after reviewing the backup and target.')
        # Prepare on the destination filesystem so each replacement is a rename.
        with tempfile.TemporaryDirectory(prefix='.hyperdns-restore-', dir=target.parent) as work:
            work = Path(work)
            incoming = work / 'incoming'
            shutil.copytree(staged, incoming)
            private_tree(incoming)
            original = work / 'original'
            original.mkdir(mode=0o700)
            if not data_only:
                subprocess.run(['systemctl', 'stop', 'hyperdns'], check=True)
                state = subprocess.check_output(['systemctl', 'show', 'hyperdns', '--property=ActiveState', '--value'], text=True).strip()
                if state not in ('inactive', 'failed'):
                    fail('Service did not stop; no data was replaced.')
            backup_dir = target.parent if data_only else Path('/root')
            fd, backup = tempfile.mkstemp(prefix='hyperdns-before-restore-', suffix='.tar.gz', dir=backup_dir)
            os.close(fd)
            with tarfile.open(backup, 'w:gz', dereference=False) as out:
                for name in NAMES:
                    if (target / name).exists():
                        out.add(target / name, arcname=name)
            print('Current state backup: ' + backup, flush=True)
            moved = []
            installed = []
            try:
                for name in NAMES:
                    if not (incoming / name).exists():
                        continue
                    if (target / name).exists():
                        os.replace(target / name, original / name)
                        moved.append(name)
                    os.replace(incoming / name, target / name)
                    installed.append(name)
            except BaseException:
                signal.signal(signal.SIGINT, signal.SIG_IGN)
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                try:
                    for name in reversed(installed):
                        path = target / name
                        if path.is_dir():
                            shutil.rmtree(path)
                        else:
                            path.unlink()
                    for name in moved:
                        os.replace(original / name, target / name)
                except BaseException:
                    recovery = Path(tempfile.mkdtemp(prefix='hyperdns-restore-recovery-', dir=target.parent))
                    os.replace(original, recovery / 'original')
                    print('Rollback incomplete. Original files retained at: ' + str(recovery), file=sys.stderr)
                    print('Complete pre-restore archive: ' + backup, file=sys.stderr)
                    raise
                raise
        print('Restore complete. Database and key were both restored; retain backups until the application has been checked.')
        if not data_only:
            print('HyperDNS is STOPPED. Check restored domains, ports and firewall rules, then run: systemctl start hyperdns')
            print('Restored credentials and panel path replace those from the fresh installation.')
        print('Keep the original archive and the pre-restore backup private.')


def interrupted(signum, frame):
    raise KeyboardInterrupt('Interrupted; restore is stopping.')


signal.signal(signal.SIGTERM, interrupted)
try:
    run()
except (Exception, KeyboardInterrupt) as exc:
    print('Restore failed: ' + str(exc), file=sys.stderr)
    print('If service shutdown was reached, HyperDNS remains stopped. Do not start it until the error is resolved.', file=sys.stderr)
    sys.exit(1)
PY
