#!/usr/bin/env python3
"""Regression test: installer drop-ins stay readable under a restrictive umask.

The online and offline installers write /etc/systemd/resolved.conf.d/hyperdns.conf
via a shell redirect. The drop-in is consumed by systemd-resolved, which runs as
its own unprivileged user — not root — so a file created under umask 077 is
unreadable by it, silently ignored, and the 127.0.0.53:53 stub listener stays
bound. The daemon then fails to bind port 53 over a conflict the installer was
explicitly asked to clear (observed on a real hardened VPS).

Runs the real installer scripts inside a disposable, networkless container under
umask 077. systemctl/curl/journalctl are stubbed; nothing is installed on the
host, no network is reached, no daemon is started.
"""
import argparse
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import uuid

FIXTURE = Path('/umask')
REF = 'v2.2.0-beta.1-umask-pinned'
DOMAIN = 'installer-umask.invalid'
ADMIN_PATH = '0123456789abcdef'

DROPIN_DIR = Path('/etc/systemd/resolved.conf.d')
DROPIN = DROPIN_DIR / 'hyperdns.conf'


def require_container():
    if (not Path('/.dockerenv').exists()
            or os.environ.get('HYPERDNS_UMASK_CONTAINER') != '1'
            or Path(__file__).resolve() != FIXTURE / 'test_installer_umask.py'):
        raise RuntimeError('Refusing container-only operations outside the umask container')


def stub(command, args):
    require_container()
    if command == 'systemctl':
        # systemd-resolved reports active so the port-53 step actually runs;
        # hyperdns is never started by this test.
        if args == ['is-active', '--quiet', 'systemd-resolved']:
            return 0
        if args == ['is-active', '--quiet', 'hyperdns']:
            return 3
        if args in (['restart', 'systemd-resolved'],
                    ['daemon-reload'], ['enable', 'hyperdns'],
                    ['restart', 'hyperdns'], ['stop', 'hyperdns']):
            return 0
        if args == ['show', 'hyperdns', '--property=LoadState', '--value']:
            print('loaded')
            return 0
        if args == ['show', 'hyperdns', '--property=ActiveState', '--value']:
            print('inactive')
            return 0
    elif command == 'curl':
        # Serve the staged local artifacts so the online installer passes its
        # download step without a network. Mode is what this test is about, so
        # the bytes themselves are irrelevant as long as they are plausible.
        urls = [a for a in args if a.startswith('https://')]
        if len(urls) == 1 and '-o' in args:
            url = urls[0]
            out = args[args.index('-o') + 1]
            if '/hyperdns-linux-amd64' in url:
                shutil.copyfile(FIXTURE / 'hyperdns', out)
                return 0
            if url.endswith('/config.example.json'):
                shutil.copyfile(FIXTURE / 'config.example.json', out)
                return 0
            if url.endswith('/scripts/restore.sh'):
                shutil.copyfile(FIXTURE / 'scripts' / 'restore.sh', out)
                return 0
            if url.endswith('/version.json'):
                shutil.copyfile(FIXTURE / 'offline-bundle' / 'version.json', out)
                return 0
            if url == 'https://api.ipify.org':
                print('192.0.2.10')
                return 0
        return 0
    elif command == 'journalctl':
        print('-- cursor: umask-cursor')
        return 0
    elif command in ('ufw', 'dig'):
        return 0
    print(f'Unexpected stub call: {command} {args}', file=sys.stderr)
    return 97


def inside():
    require_container()
    # The whole point of the test: the caller's umask is restrictive.
    os.umask(0o077)
    Path('/etc/systemd/system').mkdir(parents=True, exist_ok=True)
    stubs = FIXTURE / 'stubs'
    stubs.mkdir()
    for command in ('curl', 'systemctl', 'journalctl', 'ufw', 'dig'):
        script = stubs / command
        script.write_text(f'#!/bin/sh\nexec /usr/bin/python3 {FIXTURE}/test_installer_umask.py --stub {command} "$@"\n')
        script.chmod(0o755)
    env = dict(os.environ, PATH=f'{stubs}:/usr/bin:/bin', TERM='dumb',
               HYPERDNS_REF=REF, HYPERDNS_DOMAIN=DOMAIN,
               HYPERDNS_EMAIL='umask@example.invalid')

    failures = []
    # The archive preserves paths (scripts/install.sh), so the staged copies live
    # one level under the fixture, not in it.
    for name, script in (('online', 'scripts/install.sh'),
                         ('offline', 'scripts/install-offline.sh'),
                         ('bundle', 'offline-bundle/install.sh')):
        path = FIXTURE / script
        if not path.exists():
            failures.append(f'{name}: {script} was not staged into the container')
            continue
        result = subprocess.run(['bash', str(path)], cwd=path.parent, env=env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, timeout=90)
        # The installer may legitimately fail on a stubbed environment; the
        # defect under test is the file's mode, not the installer's exit status.
        # What matters is that the drop-in exists AND is readable by other.
        if not DROPIN.exists():
            tail = '\n'.join(result.stdout.splitlines()[-12:])
            failures.append(f'{name}: drop-in was never written (installer exit {result.returncode})\n{tail}')
            continue
        mode = stat_mode(DROPIN)
        dir_mode = stat_mode(DROPIN_DIR)
        if mode & 0o044 != 0o044:
            failures.append(f'{name}: drop-in mode {mode:04o} is not readable by other')
        if dir_mode & 0o055 != 0o055:
            failures.append(f'{name}: drop-in dir mode {dir_mode:04o} is not readable/traversable by other')
        if b'DNSStubListener=no' not in DROPIN.read_bytes():
            failures.append(f'{name}: drop-in content is wrong')

    if failures:
        for f in failures:
            print('FAIL: ' + f, file=sys.stderr)
        sys.exit(1)
    print('PASS: all installers wrote a world-readable resolved drop-in under umask 077')
    print(f'  dir: {stat_mode(DROPIN_DIR):04o}  file: {stat_mode(DROPIN):04o}')


def stat_mode(path):
    return path.stat().st_mode & 0o777


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='golang:1.26-bookworm')
    parser.add_argument('--wsl', default='Ubuntu-24.04')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    docker = (['wsl.exe', '-d', args.wsl, '-u', 'root', '-e', 'docker']
              if os.name == 'nt' else ['docker'])
    subprocess.run(docker + ['image', 'inspect', args.image], check=True,
                   stdout=subprocess.DEVNULL)
    (repo / 'build').mkdir(exist_ok=True)
    # The fixture binary is cross-built on the Windows host (WSL has no Go) and
    # staged by relative path; the script finds it next to the repo layout.
    binary = repo / 'build' / 'hyperdns-umask-fixture'
    if not binary.exists():
        raise SystemExit(f'Build the fixture first: CGO_ENABLED=0 GOOS=linux GOARCH=amd64 '
                         f'go build -trimpath -o {binary} ./cmd/hyperdns')
    assert binary.read_bytes()[:4] == b'\x7fELF', 'fixture is not a Linux ELF'

    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode='w') as archive:
        # arcname keeps the repo-relative layout, which the in-container lookup
        # (FIXTURE/'scripts'/'install.sh') matches.
        members = [repo / 'scripts' / 'install.sh',
                   repo / 'scripts' / 'install-offline.sh',
                   repo / 'offline-bundle' / 'install.sh',
                   repo / 'scripts' / 'restore.sh',
                   repo / 'config.example.json',
                   repo / 'offline-bundle' / 'version.json',
                   Path(__file__).resolve()]
        extra = {binary: 'hyperdns'}
        for source in members:
            if not Path(source).exists():
                continue
            name = str(Path(source).relative_to(repo))
            raw = Path(source).read_bytes()
            assert b'\r' not in raw, f'{name} has CRLF; bash on Linux aborts on it'
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            info.mode = 0o755
            archive.addfile(info, io.BytesIO(raw))
        # The fixture binary is staged flat; the curl stub copies it.
        for source, flat in extra.items():
            raw = Path(source).read_bytes()
            info = tarfile.TarInfo(flat)
            info.size = len(raw)
            info.mode = 0o755
            archive.addfile(info, io.BytesIO(raw))

    name = 'hyperdns-umask-' + uuid.uuid4().hex[:12]
    command = docker + ['run', '--rm', '--pull=never', '--network=none',
                        '--cap-drop=ALL', '--cap-add=CHOWN',
                        '--security-opt=no-new-privileges', '--pids-limit=128',
                        '--memory=512m', '--user=0:0', '--name', name, '-i',
                        '-e', 'HYPERDNS_UMASK_CONTAINER=1',
                        '--entrypoint=/bin/bash', args.image, '-c',
                        'mkdir /umask && tar xf - -C /umask && '
                        'cp /umask/tests/scripts/test_installer_umask.py /umask/test_installer_umask.py && '
                        'python3 /umask/test_installer_umask.py --inside']
    print('RUN: ' + subprocess.list2cmdline(command), flush=True)
    try:
        subprocess.run(command, input=payload.getvalue(), check=True, timeout=120)
    finally:
        subprocess.run(docker + ['rm', '-f', name], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=20)


if __name__ == '__main__':
    if sys.argv[1:2] == ['--inside']:
        inside()
    elif sys.argv[1:2] == ['--stub']:
        sys.exit(stub(sys.argv[2], sys.argv[3:]))
    else:
        main()
