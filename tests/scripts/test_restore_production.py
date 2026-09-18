#!/usr/bin/env python3
"""Production-mode restore smoke: real restore.sh, real Linux binary, mocked systemctl.

tests/scripts/test_restore.py covers --data-dir (offline/disposable) mode only. This
suite covers PRODUCTION mode: the path that checks the installed binary and systemd
unit, stops the hyperdns service, replaces /opt/hyperdns members, and deliberately
leaves the service stopped for the operator to verify before starting it again.

The production path mutates a real systemd unit and a real /opt/hyperdns, so like
tests/scripts/test_install_smoke.py it never runs on the host. Allowlisted public
inputs are streamed into a networkless container where systemctl is a stub on PATH;
nothing is installed, started, pulled, or networked.

Run from any directory: python3 tests/scripts/test_restore_production.py
Windows: MSYS_NO_PATHCONV=1 wsl.exe -d Ubuntu-24.04 -u root -e python3 \
         "/mnt/c/OTHER/AI/codespace/DNS Controller/tests/scripts/test_restore_production.py"
Requires a cached golang:1.26-bookworm image and build/hyperdns-restore-fixture
(Linux amd64), which the host builds offline with GOPROXY=off.
"""

import argparse
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid


FIXTURE = Path('/restore')
GATE = 'HYPERDNS_RESTORE_PROD_CONTAINER'
BINARY_NAME = 'hyperdns-restore-fixture'

# A realistic production target before restore: a binary, its scripts, its version
# file, and a live config/database/key/cert set that the archive is about to replace.
OLD = {'data.db': b'old-db-payload-0123456789',
       'master.key': b'old-key-payload-abcdef',
       'config.json': b'{"old":true}',
       'certs/old.crt': b'old-cert-payload'}


def require_container():
    if (not Path('/.dockerenv').exists()
            or os.environ.get(GATE) != '1'
            or Path(__file__).resolve() != FIXTURE / 'test_restore_production.py'):
        raise RuntimeError('Refusing production-restore operations outside the smoke container')


# --------------------------------------------------------------------------- stubs

def load_state():
    path = FIXTURE / 'state.json'
    if path.exists():
        return json.loads(path.read_text())
    return {}


def write_state(**values):
    (FIXTURE / 'state.json').write_text(json.dumps(values))


def read_calls():
    path = FIXTURE / 'calls.jsonl'
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def systemctl(args):
    """Stub for the only external command restore.sh's production path invokes.

    Defaults model a healthy install: unit loaded, running, stop succeeds and the
    unit goes inactive. load_state() overrides model the failure modes.
    """
    require_container()
    with (FIXTURE / 'calls.jsonl').open('a') as log:
        log.write(json.dumps(['systemctl', args]) + '\n')
    state = load_state()
    if args == ['show', 'hyperdns', '--property=LoadState', '--value']:
        print(state.get('loadstate', 'loaded'))
        return 0
    if args == ['show', 'hyperdns', '--property=ActiveState', '--value']:
        if (FIXTURE / 'stopped').exists():
            print(state.get('active_after_stop', 'inactive'))
        else:
            print(state.get('active_before_stop', 'active'))
        return 0
    if args == ['stop', 'hyperdns']:
        (FIXTURE / 'stopped').touch()  # Never stops a daemon; there is none.
        return int(state.get('stop_status', 0))
    with (FIXTURE / 'unexpected').open('a') as log:
        log.write(json.dumps(['systemctl', args]) + '\n')
    print(f'Unexpected stub call: systemctl {args}', file=sys.stderr)
    return 97


# ----------------------------------------------------------------------- container

def reset():
    """Return /opt/hyperdns to a freshly installed, unrestored production state."""
    for path in (FIXTURE / 'state.json', FIXTURE / 'calls.jsonl',
                 FIXTURE / 'stopped', FIXTURE / 'unexpected'):
        if path.exists():
            path.unlink()
    for stale in Path('/root').glob('hyperdns-before-restore-*.tar.gz'):
        stale.unlink()
    target = Path('/opt/hyperdns')
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True)
    target.chmod(0o755)
    shutil.copyfile(FIXTURE / 'hyperdns', target / 'hyperdns')
    (target / 'hyperdns').chmod(0o755)
    scripts = target / 'scripts'
    scripts.mkdir()
    for name in ('restore.sh', 'uninstall.sh'):
        shutil.copyfile(FIXTURE / name, scripts / name)
        (scripts / name).chmod(0o755)
    shutil.copyfile(FIXTURE / 'version.json', target / 'version.json')
    for name, value in OLD.items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
    (target / 'certs').chmod(0o700)
    for name in ('data.db', 'master.key'):
        (target / name).chmod(0o600)
    return target


def make_archive(values, name='backup.tar.gz'):
    path = FIXTURE / name
    with tarfile.open(path, 'w:gz') as out:
        for member, value in values.items():
            info = tarfile.TarInfo(member)
            info.size = len(value)
            out.addfile(info, io.BytesIO(value))
    return path


def run_restore(archive, *flags):
    stubs = FIXTURE / 'stubs'
    env = dict(os.environ, PATH=f'{stubs}:{os.environ.get("PATH", "")}')
    return subprocess.run(['bash', str(FIXTURE / 'restore.sh'), str(archive), *flags],
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True, env=env, timeout=90)


def backup_tarballs():
    return sorted(Path('/root').glob('hyperdns-before-restore-*.tar.gz'))


def assert_untouched():
    """Nothing was replaced, archived, or asked of systemd beyond the preflight."""
    target = Path('/opt/hyperdns')
    for name, value in OLD.items():
        assert (target / name).read_bytes() == value, f'destination changed: {name}'
    assert (target / 'hyperdns').read_bytes() == (FIXTURE / 'hyperdns').read_bytes(), \
        'production binary was rewritten'
    assert backup_tarballs() == [], 'a pre-restore backup should not exist'
    assert not (FIXTURE / 'unexpected').exists(), 'restore.sh made an unstubbed call'


# ------------------------------------------------------------------------- tests

def test_production_restore_replaces_members_and_leaves_service_stopped():
    reset()
    new = {'data.db': b'new-db-payload-9876543210',
           'master.key': b'new-key-payload-fedcba',
           'config.json': b'{"new":true}',
           'certs/new.crt': b'new-cert-payload'}
    result = run_restore(make_archive(new), '--yes')
    assert result.returncode == 0, result.stderr
    target = Path('/opt/hyperdns')
    for name, value in new.items():
        assert (target / name).read_bytes() == value, f'not restored: {name}'
    for name in ('data.db', 'master.key', 'config.json', 'certs/new.crt'):
        assert (target / name).stat().st_mode & 0o777 == 0o600, f'not private: {name}'
    assert (target / 'certs').stat().st_mode & 0o777 == 0o700, 'certs not private'
    assert not (target / 'certs' / 'old.crt').exists(), 'certs was not replaced wholesale'
    assert (target / 'hyperdns').read_bytes() == (FIXTURE / 'hyperdns').read_bytes(), \
        'restore rewrote the production binary'

    backups = backup_tarballs()
    assert len(backups) == 1, f'expected one pre-restore backup, got {backups}'
    assert backups[0].stat().st_mode & 0o777 == 0o600, 'pre-restore backup not private'
    with tarfile.open(backups[0]) as backup:
        for name, value in OLD.items():
            assert backup.extractfile(name).read() == value, f'backup missing: {name}'

    calls = read_calls()
    assert ['systemctl', ['show', 'hyperdns', '--property=LoadState', '--value']] in calls, calls
    assert ['systemctl', ['stop', 'hyperdns']] in calls, 'service was not stopped'
    assert ['systemctl', ['show', 'hyperdns', '--property=ActiveState', '--value']] in calls, calls
    assert not any(args[:1] == ['start'] for _, args in calls), 'restore started the service'
    assert 'Restore complete' in result.stdout, result.stdout
    assert 'HyperDNS is STOPPED' in result.stdout, 'script did not report the service stopped'
    assert not (FIXTURE / 'unexpected').exists(), 'restore.sh made an unstubbed call'


def test_optional_members_preserved_when_absent_from_archive():
    reset()
    result = run_restore(make_archive({'data.db': b'new-db', 'master.key': b'new-key'}), '--yes')
    assert result.returncode == 0, result.stderr
    target = Path('/opt/hyperdns')
    assert (target / 'data.db').read_bytes() == b'new-db'
    assert (target / 'master.key').read_bytes() == b'new-key'
    for name in ('config.json', 'certs/old.crt'):
        assert (target / name).read_bytes() == OLD[name], f'optional member replaced: {name}'
    assert not (FIXTURE / 'unexpected').exists()


def test_check_mode_validates_without_stopping_or_writing():
    reset()
    result = run_restore(make_archive({'data.db': b'new-db', 'master.key': b'new-key',
                                       'config.json': b'{}'}), '--check')
    assert result.returncode == 0, result.stderr
    assert 'Archive layout validated' in result.stdout, result.stdout
    assert_untouched()
    assert read_calls() == [], '--check must not touch the service'


def test_prompt_without_tty_fails_and_changes_nothing():
    reset()
    result = run_restore(make_archive({'data.db': b'new-db', 'master.key': b'new-key'}))
    assert result.returncode != 0, 'a missing terminal must not be treated as consent'
    assert 'No terminal available' in result.stderr, result.stderr
    assert_untouched()
    calls = read_calls()
    assert ['systemctl', ['show', 'hyperdns', '--property=LoadState', '--value']] in calls, calls
    assert ['systemctl', ['stop', 'hyperdns']] not in calls, \
        'a declined prompt must not stop the service'


def test_archive_missing_master_key_fails_before_any_destination_change():
    reset()
    result = run_restore(make_archive({'data.db': b'new-db-only'}), '--yes')
    assert result.returncode != 0, 'a half pair must not be restored'
    assert 'both data.db and master.key' in result.stderr, result.stderr
    assert_untouched()
    assert read_calls() == [], 'an invalid archive must not reach service control'


def test_missing_production_binary_fails_before_service_control():
    reset()
    (Path('/opt/hyperdns') / 'hyperdns').unlink()
    result = run_restore(make_archive({'data.db': b'new-db', 'master.key': b'new-key'}), '--yes')
    assert result.returncode != 0, 'an empty install must not be restored into'
    assert 'Install the HyperDNS binary before restoring' in result.stderr, result.stderr
    for name, value in OLD.items():
        assert (Path('/opt/hyperdns') / name).read_bytes() == value, f'changed: {name}'
    assert backup_tarballs() == []
    assert read_calls() == [], 'binary check must precede every systemctl call'


def test_unloaded_service_fails_without_stopping_or_writing():
    reset()
    write_state(loadstate='not-found')
    result = run_restore(make_archive({'data.db': b'new-db', 'master.key': b'new-key'}), '--yes')
    assert result.returncode != 0, 'an unloaded unit must not be restored against'
    assert 'Install the HyperDNS systemd service before restoring' in result.stderr, result.stderr
    assert_untouched()
    assert not (FIXTURE / 'stopped').exists(), 'restore stopped a unit it never verified'
    assert ['systemctl', 'stop', 'hyperdns'] not in read_calls()


def test_stop_failure_aborts_before_any_destination_change():
    reset()
    write_state(stop_status=5)
    result = run_restore(make_archive({'data.db': b'new-db', 'master.key': b'new-key'}), '--yes')
    assert result.returncode != 0, 'a failed shutdown must abort the restore'
    assert 'non-zero exit status 5' in result.stderr, result.stderr
    assert_untouched()


def test_service_still_active_after_stop_aborts_without_replacing_data():
    reset()
    write_state(active_after_stop='active')
    result = run_restore(make_archive({'data.db': b'new-db', 'master.key': b'new-key'}), '--yes')
    assert result.returncode != 0, 'a still-running service must abort the restore'
    assert 'Service did not stop' in result.stderr, result.stderr
    assert_untouched()


def test_data_dir_on_production_target_is_rejected():
    reset()
    result = run_restore(make_archive({'data.db': b'new-db', 'master.key': b'new-key'}),
                         '--data-dir', '/opt/hyperdns', '--yes')
    assert result.returncode != 0, '--data-dir must not bypass service control'
    assert 'Use the default mode for /opt/hyperdns' in result.stderr, result.stderr
    assert_untouched()
    assert read_calls() == []


def test_concurrent_restore_lock_is_taken_and_released():
    reset()
    archive = make_archive({'data.db': b'new-db', 'master.key': b'new-key'})
    target = Path('/opt/hyperdns')
    holder = subprocess.Popen(
        ['python3', '-c',
         'import fcntl,os,sys,time;'
         'fd=os.open(sys.argv[1],os.O_RDONLY|os.O_DIRECTORY);'
         'fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);'
         'time.sleep(float(sys.argv[2]))', str(target), '4'],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        time.sleep(0.5)  # Let the sibling process take the lock before restoring.
        result = run_restore(archive, '--yes')
        assert result.returncode != 0, 'a locked directory must not be restored into'
        assert 'Another restore is already using this directory' in result.stderr, result.stderr
        assert_untouched()
    finally:
        holder.wait(timeout=10)
        holder.stdout.close()
        holder.stderr.close()


TESTS = [
    ('production restore replaces members and leaves service stopped',
     test_production_restore_replaces_members_and_leaves_service_stopped),
    ('optional config/certs preserved when absent from archive',
     test_optional_members_preserved_when_absent_from_archive),
    ('--check validates without stopping or writing',
     test_check_mode_validates_without_stopping_or_writing),
    ('prompt without a tty fails and changes nothing',
     test_prompt_without_tty_fails_and_changes_nothing),
    ('archive missing master.key fails before any destination change',
     test_archive_missing_master_key_fails_before_any_destination_change),
    ('missing production binary fails before service control',
     test_missing_production_binary_fails_before_service_control),
    ('unloaded service fails without stopping or writing',
     test_unloaded_service_fails_without_stopping_or_writing),
    ('systemctl stop failure aborts before any destination change',
     test_stop_failure_aborts_before_any_destination_change),
    ('service still active after stop aborts without replacing data',
     test_service_still_active_after_stop_aborts_without_replacing_data),
    ('--data-dir on the production target is rejected',
     test_data_dir_on_production_target_is_rejected),
    ('concurrent restore lock is taken and released',
     test_concurrent_restore_lock_is_taken_and_released),
]


def inside():
    require_container()
    stubs = FIXTURE / 'stubs'
    stubs.mkdir(exist_ok=True)
    stub = stubs / 'systemctl'
    stub.write_text('#!/bin/sh\n'
                    'exec /usr/bin/python3 /restore/test_restore_production.py --stub "$@"\n')
    stub.chmod(0o755)
    Path('/root').mkdir(parents=True, exist_ok=True)
    reset()

    passed, failed = [], []
    for name, test in TESTS:
        try:
            test()
        except Exception as exc:
            failed.append(name)
            print(f'FAIL: {name}\n      {type(exc).__name__}: {exc}')
        else:
            passed.append(name)
            print(f'PASS: {name}')

    print()
    print(f'RESULT: {len(passed)} passed, {len(failed)} failed')
    if failed:
        for name in failed:
            print('  failed: ' + name)
        sys.exit(1)
    print('REAL: unchanged scripts/restore.sh bytes, Go production binary on disk, '
          'tar/gzip/rename/chmod/flock syscall results under /opt/hyperdns and /root')
    print('MOCKED: systemctl (load/active state and stop); no daemon, systemd or network')


# -------------------------------------------------------------------------- host

def build_fixture(repo, goproxy):
    fixture = repo / 'build' / BINARY_NAME
    if fixture.exists():
        return fixture
    env = dict(os.environ, GOOS='linux', GOARCH='amd64', CGO_ENABLED='0',
               GOPROXY=goproxy, GOSUMDB='off')
    build = ['go', 'build', '-trimpath', '-o', str(fixture), './cmd/hyperdns']
    print('BUILD (offline, linux/amd64): ' + ' '.join(build), flush=True)
    subprocess.run(build, cwd=repo, env=env, check=True, timeout=600)
    return fixture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='golang:1.26-bookworm',
                        help='Cached Linux amd64 image with bash/python3/coreutils')
    parser.add_argument('--wsl', default='Ubuntu-24.04',
                        help='Windows WSL distribution with Docker (ignored on Linux)')
    parser.add_argument('--goproxy', default='off',
                        help='GOPROXY for the fixture build when it is missing')
    args = parser.parse_args()

    repo = Path(__file__).resolve().parents[2]
    docker = (['wsl.exe', '-d', args.wsl, '-u', 'root', '-e', 'docker']
              if os.name == 'nt' else ['docker'])
    subprocess.run(docker + ['image', 'inspect', args.image], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    fixture = build_fixture(repo, args.goproxy)
    raw = fixture.read_bytes()
    assert raw[:4] == b'\x7fELF', 'fixture is not a Linux ELF binary; rebuild it for linux/amd64'

    # Do not tar the repo: it may contain private configs, databases and keys.
    # .gitattributes requires eol=lf for *.sh; CRLF would abort bash on Linux, and
    # the test says so instead of silently rewriting the script under test.
    # HYPERDNS_RESTORE_SCRIPT points this suite at a deliberately broken copy of the
    # script for negative verification (it must go red). Empty means the real one.
    script = repo / (os.environ.get('HYPERDNS_RESTORE_SCRIPT') or 'scripts/restore.sh')
    script_bytes = script.read_bytes()
    assert b'\x00' not in script_bytes, 'scripts/restore.sh is not text'
    assert b'\r' not in script_bytes, \
        'scripts/restore.sh working-tree bytes contain CR; normalize to LF first.'

    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode='w') as archive:
        members = [(fixture, 'hyperdns'),
                   (script, 'restore.sh'),
                   (repo / 'scripts' / 'uninstall.sh', 'uninstall.sh'),
                   (repo / 'config.example.json', 'config.example.json'),
                   (repo / 'offline-bundle' / 'version.json', 'version.json'),
                   (Path(__file__).resolve(), 'test_restore_production.py')]
        for source, name in members:
            info = tarfile.TarInfo(name)
            raw = Path(source).read_bytes()
            info.size = len(raw)
            info.mode = 0o755
            archive.addfile(info, io.BytesIO(raw))

    container = 'hyperdns-restore-prod-' + uuid.uuid4().hex[:12]
    command = docker + ['run', '--rm', '--pull=never', '--network=none',
                        '--cap-drop=ALL', '--security-opt=no-new-privileges',
                        '--pids-limit=128', '--memory=512m', '--user=0:0',
                        '--name', container, '-i', '-e', GATE + '=1',
                        '--entrypoint=/bin/bash', args.image, '-c',
                        'mkdir /restore && tar xf - -C /restore '
                        '&& python3 /restore/test_restore_production.py --inside']
    print('RUN: ' + subprocess.list2cmdline(command), flush=True)
    try:
        subprocess.run(command, input=payload.getvalue(), check=True, timeout=240)
    finally:
        subprocess.run(docker + ['rm', '-f', container], stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=20)


if __name__ == '__main__':
    if sys.argv[1:2] == ['--inside']:
        inside()
    elif sys.argv[1:2] == ['--stub']:
        sys.exit(systemctl(sys.argv[2:]))
    else:
        main()
