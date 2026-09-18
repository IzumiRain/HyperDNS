#!/usr/bin/env python3
"""Offline integration smoke: real install.sh and locally built Linux binary.

Run from any directory: python tests/scripts/test_install_smoke.py
Windows uses WSL Ubuntu-24.04's Docker as root; Linux uses local Docker.
Requires Go with cached modules and a cached golang:1.26-bookworm image.
No image pulls, network access, host mounts, production edits, or real services.
Only allowlisted public inputs are streamed into a disposable container.
"""

import argparse
import hashlib
import io
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import uuid


FIXTURE = Path('/smoke')
REF = 'v2.2.0-beta.1-smoke-pinned'
DOMAIN = 'installer-smoke.invalid'
ADMIN_PATH = '0123456789abcdef'


def downloads():
    raw = f'https://raw.githubusercontent.com/IzumiRain/HyperDNS/{REF}'
    release = f'https://github.com/IzumiRain/HyperDNS/releases/download/{REF}'
    return {
        f'{release}/hyperdns-linux-amd64': 'hyperdns',
        f'{raw}/config.example.json': 'config.example.json',
        f'{raw}/scripts/restore.sh': 'restore.sh',
        f'{raw}/offline-bundle/version.json': 'version.json',
    }


def require_container():
    if (not Path('/.dockerenv').exists()
            or os.environ.get('HYPERDNS_SMOKE_CONTAINER') != '1'
            or Path(__file__).resolve() != FIXTURE / 'test_install_smoke.py'):
        raise RuntimeError('Refusing container-only operations outside the smoke container')


def stub(command, args):
    require_container()
    with (FIXTURE / 'calls.jsonl').open('a') as log:
        log.write(json.dumps([command, args]) + '\n')
    if command == 'curl':
        urls = [arg for arg in args if arg.startswith('https://')]
        if len(urls) == 1:
            url = urls[0]
            if url in downloads() and '-o' in args:
                shutil.copyfile(FIXTURE / downloads()[url], args[args.index('-o') + 1])
                return 0
            if url == 'https://api.ipify.org':
                print('192.0.2.10')
                return 0
            port = json.loads(Path('/opt/hyperdns/config.json').read_text())['server']['web_port'] if Path('/opt/hyperdns/config.json').exists() else 0
            probes = [f'https://{DOMAIN}:{port}/{ADMIN_PATH}/{path}'
                      for path in ('dash/', 'css/tailwind.purged.css', 'js/app.js')]
            if url in probes and '-w' in args:
                print('200', end='')  # Synthetic health, NOT a TLS/ACME test.
                return 0
    elif command == 'systemctl':
        if args == ['is-active', '--quiet', 'hyperdns']:
            return 0 if (FIXTURE / 'started').exists() else 3
        if args in (['is-enabled', '--quiet', 'hyperdns'],
                    ['is-active', '--quiet', 'systemd-resolved']):
            return 3
        if args == ['restart', 'hyperdns']:
            (FIXTURE / 'started').touch()  # Never starts the daemon.
            return 0
        if args in (['daemon-reload'], ['enable', 'hyperdns']):
            return 0
    elif command == 'journalctl':
        if args == ['-u', 'hyperdns', '-n', '0', '--show-cursor']:
            print('-- cursor: smoke-cursor')
            return 0
        if args == ['-u', 'hyperdns', '--no-pager', '--after-cursor=smoke-cursor']:
            port = json.loads(Path('/opt/hyperdns/config.json').read_text())['server']['web_port']
            print(f'Dashboard : https://0.0.0.0:{port}/{ADMIN_PATH}/dash/login')
            return 0
    elif command == 'ufw':
        if args == ['show', 'added'] or (len(args) == 2 and args[0] == 'allow' and args[1].isdigit()):
            return 0
    elif command == 'dig' and args == ['+short', DOMAIN, 'A']:
        print('192.0.2.10')
        return 0
    # Record unexpected calls even if install.sh suppresses their exit status.
    with (FIXTURE / 'unexpected').open('a') as log:
        log.write(json.dumps([command, args]) + '\n')
    print(f'Unexpected stub call: {command} {args}', file=sys.stderr)
    return 97


def inside():
    require_container()
    target = Path('/opt/hyperdns')
    assert not target.exists(), 'Expected a clean container, not an existing install'
    Path('/etc/systemd/system').mkdir(parents=True, exist_ok=True)
    stubs = FIXTURE / 'stubs'
    stubs.mkdir()
    for command in ('curl', 'systemctl', 'journalctl', 'ufw', 'dig'):
        script = stubs / command
        script.write_text(f'#!/bin/sh\nexec /usr/bin/python3 /smoke/test_install_smoke.py --stub {command} "$@"\n')
        script.chmod(0o755)
    env = dict(os.environ, PATH=f'{stubs}:/usr/bin:/bin', TERM='dumb',
               HYPERDNS_REF=REF, HYPERDNS_DOMAIN=DOMAIN,
               HYPERDNS_EMAIL='smoke@example.invalid')
    result = subprocess.run(['bash', '-x', '/smoke/install.sh'], cwd=FIXTURE,
                            env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, timeout=45)
    (FIXTURE / 'installer.trace').write_text(result.stdout)
    if result.returncode != 0:
        print('LAST 50 INSTALLER XTRACE LINES (set -e enabled by installer, exit {}):'.format(result.returncode))
        for line in result.stdout.splitlines()[-50:]:
            if re.search(r'(GENERATED_(ADMIN_PASSWORD|API_KEY)=)|([0-9a-f]{24,64})', line):
                line = line.split(' ', 1)[0] + ' <redacted>'
            print(line)
        raise AssertionError(f'Installer exit: {result.returncode}')
    try:
        assert result.returncode == 0, f'Installer exit: {result.returncode}'
        assert not (FIXTURE / 'unexpected').exists(), 'Unexpected external command/URL'
        calls = [json.loads(line) for line in (FIXTURE / 'calls.jsonl').read_text().splitlines()]
        fetched = [next(arg for arg in args if arg.startswith('https://'))
                   for command, args in calls if command == 'curl' and '-o' in args
                   and args[args.index('-o') + 1] != '/dev/null']
        assert sorted(fetched) == sorted(downloads()), f'Wrong pinned downloads: {fetched}'
        assert all(f'/{REF}/' in url for url in fetched)
        for name, installed in [('hyperdns', target / 'hyperdns'),
                                ('restore.sh', target / 'scripts/restore.sh'),
                                ('version.json', target / 'version.json')]:
            assert installed.read_bytes() == (FIXTURE / name).read_bytes(), f'Not exact: {name}'
        assert (target / 'hyperdns').read_bytes()[:4] == b'\x7fELF', 'Not a real Linux binary'
        assert os.access(target / 'hyperdns', os.X_OK)
        assert (target / 'scripts/restore.sh').stat().st_mode & 0o777 == 0o755
        assert Path('/usr/local/bin/hdns').resolve() == target / 'hyperdns'
        # Execute ONLY the real pre-DB version command, never daemon/ACME startup.
        version = subprocess.check_output([str(target / 'hyperdns'), '-version'],
                                          cwd=target, text=True, timeout=10).strip()
        metadata = json.loads((target / 'version.json').read_text())
        display = 'v' + metadata['version'] + ('-' + metadata['channel'] if metadata['channel'] else '')
        semantic = {key: metadata[key] for key in ('version', 'channel', 'codename')}
        fingerprint = hashlib.sha256(json.dumps(semantic, sort_keys=True, separators=(',', ':'),
                                                ensure_ascii=False).encode()).hexdigest()[:8]
        assert display in version and f'hash:{fingerprint}' in version, (metadata, version)
        assert not (target / 'data.db').exists(), 'Version command unexpectedly initialized DB'
        assert sum('endpoint verified on port' in line for line in result.stdout.splitlines()
                   if not line.startswith('+')) == 3, 'Did not exercise all health probes'
        print('PASS: actual scripts/install.sh exit 0; all four artifact URLs share HYPERDNS_REF')
        for url in fetched:
            print('  ' + url)
        print('PASS: installed binary is byte-identical to the local Go build, executable ELF')
        print('  binary sha256: ' + hashlib.sha256((target / 'hyperdns').read_bytes()).hexdigest())
        print('PASS: installed version.json is exact and matches real binary -version + semantic hash')
        print('  ' + version)
        print('PASS: installed scripts/restore.sh is byte-identical and mode 0755; hdns symlink correct')
        print('REAL: full unchanged installer, Go binary -version, file writes/copies/modes, config generation')
        print('MOCKED: curl downloads/IP/HTTPS, systemctl, journalctl, dig, ufw; no daemon or ACME started')
    except Exception:
        print('Post-install assertion failed; installer exited 0. Trace remains container-only.', file=sys.stderr)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', default='golang:1.26-bookworm', help='Cached Linux amd64 image with bash/python3/openssl/coreutils')
    parser.add_argument('--wsl', default='Ubuntu-24.04', help='Windows WSL distribution with Docker')
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    docker = (['wsl.exe', '-d', args.wsl, '-u', 'root', '-e', 'docker']
              if os.name == 'nt' else ['docker'])
    subprocess.run(docker + ['image', 'inspect', args.image], check=True, stdout=subprocess.DEVNULL)
    (repo / 'build').mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='installer-smoke-', dir=repo / 'build') as temp:
        binary = Path(temp) / 'hyperdns'
        env = dict(os.environ, GOOS='linux', GOARCH='amd64', CGO_ENABLED='0',
                   GOPROXY='off', GOSUMDB='off', GOTOOLCHAIN='local')
        build = ['go', 'build', '-trimpath', '-o', str(binary), './cmd/hyperdns']
        print('BUILD (offline, linux/amd64): ' + ' '.join(build), flush=True)
        subprocess.run(build, cwd=repo, env=env, check=True, timeout=180)
        # Do not tar the repo: it may contain private configs, databases, and keys.
        # The installer runs its exact working-tree bytes. .gitattributes requires
        # eol=lf for *.sh; if the tree still has CRLF the test fails here and says
        # so instead of silently rewriting the script under test.
        script_bytes = (repo / 'scripts/install.sh').read_bytes()
        assert b'\x00' not in script_bytes, 'install.sh is not text'
        assert b'\r' not in script_bytes, \
            'install.sh working-tree bytes contain CR; bash on Linux aborts on CRLF. ' \
            'Normalize scripts/install.sh to LF first; this test never rewrites it.'
        payload = io.BytesIO()
        with tarfile.open(fileobj=payload, mode='w') as archive:
            for source, name in [(binary, 'hyperdns'),
                                 (repo / 'scripts/install.sh', 'install.sh'),
                                 (repo / 'scripts/restore.sh', 'restore.sh'),
                                 (repo / 'config.example.json', 'config.example.json'),
                                 (repo / 'offline-bundle/version.json', 'version.json'),
                                 (Path(__file__).resolve(), 'test_install_smoke.py')]:
                info = tarfile.TarInfo(name)
                raw = Path(source).read_bytes()
                info.size = len(raw)
                info.mode = 0o755
                archive.addfile(info, io.BytesIO(raw))
        name = 'hyperdns-installer-smoke-' + uuid.uuid4().hex[:12]
        command = docker + ['run', '--rm', '--pull=never', '--network=none',
                            '--cap-drop=ALL', '--cap-add=CHOWN', '--security-opt=no-new-privileges',
                            '--pids-limit=128', '--memory=512m', '--user=0:0',
                            '--name', name, '-i', '-e', 'HYPERDNS_SMOKE_CONTAINER=1',
                            '--entrypoint=/bin/bash', args.image, '-c',
                            'mkdir /smoke && tar xf - -C /smoke && python3 /smoke/test_install_smoke.py --inside']
        print('RUN: ' + subprocess.list2cmdline(command), flush=True)
        try:
            subprocess.run(command, input=payload.getvalue(), check=True, timeout=90)
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
