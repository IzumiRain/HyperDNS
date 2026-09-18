import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts' / 'restore.sh'


@unittest.skipUnless(os.name == 'posix', 'Restore requires POSIX file and service semantics')
class RestoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.target = self.root / 'target'
        self.target.mkdir()
        self.old = {'data.db': b'old-db', 'master.key': b'old-key', 'config.json': b'{"old":true}', 'certs/old.crt': b'old-cert'}
        for name, value in self.old.items():
            path = self.target / name
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(value)
        self.archive = self.root / 'backup.tar.gz'

    def archive_with(self, values=None, extra=None):
        values = {'data.db': b'new-db', 'master.key': b'new-key'} if values is None else values
        with tarfile.open(self.archive, 'w:gz') as out:
            for name, value in values.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(value)
                out.addfile(entry, io.BytesIO(value))
            if extra:
                out.addfile(extra, io.BytesIO(b'x' * extra.size) if extra.isfile() else None)

    def run_restore(self, *flags):
        return subprocess.run(['bash', str(SCRIPT), str(self.archive), '--data-dir', str(self.target), '--yes', *flags], capture_output=True, text=True)

    def assert_old(self):
        for name, value in self.old.items():
            self.assertEqual((self.target / name).read_bytes(), value)

    def test_pair_restore_backup_and_private_modes(self):
        self.archive_with({'data.db': b'new-db', 'master.key': b'new-key', 'config.json': b'{}', 'certs/new.crt': b'new-cert'})
        result = self.run_restore()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.target / 'data.db').read_bytes(), b'new-db')
        self.assertEqual((self.target / 'master.key').read_bytes(), b'new-key')
        self.assertFalse((self.target / 'certs/old.crt').exists())
        for name in ['data.db', 'master.key', 'config.json', 'certs/new.crt']:
            self.assertEqual((self.target / name).stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.target / 'certs').stat().st_mode & 0o777, 0o700)
        backups = list(self.root.glob('hyperdns-before-restore-*.tar.gz'))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)
        with tarfile.open(backups[0]) as backup:
            for name, value in self.old.items():
                self.assertEqual(backup.extractfile(name).read(), value)

    def test_optional_files_are_preserved(self):
        self.archive_with()
        self.assertEqual(self.run_restore().returncode, 0)
        for name in ['config.json', 'certs/old.crt']:
            self.assertEqual((self.target / name).read_bytes(), self.old[name])

    def test_check_does_not_mutate_or_backup(self):
        self.archive_with()
        self.assertEqual(self.run_restore('--check').returncode, 0)
        self.assert_old()
        self.assertFalse(list(self.root.glob('hyperdns-before-restore-*')))

    def test_invalid_pairs_and_json_are_rejected(self):
        cases = [
            {'data.db': b'new'},
            {'data.db': b'new', 'master.key': b''},
            {'data.db': b'', 'master.key': b'new'},
            {'data.db': b'new', 'master.key': b'new', 'config.json': b'['},
            {'data.db': b'new', 'master.key': b'new', 'config.json': b'[]'},
        ]
        for values in cases:
            with self.subTest(values=values):
                self.archive_with(values)
                self.assertNotEqual(self.run_restore().returncode, 0)
                self.assert_old()

    def test_unsafe_names_and_duplicates_rejected(self):
        for name in ['../outside', '/outside', 'certs/../outside', 'certs\\outside', 'unexpected', 'data.db', 'data.db/child']:
            with self.subTest(name=name):
                extra = tarfile.TarInfo(name)
                extra.size = 1
                self.archive_with(extra=extra)
                self.assertNotEqual(self.run_restore().returncode, 0)
                self.assert_old()

    def test_links_and_special_members_rejected(self):
        for kind in [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE]:
            with self.subTest(kind=kind):
                extra = tarfile.TarInfo('certs/link')
                extra.type = kind
                extra.linkname = '../data.db'
                self.archive_with(extra=extra)
                self.assertNotEqual(self.run_restore().returncode, 0)
                self.assert_old()

    def test_destination_link_rejected(self):
        self.archive_with()
        key = self.target / 'master.key'
        key.unlink()
        other = self.root / 'other'
        other.write_bytes(b'untouched')
        key.symlink_to(other)
        self.assertNotEqual(self.run_restore().returncode, 0)
        self.assertEqual(other.read_bytes(), b'untouched')

    def test_replace_failure_rolls_back(self):
        self.archive_with({'data.db': b'new-db', 'master.key': b'new-key', 'config.json': b'{}'})
        payload = SCRIPT.read_text().split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        shim = self.root / 'failure.py'
        shim.write_text("import os\nreal_replace = os.replace\ncalls = 0\ndef failing_replace(src, dst):\n global calls\n calls += 1\n if calls == 4: raise OSError('injected rename failure')\n return real_replace(src, dst)\nos.replace = failing_replace\n" + payload)
        result = subprocess.run(['python3', str(shim), str(self.archive), '--data-dir', str(self.target), '--yes'], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('injected rename failure', result.stderr)
        self.assert_old()
        self.assertEqual(len(list(self.root.glob('hyperdns-before-restore-*.tar.gz'))), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
