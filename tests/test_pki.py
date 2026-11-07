import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

try:
    from lab import pki
except ModuleNotFoundError as exc:
    if exc.name not in ('cryptography', 'fcntl'):
        raise
    raise unittest.SkipTest('PKI tests require the Linux lab tools container') from exc


class PersistentRootTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = pathlib.Path(temporary.name)
        patcher = patch.object(pki, 'ROOT_CA', self.directory)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_root_identity_survives_repeated_initialization(self):
        first, first_key = pki.persistent_root()
        second, second_key = pki.persistent_root()
        self.assertEqual(pki.pem(first), pki.pem(second))
        self.assertEqual(first_key.private_numbers(), second_key.private_numbers())
        intermediate_key = pki.key()
        intermediate = pki.cert('Lab Intermediate CA', intermediate_key, second, second_key, True, 0)
        intermediate.verify_directly_issued_by(first)
        self.assertEqual(os.stat(self.directory).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(self.directory / 'root.key').st_mode & 0o777, 0o600)

    def test_partial_root_is_not_regenerated(self):
        original_key = pki.key()
        pki.save_key(self.directory / 'root.key', original_key)
        original = (self.directory / 'root.key').read_bytes()
        with self.assertRaises(RuntimeError):
            pki.persistent_root()
        self.assertEqual((self.directory / 'root.key').read_bytes(), original)
        self.assertFalse((self.directory / 'root.crt').exists())

    def test_mismatched_key_is_not_replaced(self):
        root, _ = pki.persistent_root()
        pki.save_key(self.directory / 'root.key', pki.key())
        original = (self.directory / 'root.key').read_bytes()
        with self.assertRaises(RuntimeError):
            pki.persistent_root()
        self.assertEqual((self.directory / 'root.crt').read_bytes(), pki.pem(root))
        self.assertEqual((self.directory / 'root.key').read_bytes(), original)

    def test_expired_root_is_not_rotated_automatically(self):
        root_key = pki.key()
        root = pki.cert('Lab Root CA', root_key, ca=True, path=1, days=0)
        pki.save_key(self.directory / 'root.key', root_key)
        pki.write_atomic(self.directory / 'root.crt', pki.pem(root))
        with self.assertRaises(RuntimeError):
            pki.persistent_root()
        self.assertEqual((self.directory / 'root.crt').read_bytes(), pki.pem(root))

    def test_concurrent_initialization_uses_one_root(self):
        script = (
            'from pathlib import Path; from lab import pki; '
            f'pki.ROOT_CA = Path({str(self.directory)!r}); '
            'print(pki.pem(pki.persistent_root()[0]).decode(), end="")'
        )
        processes = [subprocess.Popen(
            [sys.executable, '-c', script], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=pathlib.Path(__file__).resolve().parents[1]) for _ in range(4)]
        try:
            outputs = []
            for process in processes:
                stdout, stderr = process.communicate(timeout=30)
                self.assertEqual(process.returncode, 0, stderr.decode())
                outputs.append(stdout)
            for certificate in outputs:
                self.assertEqual(certificate, (self.directory / 'root.crt').read_bytes())
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                process.communicate()


if __name__ == '__main__':
    unittest.main()
