import pathlib
import subprocess
import sys
import unittest

from demo import execute


class ExecuteTests(unittest.TestCase):
    def test_utf8_stdout(self):
        message = 'Đang chờ dịch vụ sẵn sàng — Tiếng Việt'
        command = [sys.executable, '-c',
                   f'import sys; sys.stdout.buffer.write({message.encode("utf-8")!r})']
        self.assertEqual(execute(command), message)

    def test_utf8_failure_diagnostics(self):
        stdout = 'Đầu ra: dịch vụ'
        stderr = 'Lỗi: kết nối thất bại'
        command = [sys.executable, '-c',
                   f'import sys; sys.stdout.buffer.write({stdout.encode("utf-8")!r}); '
                   f'sys.stderr.buffer.write({stderr.encode("utf-8")!r}); sys.exit(7)']
        with self.assertRaises(RuntimeError) as failure:
            execute(command)
        self.assertIn('exited 7', str(failure.exception))
        self.assertIn(stdout, str(failure.exception))
        self.assertIn(stderr, str(failure.exception))


class CliTests(unittest.TestCase):
    def test_invalid_bind(self):
        self.assert_cli_error('--bind', 'not-an-ip')

    def test_unattended_browser_mode_rejected(self):
        self.assert_cli_error('--self-test', '--bind', '127.0.0.1')

    def test_interactive_requires_terminal(self):
        self.assert_cli_error('--bind', '127.0.0.1')

    def assert_cli_error(self, *arguments):
        result = subprocess.run(
            [sys.executable, str(pathlib.Path(__file__).resolve().parents[1] / 'demo.py'), *arguments],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 2, result.stderr.decode('utf-8'))


if __name__ == '__main__':
    unittest.main()
