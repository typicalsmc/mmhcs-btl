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


if __name__ == '__main__':
    unittest.main()
