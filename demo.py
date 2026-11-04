"""Host-loopback presentation/controller for the isolated Docker PKI lab."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import http.server
import json
import pathlib
import re
import signal
import ssl
import subprocess
import sys
import threading
import time
import uuid

BASE = pathlib.Path(__file__).resolve().parent
HOST = 'login.payroll.test'
RUN_LOCK = threading.Lock()


def atomic_text(path, text):
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(text, encoding='utf-8')
    temporary.replace(path)


def execute(command, timeout=60):
    try:
        result = subprocess.run(command, cwd=BASE, text=True, capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f'{command!r}: {exc}') from exc
    if result.returncode:
        raise RuntimeError(f'{command!r} exited {result.returncode}\n{result.stderr}\n{result.stdout}')
    return result.stdout


class Deployment:
    def __init__(self, run_id):
        if not re.fullmatch(r'[0-9a-f]{12}', run_id):
            raise ValueError('run-id must be exactly twelve lowercase hexadecimal characters')
        self.run_id = run_id
        self.folder = BASE / 'runs' / run_id
        if not (self.folder / 'compose.env').is_file():
            raise ValueError(f'Run state does not exist: {self.folder}')
        self.addresses = json.loads((self.folder / 'state.json').read_text(encoding='utf-8'))['addresses']

    @classmethod
    def create(cls):
        run_id = uuid.uuid4().hex[:12]
        folder = BASE / 'runs' / run_id
        folder.mkdir(parents=True, mode=0o700)
        for directory in ('ca-private', 'legitimate', 'leak', 'attacker', 'public', 'dns'):
            (folder / directory).mkdir(mode=0o700)
        for filename in ('hosts', 'resolv.conf'):
            (folder / 'dns' / filename).touch(mode=0o600)
        # Quoted dotenv values preserve paths containing spaces on Windows and POSIX.
        value = folder.as_posix().replace("'", "\\'")
        atomic_text(folder / 'compose.env', f"LAB_RUN_DIR='{value}'\n")
        atomic_text(folder / 'state.json', json.dumps({'addresses': {}}))
        return cls(run_id)

    def compose(self, *arguments, timeout=60):
        return execute(['docker', 'compose', '--file', str(BASE / 'compose.yaml'),
                        '--env-file', str(self.folder / 'compose.env'),
                        '-p', f'pki-lab-{self.run_id}', *arguments], timeout)

    def save(self):
        atomic_text(self.folder / 'state.json', json.dumps({'addresses': self.addresses}, indent=2))

    def inspect_address(self, service):
        container = self.compose('ps', '-q', service).strip()
        if not container or '\n' in container:
            raise RuntimeError(f'{service}: expected one running container, got {container!r}\n{self.logs()}')
        info = json.loads(execute(['docker', 'inspect', container]))[0]
        networks = info['NetworkSettings']['Networks']
        if len(networks) != 1:
            raise RuntimeError(f'{service}: expected exactly one network attachment')
        address = next(iter(networks.values()))['IPAddress']
        if not address:
            raise RuntimeError(f'{service}: no IPv4 address (status {info["State"]["Status"]})\n{self.logs()}')
        self.addresses[service] = address
        self.save()
        return address

    def switch_dns(self, service):
        address = self.addresses[service]
        atomic_text(self.folder / 'dns' / 'hosts',
                    f'{address} {HOST}\n{address} other.payroll.test\n')
        self.compose('kill', '-s', 'SIGHUP', 'dns')

    def probe(self, hostname=HOST, trust='bundle', check_crl=False, request_id=None, timeout=60):
        command = ['run', '--rm', '--no-deps', 'victim', 'python', '/lab/client.py',
                   '--hostname', hostname, '--trust', trust,
                   '--request-id', request_id or f'{self.run_id}-manual-{uuid.uuid4().hex[:8]}']
        if check_crl:
            command.append('--check-crl')
        return json.loads(self.compose(*command, timeout=timeout))

    def ready(self, service, trust='bundle', check_crl=False):
        deadline = time.monotonic() + 30
        failure = ''
        while time.monotonic() < deadline:
            try:
                observation = self.probe(trust=trust, check_crl=check_crl,
                                         request_id=f'{self.run_id}-ready-{service}',
                                         timeout=max(1, deadline-time.monotonic()))
                if (observation['accepted'] and observation['peer_ip'] == self.addresses[service]
                        and observation['http_origin'] == service and observation['http_status'] == 200
                        and observation['http_body'] == f'{service.upper()} PAYROLL LAB\n'
                        and observation['protocol'] == 'TLSv1.3'):
                    return
                failure = json.dumps(observation)
            except (RuntimeError, ValueError) as exc:
                failure = str(exc)
            time.sleep(min(0.5, max(0, deadline-time.monotonic())))
        raise RuntimeError(f'{service} readiness timed out: {failure}\n{self.logs()}')

    def setup(self):
        self.compose('config')
        self.compose('build', 'ca', 'attacker', timeout=600)
        self.compose('run', '--rm', '--no-deps', 'ca', 'python', '/lab/pki.py', 'init')
        self.compose('up', '-d', '--no-deps', 'legitimate')
        address = self.inspect_address('legitimate')
        atomic_text(self.folder / 'dns' / 'hosts', f'{address} {HOST}\n{address} other.payroll.test\n')
        self.compose('up', '-d', '--no-deps', 'dns')
        dns = self.inspect_address('dns')
        atomic_text(self.folder / 'dns' / 'resolv.conf', f'nameserver {dns}\noptions timeout:2 attempts:1 ndots:1\n')
        self.ready('legitimate', check_crl=True)

    def attack(self):
        self.compose('up', '-d', '--no-deps', 'attacker')
        self.inspect_address('attacker')
        self.switch_dns('attacker')
        self.ready('attacker', trust='root')
        return self.addresses

    def revoke(self):
        return self.compose('run', '--rm', '--no-deps', 'ca', 'bash', '/lab/revoke-cert.sh')

    def recover(self):
        output = self.compose('run', '--rm', '--no-deps', 'ca', 'python', '/lab/pki.py', 'recover')
        self.compose('exec', '-T', 'legitimate', 'nginx', '-t')
        self.compose('exec', '-T', 'legitimate', 'nginx', '-s', 'reload')
        self.switch_dns('legitimate')
        self.ready('legitimate', check_crl=True)
        return output

    def logs(self):
        return self.compose('logs', '--no-color', '--timestamps', 'dns', 'legitimate', 'attacker')

    def down(self):
        return self.compose('down', '--remove-orphans')


def root_fingerprint(deployment):
    certificate = (deployment.folder / 'public' / 'root.crt').read_text(encoding='ascii')
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).hexdigest()


def run_lab():
    deployment = Deployment.create()
    failure = None
    try:
        deployment.setup()
        original_root = root_fingerprint(deployment)
        results = []

        def observe(ident, title, expected, explain, service='attacker', trust='root',
                    hostname=HOST, check=False, code=None):
            row = deployment.probe(hostname, trust, check, f'{deployment.run_id}-{ident}')
            passed = (row['accepted'] == expected
                      and row['resolved_ip'] == deployment.addresses[service]
                      and row['peer_ip'] == deployment.addresses[service])
            if expected:
                passed = (passed and row['protocol'] == 'TLSv1.3' and row['http_status'] == 200
                          and row['http_origin'] == service
                          and row['http_body'] == f'{service.upper()} PAYROLL LAB\n')
            elif code is not None:
                passed = passed and row.get('verify_code') == code
            row.update(id=ident, title=title, expected=expected, passed=bool(passed),
                       explain=explain, crl_enabled=check, trust=trust)
            results.append(row)
            return row

        baseline = observe('baseline', 'Kết nối hợp lệ ban đầu', True,
                           'DNS trỏ đến Nginx hợp lệ; kiểm tra toàn chuỗi và CRL.',
                           service='legitimate', trust='bundle', check=True)
        deployment.attack()
        observe('untrusted', 'Root CA chưa được tin cậy', False,
                'Client chỉ tin CA không liên quan nên từ chối chuỗi của attacker.', trust='unrelated')
        forged = observe('forged', 'Chứng chỉ giả vượt xác minh', True,
                         'Resolver bị kiểm soát đổi DNS; hostname/SNI giữ nguyên, khóa CA bị lộ ký leaf được tin cậy.')
        observe('hostname', 'Tên miền sai bị từ chối', False,
                'DNS vẫn dẫn đến attacker nhưng SAN không khớp other.payroll.test.',
                hostname='other.payroll.test', code=62)
        atomic_text(deployment.folder / 'revocation.txt', deployment.revoke())
        observe('revoked', 'Thu hồi CA và bật CRL', False,
                'Bash thu hồi serial của CA trung gian với lý do CACompromise.',
                trust='bundle', check=True, code=23)
        unchecked = observe('unchecked', 'Có CRL nhưng không kiểm tra', True,
                            'Cùng bundle và chứng chỉ attacker; client không thực thi CRL.', trust='bundle')
        deployment.recover()
        recovery = observe('recovery', 'Thay CA và cấp lại', True,
                           'CA trung gian mới; root cũ giữ nguyên và CA bị lộ vẫn bị thu hồi.',
                           service='legitimate', trust='bundle', check=True)
        invariants = {
            'distinct_attacker_leaf': baseline['fingerprint'] != forged['fingerprint'],
            'attacker_identity_unchanged': forged['fingerprint'] == unchecked['fingerprint'],
            'new_recovery_leaf': recovery['fingerprint'] not in (baseline['fingerprint'], forged['fingerprint']),
            'replacement_issuer': recovery['issuer'] != baseline['issuer'] and 'Replacement Intermediate CA' in recovery['issuer'],
            'root_unchanged': original_root == root_fingerprint(deployment),
        }
        output = {'hostname': HOST, 'scope': 'Isolated Docker internal lab; malicious resolver DNS redirection',
                  'issuer': forged['issuer'], 'serial': forged['serial'], 'fingerprint': forged['fingerprint'],
                  'folder': str(deployment.folder), 'run_id': deployment.run_id,
                  'addresses': deployment.addresses, 'root_fingerprint': original_root,
                  'invariants': invariants, 'results': results,
                  'all_passed': all(row['passed'] for row in results) and all(invariants.values()),
                  'openssl': forged['openssl'], 'created_at': dt.datetime.now(dt.timezone.utc).isoformat()}
        serialized = json.dumps(output, ensure_ascii=False, indent=2)
        atomic_text(deployment.folder / 'results.json', serialized)
        atomic_text(BASE / 'latest-results.json', serialized)
        return output
    except Exception as exc:
        failure = exc
        atomic_text(deployment.folder / 'failure.txt', str(exc))
        raise RuntimeError(f'Run {deployment.run_id} failed; evidence: {deployment.folder}\n{exc}') from exc
    finally:
        cleanup_errors = []
        try:
            atomic_text(deployment.folder / 'docker.log', deployment.logs())
        except Exception as exc:
            cleanup_errors.append(str(exc))
        try:
            deployment.down()
        except Exception as exc:
            cleanup_errors.append(str(exc))
        if cleanup_errors:
            atomic_text(deployment.folder / 'cleanup-errors.txt', '\n'.join(cleanup_errors))
            if failure is None:
                raise RuntimeError('\n'.join(cleanup_errors))


class Handler(http.server.BaseHTTPRequestHandler):
    def respond(self, status, payload):
        data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path not in ('/', '/index.html'):
            self.send_error(404)
            return
        data = (BASE / 'demo.html').read_bytes()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.path != '/api/run':
            self.send_error(404)
            return
        if self.headers.get('Origin') not in (None, f'http://127.0.0.1:{self.server.server_port}',
                                               f'http://localhost:{self.server.server_port}'):
            self.send_error(403)
            return
        if not RUN_LOCK.acquire(blocking=False):
            self.respond(409, {'error': 'A demo run is already in progress'})
            return
        try:
            self.respond(200, run_lab())
        except Exception as exc:
            self.respond(500, {'error': str(exc)})
        finally:
            RUN_LOCK.release()


def interrupt(_signum, _frame):
    raise KeyboardInterrupt


def run_interruptibly(deployment, action):
    """Deploy actions that start services remove their own project when interrupted."""
    if action in ('down', 'revoke', 'probe'):
        return getattr(deployment, action)()
    previous = {number: signal.signal(number, interrupt) for number in (signal.SIGINT, signal.SIGTERM)}
    try:
        return getattr(deployment, action)()
    except KeyboardInterrupt:
        message = f'Interrupted while running {action}.'
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    try:
        deployment.down()
        message += f' Project pki-lab-{deployment.run_id} removed; evidence retained.'
    except Exception as exc:
        message += f' Cleanup also failed: {exc}'
    raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--self-test', action='store_true')
    mode.add_argument('--action', choices=('setup', 'attack', 'revoke', 'probe', 'recover', 'down'))
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--run-id')
    parser.add_argument('--check-crl', action='store_true')
    args = parser.parse_args()
    if args.action and args.action != 'setup' and not args.run_id:
        parser.error('--run-id is required for non-setup actions')
    try:
        if args.self_test:
            output = run_lab()
            print(json.dumps(output, ensure_ascii=False, indent=2))
            return 0 if output['all_passed'] else 1
        if args.action:
            deployment = Deployment.create() if args.action == 'setup' else Deployment(args.run_id)
            if args.action == 'setup':
                try:
                    deployment.setup()
                except Exception as exc:
                    raise RuntimeError(f'Run {deployment.run_id}; state retained at {deployment.folder}: {exc}') from exc
                output = {'run_id': deployment.run_id, 'folder': str(deployment.folder)}
            elif args.action == 'probe':
                output = deployment.probe(check_crl=args.check_crl)
            else:
                output = run_interruptibly(deployment, args.action)
            print(json.dumps(output, ensure_ascii=False, indent=2))
            return 0
        print(f'PKI lab: http://127.0.0.1:{args.port}', flush=True)
        http.server.ThreadingHTTPServer(('127.0.0.1', args.port), Handler).serve_forever()
    except (RuntimeError, ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
