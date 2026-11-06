"""Step-by-step terminal presentation for the isolated Docker PKI lab."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import pathlib
import re
import signal
import ssl
import subprocess
import sys
import time
import uuid

BASE = pathlib.Path(__file__).resolve().parent
HOST = 'login.payroll.test'


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
        for directory in ('ca-private', 'legitimate', 'leak', 'attacker', 'public', 'dns', 'ocsp'):
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

    def ocsp(self, certificate='intermediate'):
        # Re-inspected on every call so a restarted responder is still reachable.
        address = self.inspect_address('ocsp')
        return json.loads(self.compose('run', '--rm', '--no-deps', 'victim', 'python', '/lab/client.py',
                                       '--ocsp', certificate, '--ocsp-connect', address))

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
        self.compose('up', '-d', '--no-deps', 'ocsp')
        self.compose('up', '-d', '--no-deps', 'legitimate')
        address = self.inspect_address('legitimate')
        atomic_text(self.folder / 'dns' / 'hosts', f'{address} {HOST}\n{address} other.payroll.test\n')
        self.compose('up', '-d', '--no-deps', 'dns')
        dns = self.inspect_address('dns')
        atomic_text(self.folder / 'dns' / 'resolv.conf', f'nameserver {dns}\noptions timeout:2 attempts:1 ndots:1\n')
        self.ready('legitimate', check_crl=True)
        status = self.ocsp()
        if status['cert_status'] != 'GOOD':
            raise RuntimeError(f'OCSP responder did not report the intermediate as GOOD: {json.dumps(status)}\n{self.logs()}')

    def attack(self):
        self.compose('up', '-d', '--no-deps', 'attacker')
        self.inspect_address('attacker')
        self.switch_dns('attacker')
        self.ready('attacker', trust='root')
        return self.addresses

    def reload_ocsp(self):
        # openssl ocsp checks the index for changes before blocking in accept, so its next answer
        # would still come from the old index; restart it to serve the new revocation state now.
        self.compose('restart', 'ocsp')

    def revoke(self):
        output = self.compose('run', '--rm', '--no-deps', 'ca', 'bash', '/lab/revoke-cert.sh')
        self.reload_ocsp()
        return output

    def recover(self):
        output = self.compose('run', '--rm', '--no-deps', 'ca', 'python', '/lab/pki.py', 'recover')
        self.reload_ocsp()
        self.compose('exec', '-T', 'legitimate', 'nginx', '-t')
        self.compose('exec', '-T', 'legitimate', 'nginx', '-s', 'reload')
        self.switch_dns('legitimate')
        self.ready('legitimate', check_crl=True)
        return output

    def browser(self, bind):
        """Publish the lab on one host address for a real browser; TLS stays end-to-end."""
        address = ipaddress.ip_address(bind)
        published = f'[{address}]' if address.version == 6 else str(address)
        env_file = self.folder / 'compose.env'
        lines = [line for line in env_file.read_text(encoding='utf-8').splitlines()
                 if not line.startswith('LAB_BROWSER_IP=')]
        atomic_text(env_file, '\n'.join([*lines, f"LAB_BROWSER_IP='{published}'"]) + '\n')
        self.compose('--profile', 'browser', 'up', '-d', '--no-deps', '--force-recreate', 'browser')
        return {'hosts_entry': f'{address} {HOST} crl.payroll.test ocsp.payroll.test',
                'site': f'https://{HOST}/', 'root_certificate': 'http://crl.payroll.test/root.crt',
                'root_sha256': root_fingerprint(self)}

    def logs(self):
        return self.compose('--profile', 'browser', 'logs', '--no-color', '--timestamps',
                            'dns', 'ocsp', 'legitimate', 'attacker', 'browser')

    def down(self):
        return self.compose('--profile', 'browser', 'down', '--remove-orphans')


def root_fingerprint(deployment):
    certificate = (deployment.folder / 'public' / 'root.crt').read_text(encoding='ascii')
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate)).hexdigest()


def run_lab(*, before_step=None, on_observation=None):
    deployment = Deployment.create()
    failure = None
    try:
        deployment.setup()
        original_root = root_fingerprint(deployment)
        results = []

        def observe(ident, title, expected, explain, service='attacker', trust='root',
                    hostname=HOST, check=False, code=None, prepare=None, ocsp_cert=None):
            if before_step is not None:
                before_step(len(results) + 1, ident, title, explain)
            if prepare is not None:
                prepare()
            row = deployment.probe(hostname, trust, check, f'{deployment.run_id}-{ident}')
            if ocsp_cert is not None:
                row['ocsp'] = deployment.ocsp(ocsp_cert)
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
            if on_observation is not None:
                on_observation(row)
            return row

        baseline = observe('baseline', 'Kết nối hợp lệ ban đầu', True,
                           'DNS trỏ đến Nginx hợp lệ; kiểm tra toàn chuỗi và CRL.',
                           service='legitimate', trust='bundle', check=True, ocsp_cert='intermediate')
        observe('untrusted', 'Root CA chưa được tin cậy', False,
                'Client chỉ tin CA không liên quan nên từ chối chuỗi của attacker.',
                trust='unrelated', prepare=deployment.attack)
        forged = observe('forged', 'Chứng chỉ giả vượt xác minh', True,
                         'Resolver bị kiểm soát đổi DNS; hostname/SNI giữ nguyên, khóa CA bị lộ ký leaf được tin cậy.')
        observe('hostname', 'Tên miền sai bị từ chối', False,
                'DNS vẫn dẫn đến attacker nhưng SAN không khớp other.payroll.test.',
                hostname='other.payroll.test', code=62)
        revoked = observe('revoked', 'Thu hồi CA và bật CRL', False,
                          'Bash thu hồi serial của CA trung gian với lý do CACompromise.',
                          trust='bundle', check=True, code=23, ocsp_cert='intermediate',
                          prepare=lambda: atomic_text(deployment.folder / 'revocation.txt', deployment.revoke()))
        unchecked = observe('unchecked', 'Có CRL nhưng không kiểm tra', True,
                            'Cùng bundle và chứng chỉ attacker; client không thực thi CRL.', trust='bundle')
        recovery = observe('recovery', 'Thay CA và cấp lại', True,
                           'CA trung gian mới; root cũ giữ nguyên và CA bị lộ vẫn bị thu hồi.',
                           service='legitimate', trust='bundle', check=True, prepare=deployment.recover,
                           ocsp_cert='replacement-intermediate')
        invariants = {
            'distinct_attacker_leaf': baseline['fingerprint'] != forged['fingerprint'],
            'attacker_identity_unchanged': forged['fingerprint'] == unchecked['fingerprint'],
            'new_recovery_leaf': recovery['fingerprint'] not in (baseline['fingerprint'], forged['fingerprint']),
            'replacement_issuer': recovery['issuer'] != baseline['issuer'] and 'Replacement Intermediate CA' in recovery['issuer'],
            'root_unchanged': original_root == root_fingerprint(deployment),
            'ocsp_good_before_revoke': baseline['ocsp']['cert_status'] == 'GOOD',
            'ocsp_revoked_after_revoke': (revoked['ocsp']['cert_status'] == 'REVOKED'
                                          and revoked['ocsp']['revocation_reason'] == 'ca_compromise'),
            'ocsp_replacement_good': recovery['ocsp']['cert_status'] == 'GOOD',
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
    except KeyboardInterrupt as exc:
        failure = exc
        atomic_text(deployment.folder / 'failure.txt', 'Interrupted')
        raise KeyboardInterrupt(f'Run {deployment.run_id} interrupted; evidence: {deployment.folder}') from exc
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


def prompt_step(index, ident, title, explain):
    print(f'\n[{index}/7] {ident} - {title}', flush=True)
    print(explain, flush=True)
    try:
        input('Nhấn Enter để tiếp tục (Ctrl+C để dừng): ')
    except EOFError as exc:
        raise KeyboardInterrupt('Input closed') from exc


def print_observation(row):
    def observed(field):
        value = row.get(field)
        return 'không quan sát' if value is None else value

    status = 'PASS' if row['passed'] else 'FAIL'
    tls = 'chấp nhận' if row['accepted'] else 'từ chối'
    http_host = row['hostname'] if row.get('http_status') is not None else 'không quan sát'
    body = row.get('http_body')
    body = 'không quan sát' if body is None else json.dumps(body, ensure_ascii=False)
    lines = [
        f'Kịch bản: {status}',
        f'TLS: {tls}',
        f'  Hostname: {row["hostname"]}',
        f'  SNI: {row["hostname"]}',
        f'  HTTP Host: {http_host}',
        f'  Trust: {row["trust"]}',
        f'  CRL: {"bật" if row["crl_enabled"] else "tắt"}',
    ]
    if row.get('ocsp'):
        o = row['ocsp']
        reason = f' ({o["revocation_reason"]})' if o['revocation_reason'] else ''
        lines.append(f'  OCSP ({o["certificate"]}): {o["cert_status"]}{reason}')
    lines += [
        f'  Resolved IP: {observed("resolved_ip")}',
        f'  TCP peer IP: {observed("peer_ip")}',
    ]
    if row['accepted']:
        lines.extend((f'  Protocol: {observed("protocol")}', f'  Cipher: {observed("cipher")}'))
    else:
        lines.extend((f'  Verification code: {observed("verify_code")}',
                      f'  Verification detail: {observed("detail")}'))
    lines.extend((
        f'  SHA-256 fingerprint: {observed("fingerprint")}',
        f'  Issuer: {observed("issuer")}',
        f'  Serial: {observed("serial")}',
        f'  HTTP status: {observed("http_status")}',
        f'  Origin: {observed("http_origin")}',
        f'  Body: {body}',
    ))
    print('\n'.join(lines), flush=True)


def print_summary(output):
    passed = sum(row['passed'] for row in output['results'])
    print(f'\nKết quả: {passed}/7 kịch bản PASS', flush=True)
    for name, valid in output['invariants'].items():
        print(f'  {name}: {"PASS" if valid else "FAIL"}', flush=True)
    print(f'Tổng thể: {"PASS" if output["all_passed"] else "FAIL"}', flush=True)
    print(f'Run ID: {output["run_id"]}', flush=True)
    print(f'Bằng chứng: {output["folder"]}', flush=True)
    print(f'Results JSON: {pathlib.Path(output["folder"]) / "results.json"}', flush=True)
    print(f'Victim OpenSSL: {output["openssl"]}', flush=True)


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
    mode.add_argument('--self-test', action='store_true',
                      help='run all seven steps unattended and print JSON')
    mode.add_argument('--action', choices=('setup', 'attack', 'revoke', 'probe', 'recover', 'browser', 'ocsp', 'down'),
                      help='perform an individual deployment action and print JSON')
    parser.add_argument('--run-id', help='existing deployment ID for individual actions')
    parser.add_argument('--bind', help='host address to publish ports 80/443 on for the browser action '
                                       '(for example your Tailscale IP)')
    parser.add_argument('--check-crl', action='store_true', help='enable CRL checks for the probe action')
    parser.add_argument('--ocsp-cert', choices=('intermediate', 'replacement-intermediate'), default='intermediate',
                        help='certificate to query for the ocsp action')
    args = parser.parse_args()
    if args.action and args.action != 'setup' and not args.run_id:
        parser.error('--run-id is required for non-setup actions')
    if (args.action == 'browser') != bool(args.bind):
        parser.error('--bind is required for, and only valid with, the browser action')
    if not args.self_test and not args.action and not sys.stdin.isatty():
        parser.error('Interactive mode requires a terminal; use --self-test for unattended JSON execution.')
    try:
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
            elif args.action == 'ocsp':
                output = deployment.ocsp(args.ocsp_cert)
            elif args.action == 'browser':
                output = deployment.browser(args.bind)
            else:
                output = run_interruptibly(deployment, args.action)
            print(json.dumps(output, ensure_ascii=False, indent=2))
            return 0
        if not args.self_test:
            print(f'Lab Docker cô lập cho {HOST}: 7 bước, nhấn Enter trước mỗi quan sát.\n'
                  'Đang setup/build và chờ các dịch vụ sẵn sàng; vui lòng đợi.\n'
                  'DNS và kho tin cậy của host không thay đổi.', flush=True)
        previous = signal.signal(signal.SIGTERM, interrupt)
        try:
            output = run_lab() if args.self_test else run_lab(
                before_step=prompt_step, on_observation=print_observation)
        finally:
            signal.signal(signal.SIGTERM, previous)
        if args.self_test:
            print(json.dumps(output, ensure_ascii=False, indent=2))
        else:
            print_summary(output)
        return 0 if output['all_passed'] else 1
    except KeyboardInterrupt as exc:
        print(str(exc) or 'Interrupted', file=sys.stderr, flush=True)
        return 130
    except (RuntimeError, ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
