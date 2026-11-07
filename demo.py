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
        result = subprocess.run(command, cwd=BASE, text=True, encoding='utf-8',
                                capture_output=True, timeout=timeout)
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
        (BASE / '.lab-ca').mkdir(mode=0o700, exist_ok=True)
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
        deadline = time.monotonic() + 120
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
        return {'hosts_entry': f'{address} {HOST} other.payroll.test crl.payroll.test ocsp.payroll.test',
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


LAB_STEPS = (
    dict(id='baseline', title='Kết nối hợp lệ ban đầu', expected=True, service='legitimate',
         trust='bundle', check=True, code=None, hostname=HOST, prepare=None, ocsp_cert='intermediate',
         explain='DNS trỏ đến Nginx hợp lệ; kiểm tra toàn chuỗi và CRL.',
         meaning_vi='DNS trỏ đến máy chủ thật. Chứng chỉ đúng tên miền, chuỗi đi tới Root CA đã tin cậy và CA trung gian chưa bị thu hồi. Đây là mốc so sánh trước sự cố.',
         checklist_vi=['Tin đúng Root CA đã kiểm tra SHA-256.', 'Hai chính sách thu hồi có giá trị hiệu lực 1; khởi động lại Chrome với profile strict.', 'Kiểm tra chuỗi bằng trình xem chứng chỉ Chrome; OCSP GOOD bên dưới là tham chiếu OpenSSL.'],
         browser_expected=dict(kind='http', status_code=200, origin='legitimate')),
    dict(id='untrusted', title='Root CA chưa được tin cậy', expected=False, service='attacker',
         trust='unrelated', check=False, code=20, hostname=HOST, prepare='attack', ocsp_cert=None,
         explain='Client chỉ tin CA không liên quan nên từ chối chuỗi của attacker.',
         meaning_vi='Lab chuyển hướng sang máy chủ giả, nhưng client không tin Root CA của chuỗi này nên từ chối. Terminal dùng một root không liên quan; để Chrome có cùng quyết định, bạn phải gỡ đúng Root CA lab khỏi kho tin cậy trên máy Windows.',
         checklist_vi=['Gỡ đúng thumbprint lab khỏi CurrentUser Root và LocalMachine Root nếu có; không gỡ CA khác.', 'Thoát toàn bộ Chrome và mở lại; Refresh không thay đổi trust.'],
         browser_expected=dict(kind='error', error='net::ERR_CERT_AUTHORITY_INVALID')),
    dict(id='forged', title='Chứng chỉ giả vượt xác minh', expected=True, service='attacker',
         trust='root', check=False, code=None, hostname=HOST, prepare=None, ocsp_cert=None,
         explain='Resolver bị kiểm soát đổi DNS; hostname/SNI giữ nguyên, khóa CA bị lộ ký leaf được tin cậy.',
         meaning_vi='Khóa ký của CA trung gian bị lộ. Kẻ tấn công ký được chứng chỉ đúng login.payroll.test dưới Root CA mà client tin. HTTPS kiểm tra tên miền và chuỗi chứng chỉ, không chứng minh nội dung website là của chủ thể mong muốn khi CA đã bị xâm phạm.',
         checklist_vi=['Import lại cùng Root CA đã xác minh và khởi động lại Chrome.', 'Chấp nhận chứng chỉ không chứng minh website an toàn; xem chứng chỉ thủ công.'],
         browser_expected=dict(kind='http', status_code=200, origin='attacker')),
    dict(id='hostname', title='Tên miền sai bị từ chối', expected=False, service='attacker',
         trust='root', check=False, code=62, hostname='other.payroll.test', prepare=None, ocsp_cert=None,
         explain='DNS vẫn dẫn đến attacker nhưng SAN không khớp other.payroll.test.',
         meaning_vi='Client truy cập other.payroll.test trong khi chứng chỉ chỉ dành cho login.payroll.test. Dù Root CA được tin, tên miền không khớp vẫn phải bị từ chối.',
         checklist_vi=['Hosts có other.payroll.test trỏ đến IP gateway thật.', 'Giữ Root CA được tin; không đổi tên hoặc cấp lại chứng chỉ.'],
         browser_expected=dict(kind='error', error='net::ERR_CERT_COMMON_NAME_INVALID')),
    dict(id='revoked', title='Thu hồi CA và bật CRL', expected=False, service='attacker',
         trust='bundle', check=True, code=23, hostname=HOST, prepare='revoke', ocsp_cert='intermediate',
         explain='Bash thu hồi serial của CA trung gian với lý do CACompromise.',
         meaning_vi='Bash thu hồi chứng chỉ CA trung gian với lý do CACompromise; Root CA công bố CRL và OCSP báo REVOKED. Chứng chỉ attacker vẫn giữ nguyên, nhưng client kiểm tra thu hồi phải từ chối chuỗi qua CA đó.',
         checklist_vi=['Hai chính sách thu hồi có giá trị hiệu lực 1, không ignored/error trên chrome://policy.', 'Thoát toàn bộ Chrome; dùng profile revoked mới để tránh GOOD cache.', 'OCSP REVOKED/ca_compromise là tham chiếu, không phải kết quả Chrome.'],
         browser_expected=dict(kind='error', error='net::ERR_CERT_REVOKED')),
    dict(id='unchecked', title='Có CRL nhưng không kiểm tra', expected=True, service='attacker',
         trust='bundle', check=False, code=None, hostname=HOST, prepare=None, ocsp_cert=None,
         explain='Cùng bundle và chứng chỉ attacker; client không thực thi CRL.',
         meaning_vi='Cùng máy chủ giả và cùng chứng chỉ đã dùng ở bước trước. Client không kiểm tra thu hồi vẫn có thể chấp nhận. Việc CA công bố thu hồi chỉ bảo vệ client thực sự thực thi kiểm tra.',
         checklist_vi=['Đặt cả hai chính sách thu hồi về 0 và kiểm tra giá trị hiệu lực.', 'Thoát toàn bộ Chrome; mở profile unchecked mới.', 'Không vượt interstitial hoặc tắt xác minh TLS; còn bị chặn là sai khác thật.'],
         browser_expected=dict(kind='http', status_code=200, origin='attacker')),
    dict(id='recovery', title='Thay CA và cấp lại', expected=True, service='legitimate',
         trust='bundle', check=True, code=None, hostname=HOST, prepare='recover', ocsp_cert='replacement-intermediate',
         explain='CA trung gian mới; root cũ giữ nguyên và CA bị lộ vẫn bị thu hồi.',
         meaning_vi='Giữ nguyên Root CA, tạo CA trung gian mới và cấp lại chứng chỉ cho máy chủ thật. DNS quay về máy chủ thật; CA cũ vẫn bị thu hồi. Khôi phục an toàn không phải bỏ kiểm tra thu hồi hay tin lại CA đã lộ khóa.',
         checklist_vi=['Khôi phục cả hai chính sách về 1 và tin Root CA ban đầu.', 'Thoát toàn bộ Chrome; quay về profile strict/revoked.', 'Xem issuer/leaf mới trong trình xem chứng chỉ; root không đổi và CA cũ vẫn bị thu hồi.'],
         browser_expected=dict(kind='http', status_code=200, origin='legitimate')),
)


class LabSession:
    """Ordered, one-shot reference engine; deployment lifetime belongs to the caller."""

    def __init__(self, deployment):
        self.deployment = deployment
        self.original_root = root_fingerprint(deployment)
        self.results = []
        self.failure = None

    def run_next(self, expected_id):
        if self.failure is not None:
            raise RuntimeError(f'Session failed; stop rather than replay: {self.failure}')
        if len(self.results) == len(LAB_STEPS) or LAB_STEPS[len(self.results)]['id'] != expected_id:
            raise ValueError('Out-of-order or duplicate step')
        step = LAB_STEPS[len(self.results)]
        deployment = self.deployment
        try:
            action = step['prepare']
            if action == 'attack':
                deployment.attack()
            elif action == 'revoke':
                atomic_text(deployment.folder / 'revocation.txt', deployment.revoke())
            elif action == 'recover':
                deployment.recover()
            row = deployment.probe(step['hostname'], step['trust'], step['check'],
                                   f'{deployment.run_id}-{expected_id}')
            if step['ocsp_cert'] is not None:
                row['ocsp'] = deployment.ocsp(step['ocsp_cert'])
            service = step['service']
            passed = (row['accepted'] == step['expected']
                      and row['resolved_ip'] == deployment.addresses[service]
                      and row['peer_ip'] == deployment.addresses[service])
            if step['expected']:
                passed = (passed and row['protocol'] == 'TLSv1.3' and row['http_status'] == 200
                          and row['http_origin'] == service
                          and row['http_body'] == f'{service.upper()} PAYROLL LAB\n')
            elif step['code'] is not None:
                passed = passed and row.get('verify_code') == step['code']
            row.update(id=expected_id, title=step['title'], expected=step['expected'],
                       passed=bool(passed), explain=step['explain'],
                       crl_enabled=step['check'], trust=step['trust'])
            self.results.append(row)
            return row
        except BaseException as exc:
            self.failure = str(exc)
            raise

    def summary(self):
        if self.failure is not None or len(self.results) != len(LAB_STEPS):
            raise ValueError('Seven successful observations required')
        deployment = self.deployment
        original_root = self.original_root
        results = self.results
        baseline, _, forged, _, revoked, unchecked, recovery = results
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


def run_lab(*, before_step=None, on_observation=None, browser_bind=None):
    deployment = Deployment.create()
    failure = None
    try:
        deployment.setup()
        if browser_bind is not None:
            print_browser_setup(deployment, deployment.browser(browser_bind))
        session = LabSession(deployment)
        for index, step in enumerate(LAB_STEPS, 1):
            if before_step is not None:
                before_step(index, step['id'], step['title'], step['explain'])
            row = session.run_next(step['id'])
            if on_observation is not None:
                on_observation(row)
        return session.summary()
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


def pause_for_enter(message):
    try:
        input(message)
    except EOFError as exc:
        raise KeyboardInterrupt('Input closed') from exc


def prompt_step(index, ident, title, explain):
    print(f'\n[{index}/7] {ident} - {title}', flush=True)
    print(explain, flush=True)
    pause_for_enter('Nhấn Enter để tiếp tục (Ctrl+C để dừng): ')


def print_browser_setup(deployment, info):
    bind = info['hosts_entry'].split()[0]
    wildcard = ipaddress.ip_address(bind).is_unspecified
    hosts_entry = info['hosts_entry']
    if wildcard:
        hosts_entry = '<IP-LAN/Tailscale-của-Docker-host> ' + hosts_entry.split(' ', 1)[1]
    print('\n'.join([
        '\nCẤU HÌNH TRÌNH DUYỆT THỦ CÔNG',
        f'Run ID: {deployment.run_id}',
        f'Bằng chứng: {deployment.folder}',
        f'Bind: {bind}',
        f'Site: {info["site"]}',
        'Trên máy chạy trình duyệt, thêm dòng hosts sau:',
        hosts_entry,
        r'File: /etc/hosts hoặc C:\Windows\System32\drivers\etc\hosts',
        ('Bind wildcard mở cổng trên mọi interface; thay placeholder bằng IP thật của Docker host, KHÔNG dùng 0.0.0.0/:: trong hosts.'
         if wildcard else 'Loopback chỉ dùng khi trình duyệt và Docker ở cùng máy.'),
        'Máy từ xa dùng IP LAN/Tailscale của Docker host trong hosts và cần truy cập được cổng 80/443.',
        'Muốn chỉ mở trong tailnet: chạy lại với --bind IP-Tailscale-đã-gán-cho-Docker-host.',
        f'Tải Root CA: {info["root_certificate"]}',
        f'Hoặc lấy file trên Docker host: {deployment.folder / "public" / "root.crt"}',
        f'SHA-256 của chứng chỉ DER: {info["root_sha256"]}',
        'So sánh fingerprint SHA-256 của chứng chỉ, KHÔNG phải hash file PEM.',
        'Linux/macOS (tùy chọn): openssl x509 -in root.crt -noout -fingerprint -sha256',
        'So sánh không phân biệt hoa/thường và bỏ dấu hai chấm.',
        'Windows: certutil -decode root.crt root.der',
        '         certutil -hashfile root.der SHA256',
        'Sau khi xác minh, tin Root CA trong user store: certutil -user -addstore Root root.crt',
        'Chỉ tin Root CA trên máy/profile lab dùng một lần. Root được tái sử dụng từ .lab-ca/ qua các lần setup.',
        'Chrome/Edge: bật chính sách local-root hard-fail RequireOnlineRevocationChecksForLocalAnchors.',
        'JSON: { "RequireOnlineRevocationChecksForLocalAnchors": true }',
        'Chrome Linux: đặt JSON trong /etc/opt/chrome/policies/managed/',
        'Windows (lệnh admin, bạn tự thực hiện cho trình duyệt đang dùng):',
        r'reg add HKLM\SOFTWARE\Policies\Google\Chrome /v RequireOnlineRevocationChecksForLocalAnchors /t REG_DWORD /d 1 /f',
        r'reg add HKLM\SOFTWARE\Policies\Microsoft\Edge /v RequireOnlineRevocationChecksForLocalAnchors /t REG_DWORD /d 1 /f',
        'Kiểm tra tại chrome://policy hoặc edge://policy; khởi động lại trình duyệt nếu cần.',
        'Chi tiết nền tảng khác: README, mục "Trình diễn trên trình duyệt thật". Firefox không tải CRL của lab.',
        f'Mở {info["site"]}, KHÔNG mở IP; mong đợi LEGITIMATE PAYROLL LAB.',
        'Script không tự mở trình duyệt, sửa hosts, cài CA hay chính sách.',
        'Sau phiên lab, tự gỡ thay đổi hosts/Root CA/chính sách; Docker teardown KHÔNG hoàn tác chúng.',
    ]), flush=True)
    pause_for_enter('Xác nhận hosts, Root CA, chính sách và trang ban đầu rồi nhấn Enter (Ctrl+C để dừng): ')


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


def print_browser_observation(row):
    print_observation(row)
    guidance = {
        'baseline': 'Mở site bình thường; mong đợi LEGITIMATE PAYROLL LAB.',
        'untrusted': ('Probe terminal cố ý dùng root không liên quan và phải từ chối. '
                      'Trình duyệt đã tin root lab nên có thể hiện ATTACKER PAYROLL LAB; không gỡ root giữa demo.'),
        'forged': 'Mong đợi ATTACKER PAYROLL LAB với chuỗi chứng chỉ hợp lệ trước thu hồi.',
        'hostname': ('Sai hostname chỉ là probe terminal tới other.payroll.test. Không thêm tên này vào hosts '
                     'hay đổi chứng chỉ; site bình thường vẫn do attacker kiểm soát, không tái hiện lỗi hostname.'),
        'revoked': ('Mong đợi từ chối chứng chỉ bị thu hồi: NET::ERR_CERT_REVOKED trên Chrome/Edge đã cấu hình. '
                    'Thiếu policy local-anchor có thể vẫn chấp nhận; không bỏ qua lỗi trình duyệt.'),
        'unchecked': ('Probe terminal tắt CRL nên chấp nhận cùng chứng chỉ attacker. Trình duyệt giữ policy '
                      'hard-fail vẫn phải từ chối; không tắt policy để bắt chước probe.'),
        'recovery': 'Mong đợi LEGITIMATE PAYROLL LAB dưới CA trung gian thay thế.',
    }
    print('\nTrình duyệt là client cấu hình riêng, không sao chép trust/CRL của từng probe.\n'
          'Đóng TẤT CẢ cửa sổ ẩn danh, mở cửa sổ ẩn danh mới để tránh kết nối/cache cũ.\n'
          f'Mở https://{HOST}/\n' + guidance[row['id']], flush=True)
    if row['id'] == 'recovery':
        pause_for_enter('Quan sát recovery TRƯỚC khi nhấn Enter: Enter kết thúc demo và gỡ gateway (Ctrl+C để dừng): ')
    else:
        pause_for_enter('Quan sát trình duyệt xong mới nhấn Enter để sang bước tiếp theo (Ctrl+C để dừng): ')


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
    parser.add_argument('--bind', help='host IP address to publish ports 80/443 on for guided interactive mode; '
                                       'required for browser, optional with setup')
    parser.add_argument('--check-crl', action='store_true', help='enable CRL checks for the probe action')
    parser.add_argument('--ocsp-cert', choices=('intermediate', 'replacement-intermediate'), default='intermediate',
                        help='certificate to query for the ocsp action')
    args = parser.parse_args()
    if args.action and args.action != 'setup' and not args.run_id:
        parser.error('--run-id is required for non-setup actions')
    if args.action == 'browser' and not args.bind:
        parser.error('--bind is required for the browser action')
    if args.bind is not None:
        if args.self_test or args.action not in (None, 'setup', 'browser'):
            parser.error('--bind is only valid in interactive mode or with the setup/browser actions')
        try:
            ipaddress.ip_address(args.bind)
        except ValueError:
            parser.error('--bind must be a valid IPv4 or IPv6 address')
    if not args.self_test and not args.action and not sys.stdin.isatty():
        parser.error('Interactive mode requires a terminal; use --self-test for unattended JSON execution.')
    try:
        if args.action:
            deployment = Deployment.create() if args.action == 'setup' else Deployment(args.run_id)
            if args.action == 'setup':
                try:
                    deployment.setup()
                    browser = deployment.browser(args.bind) if args.bind else {}
                except Exception as exc:
                    raise RuntimeError(f'Run {deployment.run_id}; state retained at {deployment.folder}: {exc}') from exc
                output = {'run_id': deployment.run_id, 'folder': str(deployment.folder)}
                output.update(browser)
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
            browser_notice = ('Sẽ mở browser gateway và in hướng dẫn cấu hình thủ công.\n'
                              if args.bind is not None else 'Chế độ terminal, không mở browser gateway.\n')
            print(f'Lab Docker cô lập cho {HOST}: 7 bước, nhấn Enter trước mỗi quan sát.\n'
                  'Đang setup/build và chờ các dịch vụ sẵn sàng; vui lòng đợi.\n'
                  + browser_notice
                  + 'Script không tự sửa DNS hay kho tin cậy của host.', flush=True)
        previous = signal.signal(signal.SIGTERM, interrupt)
        try:
            output = run_lab() if args.self_test else run_lab(
                before_step=prompt_step,
                on_observation=print_browser_observation if args.bind is not None else print_observation,
                browser_bind=args.bind)
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
