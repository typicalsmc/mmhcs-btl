"""Controller isolation tests. Fake deployment data is not evidence of real TLS behavior."""
import concurrent.futures
import hashlib
import http.client
import json
import pathlib
import ssl
import tempfile
import threading
import unittest
from unittest import mock

from demo import LAB_STEPS, LabSession, atomic_text
from visual_demo import (MAX_BODY, PUBLIC_FIELDS, VisualController, compare_observation,
                         create_server, validate_configuration)

EXTENSION_ID = 'a' * 32
TOKEN = 'private-test-pairing-token'
PUBLIC_DER = b'controller isolation test public DER, not a real certificate'


class ControlledDeployment:
    """Only isolate state transitions, calls, and publication; no network/TLS simulation claim."""
    def __init__(self, folder):
        self.folder = pathlib.Path(folder)
        self.run_id = '0123456789ab'
        (self.folder / 'public').mkdir()
        (self.folder / 'public' / 'root.crt').write_text(ssl.DER_cert_to_PEM_cert(PUBLIC_DER))
        self.addresses = {'legitimate': '10.0.0.2', 'attacker': '10.0.0.3'}
        self.calls = []
        self.fail_probe = False
        self.fail_setup = False
        self.fail_down = False
        self.block_step = None
        self.entered = threading.Event()
        self.release = threading.Event()

    def setup(self):
        self.calls.append('setup')
        if self.fail_setup:
            raise RuntimeError('controlled setup failure')

    def browser(self, bind):
        self.calls.append('browser')
        return {'hosts_entry': f'{bind} login.payroll.test other.payroll.test crl.payroll.test ocsp.payroll.test',
                'site': 'https://login.payroll.test/', 'root_certificate': 'http://crl.payroll.test/root.crt',
                'root_sha256': hashlib.sha256(PUBLIC_DER).hexdigest()}

    def attack(self):
        self.calls.append('attack')

    def revoke(self):
        self.calls.append('revoke')
        return 'controlled revocation output'

    def recover(self):
        self.calls.append('recover')

    def probe(self, hostname, trust, check_crl, request_id):
        self.calls.append('probe')
        step = next(step for step in LAB_STEPS if request_id == f'{self.run_id}-{step["id"]}')
        if self.block_step == step['id']:
            self.entered.set()
            if not self.release.wait(5):
                raise RuntimeError('test did not release controlled probe')
        if self.fail_probe:
            raise RuntimeError('controlled probe failure after preparation')
        service = step['service']
        return {'accepted': step['expected'], 'resolved_ip': self.addresses[service],
                'peer_ip': self.addresses[service], 'protocol': 'TLSv1.3', 'http_status': 200,
                'http_origin': service, 'http_body': f'{service.upper()} PAYROLL LAB\n',
                'verify_code': step['code'], 'fingerprint': ('recovery' if step['id'] == 'recovery'
                                                            else service),
                'issuer': ('Replacement Intermediate CA' if step['id'] == 'recovery' else 'original issuer'),
                'serial': 'test-serial', 'openssl': 'controlled reference fixture'}

    def ocsp(self, certificate):
        revoked = 'revoke' in self.calls and certificate != 'replacement-intermediate'
        return {'cert_status': 'REVOKED' if revoked else 'GOOD', 'revocation_reason': 'ca_compromise'}

    def logs(self):
        self.calls.append('logs')
        return 'controlled logs, not real Docker evidence'

    def down(self):
        self.calls.append('down')
        if self.fail_down:
            raise RuntimeError('controlled teardown failure')


class ControllerHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.deployment = ControlledDeployment(self.temporary.name)
        self.creations = 0
        def create():
            self.creations += 1
            return self.deployment
        base_patch = mock.patch('demo.BASE', self.deployment.folder)
        base_patch.start()
        self.addCleanup(base_patch.stop)
        self.controller = VisualController('127.0.0.1', EXTENSION_ID, token=TOKEN,
                                           deployment_factory=create)
        self.server = create_server(self.controller, port=0)
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()

    def tearDown(self):
        self.deployment.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join()
        self.controller.close()
        self.temporary.cleanup()

    def request(self, method, path='/api/state', body=None, *, token=TOKEN, origin=None,
                headers=None, raw=None):
        all_headers = {}
        if token is not None:
            all_headers['Authorization'] = 'Bearer ' + token
        if origin is not None:
            all_headers['Origin'] = origin
        if body is not None:
            raw = json.dumps(body).encode()
        if raw is not None:
            all_headers['Content-Type'] = 'application/json'
        all_headers.update(headers or {})
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=10)
        try:
            connection.request(method, path, body=raw, headers=all_headers)
            response = connection.getresponse()
            result = response.status, json.loads(response.read()), dict(response.getheaders())
            return result
        finally:
            connection.close()

    def settled(self):
        self.controller._operations.join()
        return self.controller.snapshot()

    def start(self):
        self.assertEqual(self.request('POST', '/api/start', {})[0], 202)
        state = self.settled()
        self.assertEqual(state['status'], 'ready', state)
        return state

    def prepare(self, step_id, acknowledge=False):
        status, body, _ = self.request('POST', '/api/next',
                                     {'step_id': step_id, 'acknowledge_mismatch': acknowledge})
        self.assertEqual(status, 202, body)
        state = self.settled()
        self.assertEqual(state['status'], 'ready', state)
        self.assertEqual(state['current_step_id'], step_id)
        return state

    def observation(self, navigation='attempt-1', **changes):
        state = self.controller.snapshot()
        step = next(step for step in LAB_STEPS if step['id'] == state['current_step_id'])
        expected = step['browser_expected']
        record = dict(run_id=state['run_id'], step_id=step['id'], navigation_id=navigation,
                      source='chrome.webRequest',
                      url=f'https://{step["hostname"]}/evidence?request_id={state["run_id"]}-chrome-{step["id"]}-{navigation}',
                      outcome=expected['kind'], status_code=expected.get('status_code'),
                      origin=expected.get('origin'), error=expected.get('error'),
                      observed_at='2026-11-07T00:00:00.000Z')
        record.update(changes)
        return record

    def observe(self, navigation='attempt-1', **changes):
        record = self.observation(navigation, **changes)
        status, result, _ = self.request('POST', '/api/browser-observations', record)
        self.assertEqual(status, 200, result)
        return record, result

    def advance_to_before(self, target):
        self.start()
        for step in LAB_STEPS:
            if step['id'] == target:
                break
            self.prepare(step['id'])
            self.observe(step['id'] + '-observation')

    def test_idle_reads_reconnects_do_not_create_or_teardown(self):
        for _ in range(3):
            status, state, headers = self.request('GET')
            self.assertEqual(status, 200)
            self.assertEqual(set(state), set(PUBLIC_FIELDS))
            self.assertEqual(state['status'], 'idle')
            self.assertIsNone(state['run_id'])
            self.assertIsNone(state['next_step_id'])
            self.assertEqual(headers['Cache-Control'], 'no-store')
            self.assertNotIn(TOKEN, json.dumps(state))
        self.assertEqual(self.creations, 0)
        self.start()
        self.prepare('baseline')
        before = self.controller.snapshot()
        for _ in range(3):
            self.assertEqual(self.request('GET')[1], before)
        self.assertEqual(self.creations, 1)
        self.assertNotIn('down', self.deployment.calls)

    def test_authentication_origin_host_and_unknown_routes(self):
        for token in (None, '', TOKEN + 'x'):
            self.assertEqual(self.request('GET', token=token)[0], 401)
        for origin in ('https://evil.example', 'null', 'chrome-extension://' + 'b' * 32):
            self.assertEqual(self.request('GET', origin=origin)[0], 403)
        self.assertEqual(self.request('GET', headers={'Host': 'localhost:' + str(self.server.server_port)})[0], 403)
        status, _, headers = self.request('GET', origin=self.controller.origin)
        self.assertEqual(status, 200)
        self.assertEqual(headers['Access-Control-Allow-Origin'], self.controller.origin)
        self.assertNotIn('Access-Control-Allow-Credentials', headers)
        self.assertEqual(self.request('GET', '/root.crt')[0], 404)
        self.assertEqual(self.request('PUT', '/api/start', {})[0], 405)
        self.assertEqual(self.request('POST', '/api/state', {})[0], 405)
        self.assertEqual(self.creations, 0)

    def test_duplicate_authorization_headers_do_not_bypass_auth(self):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=5)
        try:
            connection.putrequest('GET', '/api/state')
            connection.putheader('Authorization', 'Bearer ' + TOKEN)
            connection.putheader('Authorization', 'Bearer wrong')
            connection.endheaders()
            response = connection.getresponse()
            self.assertEqual(response.status, 401)
            response.read()
        finally:
            connection.close()

    def test_preflight_is_the_only_token_exception_and_never_starts_a_run(self):
        headers = {'Access-Control-Request-Method': 'POST',
                   'Access-Control-Request-Headers': 'authorization, content-type',
                   'Access-Control-Request-Private-Network': 'true'}
        status, _, response_headers = self.request('OPTIONS', '/api/start', token=None,
                                                 origin=self.controller.origin, headers=headers)
        self.assertEqual(status, 200)
        self.assertEqual(response_headers['Access-Control-Allow-Private-Network'], 'true')
        self.assertEqual(self.creations, 0)
        self.assertEqual(self.request('OPTIONS', '/api/start', token=None, headers=headers)[0], 403)
        headers['Access-Control-Request-Headers'] = 'x-arbitrary-header'
        self.assertEqual(self.request('OPTIONS', '/api/start', token=None,
                                      origin=self.controller.origin, headers=headers)[0], 403)

    def test_malformed_oversized_and_unexpected_json_never_start(self):
        for raw in (b'{', b'\xff', b'[]', b'{"duplicate":1,"duplicate":2}', b'{"x":NaN}'):
            self.assertEqual(self.request('POST', '/api/start', raw=raw)[0], 400)
        self.assertEqual(self.request('POST', '/api/start', raw=b' ' * (MAX_BODY + 1))[0], 413)
        self.assertEqual(self.request('POST', '/api/start', {}, headers={'Content-Type': 'text/plain'})[0], 400)
        self.assertEqual(self.request('POST', '/api/start', {'unexpected': True})[0], 400)
        self.assertEqual(self.request('POST', '/api/start', raw=b'{}',
                                      headers={'Content-Length': '9' * 5000})[0], 413)
        self.assertEqual(self.controller.snapshot()['status'], 'idle')
        self.assertEqual(self.creations, 0)

    def test_order_and_lifecycle_only_observations_cannot_unlock_next(self):
        self.start()
        self.assertEqual(self.request('POST', '/api/next',
                                      {'step_id': 'forged', 'acknowledge_mismatch': False})[0], 409)
        self.prepare('baseline')
        next_body = {'step_id': 'untrusted', 'acknowledge_mismatch': False}
        self.assertEqual(self.request('POST', '/api/next', next_body)[0], 409)
        self.observe(source='extension.lifecycle', outcome='unobserved', status_code=None, origin=None)
        self.assertEqual(self.request('POST', '/api/next', next_body)[0], 409)
        self.observe('actual-terminal')
        self.prepare('untrusted')
        self.assertEqual(self.request('POST', '/api/next', next_body)[0], 409)
        self.assertEqual(self.deployment.calls.count('attack'), 1)

    def test_mismatch_acknowledgement_is_explicit_and_persisted(self):
        self.start()
        self.prepare('baseline')
        _, result = self.observe(origin=None)
        self.assertEqual(result['comparison'], 'mismatch')
        self.assertEqual(self.request('POST', '/api/next',
                                      {'step_id': 'untrusted', 'acknowledge_mismatch': False})[0], 409)
        self.prepare('untrusted', acknowledge=True)
        evidence = json.loads((self.deployment.folder / 'browser-results.json').read_text())
        self.assertTrue(evidence['browser_observations'][0]['acknowledged_mismatch'])
        self.assertNotIn('all_passed', evidence)
        self.assertNotIn(TOKEN, json.dumps(evidence))
        self.assertEqual(evidence['setup']['root_sha1'], hashlib.sha1(PUBLIC_DER).hexdigest().upper())

    def test_duplicate_old_observation_is_idempotent_and_does_not_become_latest(self):
        self.start()
        self.prepare('baseline')
        old, _ = self.observe('old')
        self.observe('new', outcome='error', status_code=None, origin=None, error='net::ERR_CONNECTION_REFUSED')
        self.assertEqual(self.request('POST', '/api/browser-observations', old)[0], 200)
        rows = self.controller.snapshot()['browser_observations']
        self.assertEqual([row['navigation_id'] for row in rows], ['old', 'new'])
        self.assertEqual(self.request('POST', '/api/next',
                                      {'step_id': 'untrusted', 'acknowledge_mismatch': False})[0], 409)
        self.prepare('untrusted', acknowledge=True)
        self.assertEqual(self.request('POST', '/api/browser-observations', old)[0], 200)
        self.assertEqual(self.controller.snapshot()['current_step_id'], 'untrusted')
        self.assertEqual(len(self.controller.snapshot()['browser_observations']), 2)

    def test_wrong_nonce_host_path_source_and_types_are_rejected(self):
        self.start()
        self.prepare('baseline')
        for changes in ({'url': 'https://login.payroll.test/evidence?request_id=wrong'},
                        {'url': 'https://other.payroll.test/evidence'},
                        {'source': 'extension.lifecycle'}, {'status_code': True},
                        {'origin': ['legitimate']}, {'error': 5}, {'observed_at': 'yesterday'},
                        {'navigation_id': '../private'}, {'unexpected': 'field'}):
            record = self.observation(**changes)
            self.assertEqual(self.request('POST', '/api/browser-observations', record)[0], 400, changes)
        record = self.observation(run_id='other-run')
        self.assertEqual(self.request('POST', '/api/browser-observations', record)[0], 409)
        self.assertEqual(self.controller.snapshot()['browser_observations'], [])

    def test_concurrent_next_cannot_repeat_revoke_or_recover_and_stop_waits(self):
        for target in ('revoked', 'recovery'):
            with self.subTest(target=target):
                if target == 'revoked':
                    self.advance_to_before(target)
                else:
                    self.observe('revoked-terminal')
                    self.prepare('unchecked')
                    self.observe('unchecked-terminal')
                self.deployment.block_step = target
                self.deployment.entered.clear()
                self.deployment.release.clear()
                body = {'step_id': target, 'acknowledge_mismatch': False}
                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                        futures = [pool.submit(self.request, 'POST', '/api/next', body) for _ in range(8)]
                        statuses = [future.result()[0] for future in futures]
                    self.assertEqual(statuses.count(202), 1, statuses)
                    self.assertEqual(statuses.count(409), 7, statuses)
                    self.assertTrue(self.deployment.entered.wait(2))
                    self.assertEqual(self.request('POST', '/api/stop', {})[0], 409)
                finally:
                    self.deployment.release.set()
                self.assertEqual(self.settled()['status'], 'ready')
                self.assertEqual(self.deployment.calls.count('revoke' if target == 'revoked' else 'recover'), 1)

    def test_final_mismatch_completes_without_teardown_and_allows_reobservation(self):
        self.advance_to_before('recovery')
        # Keep legacy summary publication inside this temporary fixture directory.
        with mock.patch('demo.BASE', self.deployment.folder):
            self.prepare('recovery')
        self.assertEqual(self.controller.snapshot()['status'], 'ready')
        self.observe('final-mismatch', outcome='error', status_code=None, origin=None,
                     error='net::ERR_CONNECTION_REFUSED')
        self.assertEqual(self.controller.snapshot()['status'], 'complete')
        self.assertEqual(self.controller.snapshot()['browser_observations'][-1]['comparison'], 'mismatch')
        self.assertNotIn('down', self.deployment.calls)
        self.observe('final-reobserve')
        self.assertEqual(len(self.controller.snapshot()['browser_observations']), 8)
        self.assertEqual(self.request('POST', '/api/stop', {})[0], 202)
        self.assertEqual(self.settled()['status'], 'stopped')
        self.assertEqual(self.deployment.calls.count('down'), 1)
        self.assertLess(self.deployment.calls.index('logs'), self.deployment.calls.index('down'))
        self.assertTrue((self.deployment.folder / 'public' / 'root.crt').exists())

    def test_setup_failure_cleans_only_new_run_and_keeps_diagnostics(self):
        self.deployment.fail_setup = True
        self.assertEqual(self.request('POST', '/api/start', {})[0], 202)
        state = self.settled()
        self.assertEqual(state['status'], 'failed')
        self.assertIn('controlled setup failure', state['error'])
        self.assertEqual(self.deployment.calls.count('down'), 1)
        self.assertEqual(self.request('POST', '/api/start', {})[0], 409)

    def test_probe_failure_latches_controller_and_never_replays_preparation(self):
        self.advance_to_before('revoked')
        self.deployment.fail_probe = True
        body = {'step_id': 'revoked', 'acknowledge_mismatch': False}
        self.assertEqual(self.request('POST', '/api/next', body)[0], 202)
        self.assertEqual(self.settled()['status'], 'failed')
        self.assertEqual(self.request('POST', '/api/next', body)[0], 409)
        self.assertEqual(self.deployment.calls.count('revoke'), 1)
        self.assertEqual(self.request('POST', '/api/stop', {})[0], 202)
        self.assertEqual(self.settled()['status'], 'stopped')

    def test_evidence_save_failure_is_not_reported_as_success(self):
        self.start()
        self.prepare('baseline')
        def fail_write(path, text):
            raise OSError('controlled disk failure')
        self.controller._writer = fail_write
        status, body, _ = self.request('POST', '/api/browser-observations', self.observation())
        self.assertEqual(status, 500)
        self.assertIn('Evidence save failed', body['error'])
        self.assertEqual(self.controller.snapshot()['status'], 'failed')
        # A timed-out client may resend the same captured navigation after disk failure.
        self.assertEqual(self.request('POST', '/api/browser-observations', self.observation())[0], 500)
        self.controller._writer = atomic_text
        self.assertEqual(self.request('POST', '/api/browser-observations', self.observation())[0], 200)
        saved = json.loads((self.deployment.folder / 'browser-results.json').read_text())
        self.assertEqual(saved['browser_observations'], self.controller.snapshot()['browser_observations'])

    def test_cleanup_failure_allows_explicit_stop_retry(self):
        self.start()
        self.deployment.fail_down = True
        self.assertEqual(self.request('POST', '/api/stop', {})[0], 202)
        state = self.settled()
        self.assertEqual(state['status'], 'failed')
        self.assertIn('Teardown failed', state['error'])
        self.deployment.fail_down = False
        self.assertEqual(self.request('POST', '/api/stop', {})[0], 202)
        self.assertEqual(self.settled()['status'], 'stopped')
        self.assertEqual(self.deployment.calls.count('down'), 2)

    def test_shutdown_awaits_active_operation_then_captures_logs_and_tears_down(self):
        self.start()
        self.deployment.block_step = 'baseline'
        self.assertEqual(self.request('POST', '/api/next',
                                      {'step_id': 'baseline', 'acknowledge_mismatch': False})[0], 202)
        self.assertTrue(self.deployment.entered.wait(2))
        closed = threading.Event()
        def close():
            self.controller.close()
            closed.set()
        closer = threading.Thread(target=close)
        closer.start()
        try:
            self.assertFalse(closed.wait(0.05))
            self.assertNotIn('down', self.deployment.calls)
        finally:
            self.deployment.release.set()
            closer.join(5)
        self.assertTrue(closed.is_set())
        self.assertEqual(self.controller.snapshot()['status'], 'stopped')
        self.assertEqual(self.deployment.calls.count('down'), 1)


class SharedEngineFailureTests(unittest.TestCase):
    def test_preparation_succeeded_probe_failed_latches_actual_engine(self):
        for target, action in (('revoked', 'revoke'), ('recovery', 'recover')):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as folder:
                deployment = ControlledDeployment(folder)
                session = LabSession(deployment)
                index = next(index for index, step in enumerate(LAB_STEPS) if step['id'] == target)
                session.results = [{} for _ in range(index)]
                deployment.fail_probe = True
                with self.assertRaisesRegex(RuntimeError, 'controlled probe failure'):
                    session.run_next(target)
                self.assertIsNotNone(session.failure)
                with self.assertRaisesRegex(RuntimeError, 'stop rather than replay'):
                    session.run_next(target)
                self.assertEqual(deployment.calls.count(action), 1)
                with self.assertRaises(ValueError):
                    session.summary()


class ComparisonAndConfigurationTests(unittest.TestCase):
    def test_http_requires_observed_status_and_origin(self):
        expected = {'kind': 'http', 'status_code': 200, 'origin': 'legitimate'}
        for origin in (None, 'attacker', 'LEGITIMATE'):
            self.assertEqual(compare_observation({'outcome': 'http', 'status_code': 200,
                                                  'origin': origin}, expected), 'mismatch')
        self.assertEqual(compare_observation({'outcome': 'http', 'status_code': 503,
                                              'origin': 'legitimate'}, expected), 'mismatch')
        self.assertEqual(compare_observation({'outcome': 'http', 'status_code': 200,
                                              'origin': 'legitimate'}, expected), 'match')

    def test_generic_errors_never_become_certificate_errors(self):
        expected = {'kind': 'error', 'error': 'net::ERR_CERT_REVOKED'}
        for error in ('net::ERR_ABORTED', 'net::ERR_CONNECTION_REFUSED', 'ERR_CERT_AUTHORITY_INVALID'):
            self.assertEqual(compare_observation({'outcome': 'error', 'error': error}, expected), 'mismatch')
        for error in ('net::ERR_CERT_REVOKED', 'ERR_CERT_REVOKED'):
            self.assertEqual(compare_observation({'outcome': 'error', 'error': error}, expected), 'match')
        self.assertEqual(compare_observation({'outcome': 'unobserved'}, expected), 'unobserved')

    def test_invalid_configuration_fails_before_deployment(self):
        for ip in ('0.0.0.0', '::', '224.0.0.1', 'ff02::1', 'hostname.example', 'fe80::1%eth0'):
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                validate_configuration(ip, EXTENSION_ID)
        for extension in ('', 'q' * 32, 'a' * 31, 'A' * 32):
            with self.subTest(extension=extension), self.assertRaises(ValueError):
                validate_configuration('127.0.0.1', extension)
        with mock.patch('visual_demo.socket.socket') as socket_factory:
            socket_factory.return_value.__enter__.return_value.bind.side_effect = OSError('not assigned')
            with self.assertRaisesRegex(ValueError, 'assigned'):
                validate_configuration('192.0.2.1', EXTENSION_ID)


if __name__ == '__main__':
    unittest.main()
