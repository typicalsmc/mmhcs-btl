"""Loopback-only controller for a new, explicitly managed visual PKI session."""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import queue
import re
import secrets
import signal
import socket
import ssl
import threading

from demo import Deployment, LAB_STEPS, LabSession, atomic_text

MAX_BODY = 64 * 1024
PUBLIC_FIELDS = ('status', 'run_id', 'setup', 'steps', 'current_step_id',
                 'next_step_id', 'reference_results', 'browser_observations', 'error')
OBSERVATION_FIELDS = {'run_id', 'step_id', 'navigation_id', 'source', 'url', 'outcome',
                      'status_code', 'origin', 'error', 'observed_at'}
PATHS = {'/api/state', '/api/start', '/api/next', '/api/browser-observations', '/api/stop'}


class APIError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def validate_configuration(lab_ip, extension_id):
    """Validate literals and assignment without creating or changing a deployment."""
    if '%' in lab_ip:
        raise ValueError('--lab-ip must not contain an IPv6 scope identifier')
    try:
        address = ipaddress.ip_address(lab_ip)
    except ValueError as exc:
        raise ValueError('--lab-ip must be an assigned IPv4/IPv6 literal') from exc
    if address.is_unspecified or address.is_multicast:
        raise ValueError('--lab-ip cannot be unspecified or multicast')
    if not re.fullmatch(r'[a-p]{32}', extension_id):
        raise ValueError('--extension-id must contain exactly 32 letters a-p')
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as probe:
            probe.bind((str(address), 0))
    except OSError as exc:
        raise ValueError('--lab-ip must be assigned to this Docker host') from exc
    return str(address)


def compare_observation(record, expected):
    """Compare reported events; neither missing data nor generic errors imply TLS rejection."""
    if record['outcome'] == 'unobserved':
        return 'unobserved'
    match = False
    if record['outcome'] == expected['kind'] == 'http':
        match = (record['status_code'] == expected['status_code']
                 and record['origin'] == expected['origin'])
    elif record['outcome'] == expected['kind'] == 'error':
        match = record['error'].removeprefix('net::') == expected['error'].removeprefix('net::')
    return 'match' if match else 'mismatch'


class VisualController:
    """One in-memory run, one serialized worker, and explicit public snapshots.

    Construction creates no deployment and prints no token. Tests may inject factories
    and a writer; production always uses the shared Deployment and LabSession APIs.
    Call close() to await the active operation and clean up this controller's run.
    """
    def __init__(self, lab_ip, extension_id, *, token=None, deployment_factory=None,
                 session_factory=None, writer=atomic_text):
        self.lab_ip = validate_configuration(lab_ip, extension_id)
        self.origin = f'chrome-extension://{extension_id}'
        self.token = token if token is not None else secrets.token_urlsafe(32)
        if not isinstance(self.token, str) or not self.token or not self.token.isascii():
            raise ValueError('Token must be a nonempty ASCII string')
        self._deployment_factory = deployment_factory or Deployment.create
        self._session_factory = session_factory or LabSession
        self._writer = writer
        self._lock = threading.RLock()
        self._accepting = True
        self._closed = False
        self._deployment = None
        self._session = None
        self._down_complete = False
        self._logs_complete = False
        self._state = dict(status='idle', run_id=None, setup=None,
                           steps=[{key: copy.deepcopy(step[key]) for key in
                                   ('id', 'title', 'meaning_vi', 'checklist_vi', 'browser_expected')}
                                  | {'browser_url': f'https://{step["hostname"]}/evidence'}
                                  for step in LAB_STEPS],
                           current_step_id=None, next_step_id=None, reference_results=[],
                           browser_observations=[], error=None)
        self._operations = queue.Queue()
        self._worker = threading.Thread(target=self._work, name='visual-lab-worker', daemon=False)
        self._worker.start()

    def snapshot(self):
        with self._lock:
            return copy.deepcopy(self._state)

    def _diagnostic(self, exc):
        return f'{type(exc).__name__}: {exc}'.replace(self.token, '[redacted]')

    def _persist(self):
        if self._deployment is None:
            return
        evidence = {key: self._state[key] for key in
                    ('run_id', 'setup', 'reference_results', 'browser_observations', 'status', 'error')}
        evidence['browser_evidence_provenance'] = (
            'Trusted-extension-reported events; not cryptographically attested browser data. '
            'Expected browser results are not observations. OpenSSL results are reference evidence only.')
        self._writer(self._deployment.folder / 'browser-results.json',
                     json.dumps(evidence, ensure_ascii=False, indent=2))

    def _save_or_fail(self):
        try:
            self._persist()
        except Exception as exc:
            self._state.update(status='failed', error=f'Evidence save failed: {self._diagnostic(exc)}')
            raise APIError(500, self._state['error']) from exc

    @staticmethod
    def _body_keys(body, keys):
        if not isinstance(body, dict) or set(body) != set(keys):
            raise APIError(400, 'JSON object has missing or unexpected fields')

    def command(self, path, body):
        """Validate and atomically reserve mutations. Never retry a queued operation."""
        with self._lock:
            if not self._accepting:
                raise APIError(409, 'Controller is shutting down')
            if path == '/api/browser-observations':
                return 200, self._observe(body)
            if path == '/api/next':
                self._body_keys(body, ('step_id', 'acknowledge_mismatch'))
                if not isinstance(body['step_id'], str) or type(body['acknowledge_mismatch']) is not bool:
                    raise APIError(400, 'step_id must be text and acknowledge_mismatch must be boolean')
                if self._state['status'] != 'ready' or body['step_id'] != self._state['next_step_id']:
                    raise APIError(409, 'Step is not the next ready step')
                if self._state['current_step_id'] is not None:
                    latest = self._current_observation()
                    if latest is None or latest['outcome'] == 'unobserved':
                        raise APIError(409, 'A terminal Chrome observation is required; Reobserve')
                    if latest['comparison'] == 'mismatch':
                        if not body['acknowledge_mismatch']:
                            raise APIError(409, 'Explicit acknowledgement of the Chrome mismatch is required')
                        latest['acknowledged_mismatch'] = True
                        self._save_or_fail()
                operation = ('next', body['step_id'])
            elif path == '/api/start':
                self._body_keys(body, ())
                if self._state['status'] != 'idle':
                    raise APIError(409, 'Start is allowed only for an idle controller')
                operation = ('start', None)
            elif path == '/api/stop':
                self._body_keys(body, ())
                if self._state['status'] not in ('ready', 'complete', 'failed'):
                    raise APIError(409, 'Wait for the active operation before Stop')
                operation = ('stop', None)
            else:
                raise APIError(404, 'Unknown endpoint')
            self._state.update(status='busy', error=None)
            self._operations.put(operation)
            return 202, {'accepted': True}

    def _current_observation(self):
        return next((row for row in reversed(self._state['browser_observations'])
                     if row['step_id'] == self._state['current_step_id']), None)

    def _validate_observation(self, body):
        self._body_keys(body, OBSERVATION_FIELDS)
        if any(isinstance(value, str) and self.token in value for value in body.values()):
            raise APIError(400, 'Pairing credentials must not appear in browser evidence')
        if self._state['status'] not in ('ready', 'complete') or self._state['current_step_id'] is None:
            raise APIError(409, 'No current ready browser step')
        if body['run_id'] != self._state['run_id'] or body['step_id'] != self._state['current_step_id']:
            raise APIError(409, 'Observation is not for this run and current step')
        navigation = body['navigation_id']
        if not isinstance(navigation, str) or not re.fullmatch(r'[A-Za-z0-9-]{1,128}', navigation):
            raise APIError(400, 'Invalid navigation_id')
        step = next(step for step in LAB_STEPS if step['id'] == body['step_id'])
        expected_url = (f'https://{step["hostname"]}/evidence?request_id='
                        f'{body["run_id"]}-chrome-{body["step_id"]}-{navigation}')
        if body['url'] != expected_url:
            raise APIError(400, 'Observation URL must contain the exact expected hostname, path and navigation ID')
        if body['outcome'] not in ('http', 'error', 'unobserved'):
            raise APIError(400, 'Invalid observation outcome')
        expected_source = 'extension.lifecycle' if body['outcome'] == 'unobserved' else 'chrome.webRequest'
        if body['source'] != expected_source:
            raise APIError(400, 'Invalid observation provenance')
        status = body['status_code']
        if status is not None and (type(status) is not int or not 100 <= status <= 599):
            raise APIError(400, 'status_code must be an HTTP status or null')
        for field in ('origin', 'error'):
            if body[field] is not None and (not isinstance(body[field], str) or len(body[field]) > 1024):
                raise APIError(400, f'{field} must be bounded text or null')
        if body['outcome'] == 'http' and (status is None or body['error'] is not None):
            raise APIError(400, 'HTTP observations require an actual status and no network error')
        if body['outcome'] == 'error' and not body['error']:
            raise APIError(400, 'Error observations require the original Chrome network error')
        timestamp = body['observed_at']
        if not isinstance(timestamp, str) or len(timestamp) > 80:
            raise APIError(400, 'observed_at must be an ISO timestamp')
        try:
            parsed = dt.datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            if parsed.tzinfo is None:
                raise ValueError('Timezone required')
        except ValueError as exc:
            raise APIError(400, 'observed_at must be an ISO timestamp with timezone') from exc
        return step

    def _observe(self, body):
        self._body_keys(body, OBSERVATION_FIELDS)
        rows = self._state['browser_observations']
        existing = next((row for row in rows if row['navigation_id'] == body['navigation_id']), None)
        if existing is not None and all(existing[key] == body[key] for key in OBSERVATION_FIELDS):
            # In-memory deduplication is not proof that a prior disk write succeeded.
            self._save_or_fail()
            return copy.deepcopy(existing)
        step = self._validate_observation(body)
        record = copy.deepcopy(body)
        record.update(comparison=compare_observation(body, step['browser_expected']), acknowledged_mismatch=False)
        if existing is not None:
            # Update in place: an older navigation can never become the latest attempt.
            existing.clear()
            existing.update(record)
            record = existing
        else:
            rows.append(record)
        if step['id'] == LAB_STEPS[-1]['id'] and body['outcome'] in ('http', 'error'):
            self._state['status'] = 'complete'
        self._save_or_fail()
        return copy.deepcopy(record)

    def _start(self):
        deployment = self._deployment_factory()
        with self._lock:
            self._deployment = deployment
            self._state['run_id'] = deployment.run_id
        deployment.setup()
        setup = deployment.browser(self.lab_ip)
        root = (deployment.folder / 'public' / 'root.crt').read_text(encoding='ascii')
        der = ssl.PEM_cert_to_DER_cert(root)
        # These identify the same public DER. SHA-1 is only the Windows store selector.
        setup = {key: setup[key] for key in ('hosts_entry', 'site', 'root_certificate', 'root_sha256')}
        if setup['root_sha256'].lower().replace(':', '') != hashlib.sha256(der).hexdigest():
            raise RuntimeError('Browser setup root fingerprint differs from public root DER')
        setup.update(lab_ip=self.lab_ip, root_sha1=hashlib.sha1(der).hexdigest().upper())
        session = self._session_factory(deployment)
        with self._lock:
            self._session = session
            self._state.update(setup=setup, status='ready', next_step_id=LAB_STEPS[0]['id'])
            self._save_or_fail()

    def _next(self, step_id):
        row = self._session.run_next(step_id)
        index = next(index for index, step in enumerate(LAB_STEPS) if step['id'] == step_id)
        # Publish the completed reference even when summary publication subsequently fails.
        with self._lock:
            self._state['reference_results'].append(copy.deepcopy(row))
            self._state.update(current_step_id=step_id,
                               next_step_id=LAB_STEPS[index + 1]['id'] if index + 1 < len(LAB_STEPS) else None)
        if index == len(LAB_STEPS) - 1:
            self._session.summary()
        with self._lock:
            self._state['status'] = 'ready'
            self._save_or_fail()

    def _cleanup(self):
        if self._deployment is None:
            return
        errors = []
        if not self._logs_complete:
            try:
                self._writer(self._deployment.folder / 'docker.log', self._deployment.logs())
                self._logs_complete = True
            except Exception as exc:
                errors.append(f'Log capture failed: {self._diagnostic(exc)}')
        if not self._down_complete:
            try:
                self._deployment.down()
                self._down_complete = True
            except Exception as exc:
                errors.append(f'Teardown failed: {self._diagnostic(exc)}')
        if errors:
            raise RuntimeError('; '.join(errors))

    def _work(self):
        while True:
            operation, argument = self._operations.get()
            try:
                if operation == 'shutdown':
                    self._cleanup()
                    with self._lock:
                        if self._deployment is not None:
                            self._state.update(status='stopped', error=None)
                            self._save_or_fail()
                    return
                if operation == 'start':
                    self._start()
                elif operation == 'next':
                    self._next(argument)
                elif operation == 'stop':
                    self._cleanup()
                    with self._lock:
                        self._state.update(status='stopped', error=None)
                        self._save_or_fail()
            except Exception as exc:
                diagnostic = self._diagnostic(exc)
                if operation == 'start':
                    try:
                        self._cleanup()
                    except Exception as cleanup_error:
                        diagnostic += '; ' + self._diagnostic(cleanup_error)
                with self._lock:
                    self._state.update(status='failed', error=diagnostic)
                    try:
                        self._persist()
                    except Exception as save_error:
                        self._state['error'] += '; Evidence save failed: ' + self._diagnostic(save_error)
                if operation == 'shutdown':
                    return
            finally:
                self._operations.task_done()

    def close(self):
        """Stop accepting commands, await the active worker, then clean up owned resources."""
        with self._lock:
            if not self._closed:
                self._closed = True
                self._accepting = False
                self._operations.put(('shutdown', None))
        self._worker.join()


class VisualHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, controller, port=8765):
        self.controller = controller
        super().__init__(('127.0.0.1', port), VisualHandler)
        self.expected_host = f'127.0.0.1:{self.server_port}'


class VisualHandler(BaseHTTPRequestHandler):
    # No HTTP request/header/token is emitted into access logs.
    def log_message(self, format, *args):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def _reply(self, status, body, *, preflight=None):
        encoded = json.dumps(body, ensure_ascii=False, allow_nan=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(encoded)))
        self.send_header('Connection', 'close')
        if getattr(self, '_allowed_origin', False):
            self.send_header('Access-Control-Allow-Origin', self.server.controller.origin)
            self.send_header('Vary', 'Origin')
        if preflight is not None:
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Authorization, Content-Type')
            if preflight:
                self.send_header('Access-Control-Allow-Private-Network', 'true')
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(encoded)
        self.close_connection = True

    def send_error(self, code, message=None, explain=None):
        # Includes BaseHTTPRequestHandler parser errors and unsupported methods: never HTML.
        self._reply(code, {'error': 'Invalid HTTP request' if code != 501 else 'Method not allowed'})

    def _access(self, *, preflight=False):
        if self.headers.get_all('Host') != [self.server.expected_host]:
            raise APIError(403, 'Host is not the loopback controller')
        origins = self.headers.get_all('Origin')
        if origins is not None and origins != [self.server.controller.origin]:
            raise APIError(403, 'Origin is not the paired extension')
        if preflight and origins is None:
            raise APIError(403, 'Preflight requires the paired extension origin')
        self._allowed_origin = origins is not None
        if not preflight:
            authorization = self.headers.get_all('Authorization')
            expected = 'Bearer ' + self.server.controller.token
            if (authorization is None or len(authorization) != 1 or not authorization[0].isascii()
                    or not hmac.compare_digest(authorization[0], expected)):
                raise APIError(401, 'Missing or invalid bearer token')

    def _json(self):
        if self.headers.get_all('Transfer-Encoding') or self.headers.get_all('Content-Encoding'):
            raise APIError(400, 'Encoded or chunked request bodies are not supported')
        types = self.headers.get_all('Content-Type')
        if types is None or len(types) != 1 or not re.fullmatch(
                r'application/json(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?', types[0], re.I):
            raise APIError(400, 'Content-Type must be application/json with UTF-8 encoding')
        lengths = self.headers.get_all('Content-Length')
        if lengths is None or len(lengths) != 1 or not re.fullmatch(r'[0-9]+', lengths[0]):
            raise APIError(400, 'One valid Content-Length is required')
        significant = lengths[0].lstrip('0') or '0'
        if len(significant) > len(str(MAX_BODY)):
            raise APIError(413, 'JSON body exceeds 64 KiB')
        length = int(significant)
        if length > MAX_BODY:
            raise APIError(413, 'JSON body exceeds 64 KiB')
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError('Incomplete body')
            def unique_object(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError('Duplicate JSON key')
                    result[key] = value
                return result
            def reject_constant(value):
                raise ValueError('Non-finite JSON number')
            return json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object,
                              parse_constant=reject_constant)
        except (ValueError, RecursionError, socket.timeout) as exc:
            raise APIError(400, 'Malformed UTF-8 JSON body') from exc

    def _handle(self):
        try:
            self._access(preflight=self.command == 'OPTIONS')
            if self.path not in PATHS:
                raise APIError(404, 'Unknown endpoint')
            if self.command == 'OPTIONS':
                method = self.headers.get_all('Access-Control-Request-Method')
                if method not in (['GET'], ['POST']):
                    raise APIError(403, 'Preflight method is not allowed')
                requested = self.headers.get_all('Access-Control-Request-Headers') or []
                headers = {item.strip().lower() for value in requested for item in value.split(',')}
                if not headers <= {'authorization', 'content-type'}:
                    raise APIError(403, 'Preflight headers are not allowed')
                private = self.headers.get_all('Access-Control-Request-Private-Network')
                if private is not None and private != ['true']:
                    raise APIError(403, 'Invalid private-network preflight')
                self._reply(200, {}, preflight=private == ['true'])
                return
            if self.command == 'GET' and self.path == '/api/state':
                self._reply(200, self.server.controller.snapshot())
            elif self.command == 'POST' and self.path != '/api/state':
                status, body = self.server.controller.command(self.path, self._json())
                self._reply(status, body)
            else:
                raise APIError(405, 'Method is not allowed for this endpoint')
        except APIError as exc:
            self._reply(exc.status, {'error': str(exc)})

    do_GET = _handle
    do_POST = _handle
    do_OPTIONS = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_PATCH = _handle
    do_HEAD = _handle
    do_TRACE = _handle
    do_CONNECT = _handle


def create_server(controller, *, port=8765):
    """Bind loopback only; port=0 is supported for isolated HTTP boundary tests."""
    return VisualHTTPServer(controller, port)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab-ip', required=True)
    parser.add_argument('--extension-id', required=True)
    args = parser.parse_args()
    try:
        controller = VisualController(args.lab_ip, args.extension_id)
    except ValueError as exc:
        parser.error(str(exc))
    try:
        server = create_server(controller)
    except OSError as exc:
        controller.close()
        parser.error(f'Cannot bind 127.0.0.1:8765: {exc}')
    shutdown = threading.Event()
    def request_shutdown(signum, frame):
        with controller._lock:
            controller._accepting = False
        shutdown.set()
    previous = {sig: signal.signal(sig, request_shutdown) for sig in (signal.SIGINT, signal.SIGTERM)}
    server.timeout = 0.25
    print('Control ready: http://127.0.0.1:8765', flush=True)
    print(f'Pairing token (private): {controller.token}', flush=True)
    print('Windows tunnel: ssh -N -L 127.0.0.1:8765:127.0.0.1:8765 USER@DOCKER_HOST', flush=True)
    print('No deployment exists until Start. Do not restart/replay an old visual run.', flush=True)
    try:
        while not shutdown.is_set():
            server.handle_request()
    finally:
        server.server_close()
        controller.close()
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    state = controller.snapshot()
    if state['status'] == 'failed':
        print(f'Cleanup failed: {state["error"]}', flush=True)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
