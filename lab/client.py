"""Observe a real DNS -> TCP -> verified TLS -> HTTP connection in the lab."""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import socket
import ssl
import sys
from urllib.parse import quote

from cryptography import x509


def observe(hostname, trust, check_crl, request_id):
    files = {'root': '/trust/root.crt', 'unrelated': '/trust/unrelated-root.crt',
             'bundle': '/trust/trust.pem'}
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(cafile=files[trust])
    if check_crl:
        context.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN
    result = dict.fromkeys(('hostname', 'resolved_ip', 'peer_ip', 'accepted', 'protocol',
                            'cipher', 'fingerprint', 'serial', 'issuer', 'http_status',
                            'http_origin', 'http_body', 'detail', 'openssl'))
    result.update(hostname=hostname, openssl=ssl.OPENSSL_VERSION)
    family, kind, protocol, _, destination = socket.getaddrinfo(
        hostname, 443, type=socket.SOCK_STREAM)[0]
    result['resolved_ip'] = destination[0]
    with socket.socket(family, kind, protocol) as raw:
        raw.settimeout(5)
        raw.connect(destination)
        result['peer_ip'] = raw.getpeername()[0]
        try:
            connection = context.wrap_socket(raw, server_hostname=hostname)
        except ssl.SSLCertVerificationError as exc:
            result.update(accepted=False, verify_code=exc.verify_code, detail=exc.verify_message)
            return result
        with connection:
            certificate_der = connection.getpeercert(binary_form=True)
            certificate = x509.load_der_x509_certificate(certificate_der)
            result.update(accepted=True, protocol=connection.version(), cipher=connection.cipher()[0],
                          fingerprint=hashlib.sha256(certificate_der).hexdigest(),
                          serial=format(certificate.serial_number, 'x'), issuer=certificate.issuer.rfc4514_string())
            path = '/evidence?request_id=' + quote(request_id, safe='')
            connection.sendall((f'GET {path} HTTP/1.1\r\nHost: {hostname}\r\n'
                                'Connection: close\r\n\r\n').encode('ascii'))
            response = http.client.HTTPResponse(connection)
            response.begin()
            body = response.read().decode('utf-8')
            result.update(http_status=response.status, http_origin=response.getheader('X-Lab-Origin'),
                          http_body=body, detail=body)
            return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hostname', default='login.payroll.test')
    parser.add_argument('--trust', choices=('root', 'unrelated', 'bundle'), default='bundle')
    parser.add_argument('--check-crl', action='store_true')
    parser.add_argument('--request-id', required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(observe(args.hostname, args.trust, args.check_crl, args.request_id)))
    except (OSError, ValueError, http.client.HTTPException) as exc:
        print(f'Operational error: {type(exc).__name__}: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
