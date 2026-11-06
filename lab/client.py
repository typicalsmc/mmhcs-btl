"""Observe a real DNS -> TCP -> verified TLS -> HTTP connection in the lab."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import http.client
import json
import socket
import ssl
import sys
from pathlib import Path
from urllib.parse import quote, urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import ocsp
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtendedKeyUsageOID


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


def ocsp_status(name, connect_ip):
    """Ask the OCSP URL named in a CA certificate, verify the signed answer, and report the status."""
    certificate = x509.load_pem_x509_certificate(Path(f'/trust/{name}.crt').read_bytes())
    issuer = x509.load_pem_x509_certificate(Path('/trust/root.crt').read_bytes())
    access = certificate.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
    urls = [entry.access_location.value for entry in access
            if entry.access_method == AuthorityInformationAccessOID.OCSP]
    if not urls:
        raise ValueError(f'{name} certificate has no OCSP URL')
    url = urlsplit(urls[0])
    if url.scheme != 'http' or not url.hostname:
        raise ValueError(f'Unsupported OCSP URL: {urls[0]}')
    request = ocsp.OCSPRequestBuilder().add_certificate(certificate, issuer, hashes.SHA1()).build()
    # Connect to the given address but keep the certificate's Host, independent of lab DNS.
    connection = http.client.HTTPConnection(connect_ip, url.port or 80, timeout=5)
    try:
        connection.request('POST', url.path or '/', request.public_bytes(serialization.Encoding.DER),
                           {'Host': url.netloc, 'Content-Type': 'application/ocsp-request',
                            'Connection': 'close'})
        reply = connection.getresponse()
        body = reply.read()
    finally:
        connection.close()
    if reply.status != 200:
        raise ValueError(f'OCSP HTTP status {reply.status}')
    response = ocsp.load_der_ocsp_response(body)
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise ValueError(f'OCSP response status {response.response_status.name}')
    signer = response.certificates[0] if response.certificates else issuer
    if signer != issuer:
        # Delegated responder (RFC 6960 4.2.2.2): issued by the CA and authorized for OCSPSigning.
        signer.verify_directly_issued_by(issuer)
        usage = signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        if ExtendedKeyUsageOID.OCSP_SIGNING not in usage:
            raise ValueError('OCSP signer is not authorized for OCSPSigning')
    signer.public_key().verify(response.signature, response.tbs_response_bytes, padding.PKCS1v15(),
                               response.signature_hash_algorithm)
    if response.serial_number != certificate.serial_number:
        raise ValueError('OCSP response is for a different certificate')
    now = dt.datetime.now(dt.timezone.utc)
    skew = dt.timedelta(minutes=5)
    if response.this_update_utc > now + skew or (
            response.next_update_utc is not None and response.next_update_utc < now - skew):
        raise ValueError('OCSP response is not current')
    revoked = response.certificate_status == ocsp.OCSPCertStatus.REVOKED
    return {
        'certificate': certificate.subject.rfc4514_string(),
        'serial': format(certificate.serial_number, 'x'),
        'url': urls[0],
        'responder': signer.subject.rfc4514_string(),
        'cert_status': response.certificate_status.name,
        'revocation_reason': (response.revocation_reason.name
                              if revoked and response.revocation_reason is not None else None),
        'revocation_time': response.revocation_time_utc.isoformat() if revoked else None,
        'this_update': response.this_update_utc.isoformat(),
        'next_update': response.next_update_utc.isoformat() if response.next_update_utc else None,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hostname', default='login.payroll.test')
    parser.add_argument('--trust', choices=('root', 'unrelated', 'bundle'), default='bundle')
    parser.add_argument('--check-crl', action='store_true')
    parser.add_argument('--request-id')
    parser.add_argument('--ocsp', choices=('intermediate', 'replacement-intermediate'),
                        help='query the OCSP responder named in this CA certificate instead of connecting over TLS')
    parser.add_argument('--ocsp-connect', help='IP address to send the OCSP request to')
    args = parser.parse_args()
    try:
        if args.ocsp:
            if not args.ocsp_connect:
                parser.error('--ocsp-connect is required with --ocsp')
            print(json.dumps(ocsp_status(args.ocsp, args.ocsp_connect)))
            return 0
        if not args.request_id:
            parser.error('--request-id is required')
        print(json.dumps(observe(args.hostname, args.trust, args.check_crl, args.request_id)))
    except (OSError, ValueError, http.client.HTTPException, InvalidSignature, x509.ExtensionNotFound) as exc:
        print(f'Operational error: {type(exc).__name__}: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
