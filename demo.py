"""Local TLS/PKI lab. No OS trust-store changes, all sockets bind loopback."""
from __future__ import annotations
import argparse, datetime as dt, hashlib, http.server, json, pathlib, socket, ssl, threading, uuid
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

BASE = pathlib.Path(__file__).resolve().parent
HOST = 'login.payroll.test'

def key(): return rsa.generate_private_key(public_exponent=65537, key_size=2048)
def name(cn): return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
def cert(cn, subject_key, issuer_cert=None, issuer_key=None, ca=False, path=None):
    now = dt.datetime.now(dt.timezone.utc)
    subject = name(cn)
    b = (x509.CertificateBuilder().subject_name(subject)
         .issuer_name(issuer_cert.subject if issuer_cert else subject)
         .public_key(subject_key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now-dt.timedelta(minutes=5)).not_valid_after(now+dt.timedelta(days=30))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=path), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
             key_encipherment=not ca, data_encipherment=False, key_agreement=False,
             key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), False))
    signing_key = issuer_key or subject_key
    b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()), False)
    if not ca:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), False)
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
    return b.sign(signing_key, hashes.SHA256())

def pem(obj): return obj.public_bytes(serialization.Encoding.PEM)
def crl(issuer, signing_key, revoked=None):
    now = dt.datetime.now(dt.timezone.utc)
    b = (x509.CertificateRevocationListBuilder().issuer_name(issuer.subject)
         .last_update(now-dt.timedelta(minutes=1)).next_update(now+dt.timedelta(days=1))
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()), False))
    if revoked:
        entry = (x509.RevokedCertificateBuilder().serial_number(revoked.serial_number)
                 .revocation_date(now-dt.timedelta(seconds=30))
                 .add_extension(x509.CRLReason(x509.ReasonFlags.ca_compromise), False).build())
        b = b.add_revoked_certificate(entry)
    return b.sign(signing_key, hashes.SHA256())

def handshake(folder, chain_name, key_name, trust, hostname=HOST, check_crl=False):
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    server_ctx.load_cert_chain(str(folder/chain_name), str(folder/key_name))
    listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(8)
    port = listener.getsockname()[1]
    def serve():
        try:
            raw, _ = listener.accept(); raw.settimeout(5)
            with raw:
                try:
                    with server_ctx.wrap_socket(raw, server_side=True) as conn:
                        conn.recv(1); conn.sendall(b'PKI lab OK')
                except (ssl.SSLError, OSError): pass
        finally: listener.close()
    thread = threading.Thread(target=serve, daemon=True); thread.start()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=str(folder/trust))
    if check_crl: ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as conn:
                conn.sendall(b'?'); data=conn.recv(100).decode()
                result={'accepted':True, 'protocol':conn.version(), 'cipher':conn.cipher()[0], 'detail':data}
    except ssl.SSLCertVerificationError as e:
        result={'accepted':False, 'verify_code':e.verify_code, 'detail':e.verify_message}
    finally: thread.join(timeout=9)
    return result

def run_lab():
    folder=BASE/'runs'/uuid.uuid4().hex[:12]; folder.mkdir(parents=True)
    root_k=key(); root=cert('Lab Root CA',root_k,ca=True,path=1)
    inter_k=key(); inter=cert('Lab Intermediate CA',inter_k,root,root_k,True,0)
    leaf_k=key(); forged=cert(HOST,leaf_k,inter,inter_k)
    fresh_k=key(); fresh=cert('Replacement Intermediate CA',fresh_k,root,root_k,True,0)
    recovered_k=key(); recovered=cert(HOST,recovered_k,fresh,fresh_k)
    unrelated_k=key(); unrelated=cert('Untrusted Root CA',unrelated_k,ca=True,path=1)
    for filename, obj in {'root.crt':root,'intermediate.crt':inter,'impostor.crt':forged,
        'replacement-intermediate.crt':fresh,'recovered.crt':recovered,'unrelated-root.crt':unrelated}.items():
        (folder/filename).write_bytes(pem(obj))
    # The only exposed signing material belongs to the compromised intermediate.
    for filename,obj in {'leaked-intermediate.key':inter_k,'impostor.key':leaf_k,'recovered.key':recovered_k}.items():
        (folder/filename).write_bytes(obj.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    (folder/'forged-chain.pem').write_bytes(pem(forged)+pem(inter))
    (folder/'recovered-chain.pem').write_bytes(pem(recovered)+pem(fresh))
    root_crl=crl(root,root_k,inter); inter_crl=crl(inter,inter_k); fresh_crl=crl(fresh,fresh_k)
    (folder/'root.crl.pem').write_bytes(pem(root_crl))
    (folder/'revocation-trust.pem').write_bytes(pem(root)+pem(root_crl)+pem(inter_crl))
    (folder/'recovery-trust.pem').write_bytes(pem(root)+pem(root_crl)+pem(fresh_crl))
    specs=[
      ('untrusted','Root CA chưa được tin cậy','unrelated-root.crt',HOST,False,False,'Client chỉ tin CA trong kho riêng của lab.'),
      ('forged','Chứng chỉ giả vượt xác minh','root.crt',HOST,False,True,'Khóa CA trung gian bị lộ ký được leaf có SAN và chuỗi hợp lệ.'),
      ('hostname','Tên miền sai bị từ chối','root.crt','other.payroll.test',False,False,'Chữ ký hợp lệ vẫn không thay thế kiểm tra hostname.'),
      ('revoked','Bật kiểm tra CRL và thu hồi CA','revocation-trust.pem',HOST,True,False,'Root CA ký CRL thu hồi Intermediate với lý do cACompromise.'),
      ('unchecked','Tắt kiểm tra thu hồi','revocation-trust.pem',HOST,False,True,'Có CRL trong trust bundle chưa đủ. Client phải thực thi kiểm tra.'),
      ('recovery','Thay CA trung gian và cấp lại','recovery-trust.pem',HOST,True,True,'Chuỗi mới hợp lệ, CA cũ vẫn nằm trong CRL của Root.')]
    results=[]
    for ident,title,trust,hostname,check,expected,explain in specs:
        recovery=ident=='recovery'
        r=handshake(folder,'recovered-chain.pem' if recovery else 'forged-chain.pem',
            'recovered.key' if recovery else 'impostor.key',trust,hostname,check)
        r.update(id=ident,title=title,expected=expected,passed=r['accepted']==expected,explain=explain,crl_enabled=check)
        results.append(r)
    output={'hostname':HOST,'scope':'127.0.0.1, TLS 1.3, kho tin cậy riêng',
        'issuer':inter.subject.rfc4514_string(),'serial':hex(forged.serial_number),
        'fingerprint':forged.fingerprint(hashes.SHA256()).hex(), 'folder':str(folder),
        'results':results,'all_passed':all(r['passed'] for r in results),'openssl':ssl.OPENSSL_VERSION,
        'created_at':dt.datetime.now(dt.timezone.utc).isoformat()}
    (folder/'results.json').write_text(json.dumps(output,ensure_ascii=False,indent=2),encoding='utf8')
    (BASE/'latest-results.json').write_text(json.dumps(output,ensure_ascii=False,indent=2),encoding='utf8')
    return output

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ['/', '/index.html']:
            self.send_error(404); return
        data=(BASE/'demo.html').read_bytes(); self.send_response(200)
        self.send_header('Content-Type','text/html; charset=utf-8');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
    def do_POST(self):
        if self.path!='/api/run':self.send_error(404);return
        if self.headers.get('Origin') not in [None, f'http://127.0.0.1:{self.server.server_port}', f'http://localhost:{self.server.server_port}']:
            self.send_error(403);return
        try: data=json.dumps(run_lab(),ensure_ascii=False).encode(); status=200
        except Exception as e: data=json.dumps({'error':str(e)}).encode();status=500
        self.send_response(status);self.send_header('Content-Type','application/json; charset=utf-8');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--self-test',action='store_true');parser.add_argument('--port',type=int,default=8765);args=parser.parse_args()
    if args.self_test:
        result=run_lab();print(json.dumps(result,ensure_ascii=True,indent=2));raise SystemExit(0 if result['all_passed'] else 1)
    print(f'PKI lab: http://127.0.0.1:{args.port}',flush=True)
    http.server.ThreadingHTTPServer(('127.0.0.1',args.port),Handler).serve_forever()
