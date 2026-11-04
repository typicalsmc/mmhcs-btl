"""Offline certificate authority for the isolated, disposable Docker lab."""
from __future__ import annotations

import argparse
import datetime as dt
import os
from pathlib import Path
import subprocess
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HOST = "login.payroll.test"
CA_PRIVATE = Path("/ca-private")
PUBLIC = Path("/public")
LEGITIMATE = Path("/legitimate")
LEAK = Path("/leak")


def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def cert(cn, subject_key, issuer_cert=None, issuer_key=None, ca=False, path=None):
    now = dt.datetime.now(dt.timezone.utc)
    subject = name(cn)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject if issuer_cert else subject)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=path), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=not ca,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=ca,
                crl_sign=ca,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), False)
    )
    signing_key = issuer_key or subject_key
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()), False
    )
    if not ca:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), False)
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
    return builder.sign(signing_key, hashes.SHA256())


def pem(obj):
    return obj.public_bytes(serialization.Encoding.PEM)


def crl(issuer, signing_key, revoked=None):
    now = dt.datetime.now(dt.timezone.utc)
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer.subject)
        .last_update(now - dt.timedelta(minutes=1))
        .next_update(now + dt.timedelta(days=1))
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()), False
        )
    )
    if revoked:
        entry = (
            x509.RevokedCertificateBuilder()
            .serial_number(revoked.serial_number)
            .revocation_date(now - dt.timedelta(seconds=30))
            .add_extension(x509.CRLReason(x509.ReasonFlags.ca_compromise), False)
            .build()
        )
        builder = builder.add_revoked_certificate(entry)
    return builder.sign(signing_key, hashes.SHA256())


def write_atomic(path, data, *, private=False):
    """Publish complete files; keep private material owner-readable only."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=f".{path.name}.", delete=False) as out:
            temporary = Path(out.name)
            out.write(data)
            out.flush()
            os.fchmod(out.fileno(), 0o600 if private else 0o644)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def save_key(path, signing_key):
    write_atomic(
        path,
        signing_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        private=True,
    )


def require_files(*paths):
    for path in paths:
        if not path.is_file():
            raise RuntimeError(f"Required initialized lab file is missing: {path}")


def load_certificate(path):
    require_files(path)
    return x509.load_pem_x509_certificate(path.read_bytes())


def load_key(path):
    require_files(path)
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def publish_trust():
    required = (
        PUBLIC / "root.crt",
        PUBLIC / "root.crl.pem",
        PUBLIC / "intermediate.crt",
        PUBLIC / "intermediate.crl.pem",
    )
    require_files(*required)
    paths = [PUBLIC / "root.crt", PUBLIC / "root.crl.pem", PUBLIC / "intermediate.crl.pem"]
    replacement_cert = PUBLIC / "replacement-intermediate.crt"
    replacement_crl = PUBLIC / "replacement-intermediate.crl.pem"
    if replacement_cert.exists() or replacement_crl.exists():
        require_files(replacement_cert, replacement_crl)
        paths.append(replacement_crl)
    write_atomic(PUBLIC / "trust.pem", b"".join(path.read_bytes() for path in paths))


def init():
    for directory in (CA_PRIVATE, PUBLIC, LEGITIMATE, LEAK):
        if not directory.is_dir():
            raise RuntimeError(f"Required bind-mounted directory is missing: {directory}")
    if any(CA_PRIVATE.iterdir()):
        raise RuntimeError("CA directory is not empty; refusing to initialize or mix an existing run")
    if any(any(directory.iterdir()) for directory in (PUBLIC, LEGITIMATE, LEAK)):
        raise RuntimeError("Public, legitimate, and leak directories must be empty for initialization")
    CA_PRIVATE.chmod(0o700)

    root_key = key()
    root = cert("Lab Root CA", root_key, ca=True, path=1)
    intermediate_key = key()
    intermediate = cert("Lab Intermediate CA", intermediate_key, root, root_key, True, 0)
    leaf_key = key()
    leaf = cert(HOST, leaf_key, intermediate, intermediate_key)
    unrelated_key = key()
    unrelated_root = cert("Untrusted Root CA", unrelated_key, ca=True, path=1)

    save_key(CA_PRIVATE / "root.key", root_key)
    save_key(CA_PRIVATE / "intermediate.key", intermediate_key)
    write_atomic(CA_PRIVATE / "root.crt", pem(root))
    write_atomic(CA_PRIVATE / "intermediate.crt", pem(intermediate))
    save_key(LEGITIMATE / "server.key", leaf_key)
    write_atomic(LEGITIMATE / "chain.pem", pem(leaf) + pem(intermediate))
    write_atomic(LEAK / "intermediate.crt", pem(intermediate))
    save_key(LEAK / "leaked-intermediate.key", intermediate_key)
    for filename, certificate in (
        ("root.crt", root),
        ("intermediate.crt", intermediate),
        ("unrelated-root.crt", unrelated_root),
    ):
        write_atomic(PUBLIC / filename, pem(certificate))
    write_atomic(PUBLIC / "root.crl.pem", pem(crl(root, root_key)))
    write_atomic(PUBLIC / "intermediate.crl.pem", pem(crl(intermediate, intermediate_key)))

    (CA_PRIVATE / "newcerts").mkdir(mode=0o700)
    write_atomic(CA_PRIVATE / "index.txt", b"", private=True)
    write_atomic(CA_PRIVATE / "serial", b"1000\n", private=True)
    write_atomic(CA_PRIVATE / "crlnumber", b"1000\n", private=True)
    write_atomic(CA_PRIVATE / "root.cnf", ROOT_CONFIG.encode("ascii"), private=True)
    subprocess.run(
        ["openssl", "ca", "-config", str(CA_PRIVATE / "root.cnf"), "-valid", str(PUBLIC / "intermediate.crt")],
        check=True,
        timeout=30,
    )
    publish_trust()


def recover():
    replacement_paths = (
        CA_PRIVATE / "replacement-intermediate.key",
        CA_PRIVATE / "replacement-intermediate.crt",
        PUBLIC / "replacement-intermediate.crt",
        PUBLIC / "replacement-intermediate.crl.pem",
    )
    if any(path.exists() for path in replacement_paths):
        raise RuntimeError("Recovery has already been created or partially written; refusing duplicate recovery")
    root = load_certificate(CA_PRIVATE / "root.crt")
    old_intermediate = load_certificate(CA_PRIVATE / "intermediate.crt")
    require_files(CA_PRIVATE / "root.cnf", CA_PRIVATE / "index.txt", PUBLIC / "root.crl.pem")
    root_crl = x509.load_pem_x509_crl((PUBLIC / "root.crl.pem").read_bytes())
    if root_crl.issuer != root.subject or not root_crl.is_signature_valid(root.public_key()):
        raise RuntimeError("Root CRL is not signed by this run's root CA")
    if root_crl.get_revoked_certificate_by_serial_number(old_intermediate.serial_number) is None:
        raise RuntimeError("Revoke the compromised intermediate before recovery")
    root_key = load_key(CA_PRIVATE / "root.key")
    replacement_key = key()
    replacement = cert("Replacement Intermediate CA", replacement_key, root, root_key, True, 0)
    leaf_key = key()
    leaf = cert(HOST, leaf_key, replacement, replacement_key)

    save_key(CA_PRIVATE / "replacement-intermediate.key", replacement_key)
    write_atomic(CA_PRIVATE / "replacement-intermediate.crt", pem(replacement))
    write_atomic(PUBLIC / "replacement-intermediate.crt", pem(replacement))
    write_atomic(PUBLIC / "replacement-intermediate.crl.pem", pem(crl(replacement, replacement_key)))
    save_key(LEGITIMATE / "server.key", leaf_key)
    write_atomic(LEGITIMATE / "chain.pem", pem(leaf) + pem(replacement))
    # The existing root CRL is deliberately retained, including the old issuer's revocation.
    publish_trust()


ROOT_CONFIG = """[ ca ]
default_ca = root_ca

[ root_ca ]
dir = /ca-private
database = $dir/index.txt
new_certs_dir = $dir/newcerts
certificate = $dir/root.crt
private_key = $dir/root.key
serial = $dir/serial
crlnumber = $dir/crlnumber
default_md = sha256
default_days = 30
default_crl_days = 1
policy = policy_subject
unique_subject = no
crl_extensions = crl_ext

[ policy_subject ]
commonName = supplied

[ crl_ext ]
authorityKeyIdentifier = keyid:always
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("init", "recover", "publish-trust"))
    args = parser.parse_args()
    os.umask(0o077)
    try:
        {"init": init, "recover": recover, "publish-trust": publish_trust}[args.command]()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"PKI {args.command} failed: {error}\n")


if __name__ == "__main__":
    main()
