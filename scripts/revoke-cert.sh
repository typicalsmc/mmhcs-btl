#!/usr/bin/env bash
set -euo pipefail
umask 077

for required in \
    /ca-private/root.cnf \
    /ca-private/root.key \
    /ca-private/root.crt \
    /ca-private/index.txt \
    /ca-private/serial \
    /ca-private/crlnumber \
    /public/intermediate.crt \
    /public/root.crl.pem \
    /public/intermediate.crl.pem; do
    if [[ ! -f "$required" ]]; then
        printf 'Required initialized CA file is missing: %s\n' "$required" >&2
        exit 1
    fi
done
if [[ ! -d /ca-private/newcerts ]]; then
    printf 'Required initialized CA directory is missing: /ca-private/newcerts\n' >&2
    exit 1
fi

trap 'rm -f -- /public/root.crl.pem.tmp' EXIT
openssl ca -batch -config /ca-private/root.cnf -revoke /public/intermediate.crt -crl_reason CACompromise
openssl ca -batch -config /ca-private/root.cnf -gencrl -out /public/root.crl.pem.tmp
chmod 644 /public/root.crl.pem.tmp
mv -f -- /public/root.crl.pem.tmp /public/root.crl.pem
python /lab/pki.py publish-trust

printf 'Revoked compromised intermediate certificate:\n'
openssl x509 -in /public/intermediate.crt -noout -serial
printf '\nPublished root CRL (public data only):\n'
openssl crl -in /public/root.crl.pem -noout -text
