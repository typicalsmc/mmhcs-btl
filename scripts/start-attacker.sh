#!/usr/bin/env bash
set -euo pipefail
umask 077
for file in /leak/intermediate.crt /leak/leaked-intermediate.key; do
    [[ -s "$file" ]] || { echo "Missing required leaked CA material: $file" >&2; exit 1; }
done
if [[ -e /certs/server.key || -e /certs/chain.pem ]]; then
    [[ -s /certs/server.key && -s /certs/chain.pem ]] || {
        echo "Incomplete attacker key/chain pair; refusing identity rotation" >&2; exit 1;
    }
else
    openssl req -new -newkey rsa:2048 -nodes -subj /CN=login.payroll.test \
        -keyout /certs/server.key -out /certs/server.csr
    cat > /certs/leaf.cnf <<'EXT'
subjectAltName=DNS:login.payroll.test
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EXT
    serial="$(openssl rand -hex 16)"
    [[ "$serial" != 00000000000000000000000000000000 ]] || { echo 'Zero serial' >&2; exit 1; }
    openssl x509 -req -in /certs/server.csr -CA /leak/intermediate.crt \
        -CAkey /leak/leaked-intermediate.key -set_serial "0x$serial" -days 30 -sha256 \
        -extfile /certs/leaf.cnf -out /certs/server.crt
    cat /certs/server.crt /leak/intermediate.crt > /certs/chain.pem
fi
exec /docker-entrypoint.sh nginx -g 'daemon off;'
