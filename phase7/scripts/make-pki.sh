#!/bin/bash
# Phase 7 — private PKI for the encrypted last mile.
#
# Produces, under /lab/pki:
#   ca.crt / ca.key                 the lab's private CA (installed in the client)
#   resolver.crt / resolver.key     the resolver's cert, SAN = resolver.cs6008.local
#                                   (NO IP SAN — the client must connect by name)
#   resolver.fullchain.crt          resolver.crt + ca.crt (served by BIND)
#   rogue.crt / rogue.key           an attacker cert for resolver.cs6008.local
#                                   signed by a DIFFERENT, untrusted CA (Attack ii)
#
# Run on the HOST before `docker compose up`:
#   sudo docker run --rm -v "$PWD:/lab" --entrypoint /bin/bash \
#        cs6008-dns-lab:local /lab/scripts/make-pki.sh
set -euo pipefail

PKI="/lab/pki"
NAME="resolver.cs6008.local"
rm -rf "$PKI"; mkdir -p "$PKI"; cd "$PKI"

echo "=== 1. Lab CA ==="
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 365 \
    -subj "/O=CS6008 Lab/CN=CS6008 Lab Root CA" -out ca.crt

echo "=== 2. Resolver key + CSR (SAN = $NAME, no IP SAN) ==="
openssl ecparam -name prime256v1 -genkey -noout -out resolver.key
openssl req -new -key resolver.key -subj "/O=CS6008 Lab/CN=$NAME" -out resolver.csr

cat > resolver.ext <<EXT
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:$NAME
EXT

openssl x509 -req -in resolver.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -sha256 -days 365 -extfile resolver.ext -out resolver.crt
cat resolver.crt ca.crt > resolver.fullchain.crt

echo "=== 3. Rogue CA + rogue resolver cert (same name, untrusted issuer) ==="
openssl ecparam -name prime256v1 -genkey -noout -out rogue-ca.key
openssl req -x509 -new -key rogue-ca.key -sha256 -days 365 \
    -subj "/O=Evil Corp/CN=Evil Root CA" -out rogue-ca.crt
openssl ecparam -name prime256v1 -genkey -noout -out rogue.key
openssl req -new -key rogue.key -subj "/O=Evil Corp/CN=$NAME" -out rogue.csr
openssl x509 -req -in rogue.csr -CA rogue-ca.crt -CAkey rogue-ca.key -CAcreateserial \
    -sha256 -days 365 -extfile resolver.ext -out rogue.crt
cat rogue.crt rogue-ca.crt > rogue.fullchain.crt

chmod 644 *.crt *.key
rm -f *.csr
echo "PKI written to $PKI:"
ls -1 "$PKI"
echo "--- resolver.crt SAN ---"
openssl x509 -in resolver.crt -noout -text | grep -A1 "Subject Alternative Name"
