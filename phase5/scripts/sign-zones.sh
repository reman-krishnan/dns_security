#!/bin/bash
# Phase 4 — Run A signing (identical chain of trust to Phase 3).
# Generates fresh keys for ., com and example.com; signs every zone; publishes
# com's DS in the root and example.com's DS in com, giving an unbroken chain
# from the root KSK down to example.com. Also writes the resolver's trust
# anchor (the root KSK) into configs/trust-anchors.conf.
#
# Run on the HOST before `docker compose up`, exactly as in Phase 3:
#   sudo docker run --rm -v "$PWD:/lab" --entrypoint /bin/bash \
#        cs6008-dns-lab:local /lab/scripts/sign-zones.sh
set -euo pipefail

WORKDIR="/lab"
KEYDIR="$WORKDIR/keys"
ZONEDIR="$WORKDIR/zones"
CONFIGDIR="$WORKDIR/configs"

rm -rf "$KEYDIR"/*
mkdir -p "$KEYDIR"
cd "$KEYDIR"

echo "=== 1. Keys for example.com ==="
EX_ZSK=$(dnssec-keygen -a ECDSAP256SHA256 -n ZONE example.com)
EX_KSK=$(dnssec-keygen -a ECDSAP256SHA256 -f KSK -n ZONE example.com)

echo "=== 2. Keys for com ==="
COM_ZSK=$(dnssec-keygen -a ECDSAP256SHA256 -n ZONE com)
COM_KSK=$(dnssec-keygen -a ECDSAP256SHA256 -f KSK -n ZONE com)

echo "=== 3. Keys for root (.) ==="
ROOT_ZSK=$(dnssec-keygen -a ECDSAP256SHA256 -n ZONE .)
ROOT_KSK=$(dnssec-keygen -a ECDSAP256SHA256 -f KSK -n ZONE .)

echo "=== 4. Sign example.com ==="
cp "$ZONEDIR/db.example.com" "$ZONEDIR/db.example.com.unsigned"
cat "$KEYDIR/$EX_ZSK.key" "$KEYDIR/$EX_KSK.key" >> "$ZONEDIR/db.example.com.unsigned"
dnssec-signzone -S -K "$KEYDIR" -o example.com -f "$ZONEDIR/db.example.com.signed" "$ZONEDIR/db.example.com.unsigned"
dnssec-dsfromkey -2 "$KEYDIR/$EX_KSK.key" > "$KEYDIR/dsset-example.com"

echo "=== 5. Publish example.com DS into com and sign com ==="
cp "$ZONEDIR/db.com" "$ZONEDIR/db.com.unsigned"
cat "$KEYDIR/dsset-example.com" >> "$ZONEDIR/db.com.unsigned"
cat "$KEYDIR/$COM_ZSK.key" "$KEYDIR/$COM_KSK.key" >> "$ZONEDIR/db.com.unsigned"
dnssec-signzone -S -K "$KEYDIR" -o com -f "$ZONEDIR/db.com.signed" "$ZONEDIR/db.com.unsigned"
dnssec-dsfromkey -2 "$KEYDIR/$COM_KSK.key" > "$KEYDIR/dsset-com"

echo "=== 6. Publish com DS into root and sign root (.) ==="
cp "$ZONEDIR/db.root" "$ZONEDIR/db.root.unsigned"
cat "$KEYDIR/dsset-com" >> "$ZONEDIR/db.root.unsigned"
cat "$KEYDIR/$ROOT_ZSK.key" "$KEYDIR/$ROOT_KSK.key" >> "$ZONEDIR/db.root.unsigned"
dnssec-signzone -S -K "$KEYDIR" -o . -f "$ZONEDIR/db.root.signed" "$ZONEDIR/db.root.unsigned"

echo "=== 7. Resolver trust anchor (root KSK) ==="
# Take the single DNSKEY line from the KSK .key file (ignore ; comments).
KEY_LINE=$(grep -v '^;' "$KEYDIR/$ROOT_KSK.key" | grep 'DNSKEY' | head -1)

# Fields after "DNSKEY": <flags> <proto> <alg> <key...>. For ECDSA the base64
# key is often split across several whitespace-separated chunks, so the public
# key is EVERY field from (DNSKEY+4) to end of line, concatenated with no space.
FLAGS=$(echo "$KEY_LINE" | awk '{for(i=1;i<=NF;i++) if($i=="DNSKEY"){print $(i+1); exit}}')
PROTO=$(echo "$KEY_LINE" | awk '{for(i=1;i<=NF;i++) if($i=="DNSKEY"){print $(i+2); exit}}')
ALG=$(echo   "$KEY_LINE" | awk '{for(i=1;i<=NF;i++) if($i=="DNSKEY"){print $(i+3); exit}}')
PUBKEY=$(echo "$KEY_LINE" | awk '{for(i=1;i<=NF;i++) if($i=="DNSKEY"){s=""; for(j=i+4;j<=NF;j++) s=s $j; print s; exit}}')

cat > "$CONFIGDIR/trust-anchors.conf" <<TA_EOF
trust-anchors {
    . static-key $FLAGS $PROTO $ALG "$PUBKEY";
};
TA_EOF

echo "Run A chain signed. Trust anchor -> $CONFIGDIR/trust-anchors.conf"
