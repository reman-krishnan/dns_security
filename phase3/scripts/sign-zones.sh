#!/bin/bash
set -euo pipefail

WORKDIR="/lab"
KEYDIR="$WORKDIR/keys"
ZONEDIR="$WORKDIR/zones"
CONFIGDIR="$WORKDIR/configs"

rm -rf "$KEYDIR"/*
mkdir -p "$KEYDIR"
cd "$KEYDIR"

echo "=== 1. Generating Keys for example.com ==="
EX_ZSK=$(dnssec-keygen -a ECDSAP256SHA256 -n ZONE example.com)
EX_KSK=$(dnssec-keygen -a ECDSAP256SHA256 -f KSK -n ZONE example.com)

echo "=== 2. Generating Keys for com ==="
COM_ZSK=$(dnssec-keygen -a ECDSAP256SHA256 -n ZONE com)
COM_KSK=$(dnssec-keygen -a ECDSAP256SHA256 -f KSK -n ZONE com)

echo "=== 3. Generating Keys for root (.) ==="
ROOT_ZSK=$(dnssec-keygen -a ECDSAP256SHA256 -n ZONE .)
ROOT_KSK=$(dnssec-keygen -a ECDSAP256SHA256 -f KSK -n ZONE .)

echo "=== 4. Signing example.com ==="
cp "$ZONEDIR/db.example.com" "$ZONEDIR/db.example.com.unsigned"
cat "$KEYDIR/$EX_ZSK.key" "$KEYDIR/$EX_KSK.key" >> "$ZONEDIR/db.example.com.unsigned"
dnssec-signzone -S -K "$KEYDIR" -o example.com -f "$ZONEDIR/db.example.com.signed" "$ZONEDIR/db.example.com.unsigned"
dnssec-dsfromkey -2 "$KEYDIR/$EX_KSK.key" > "$KEYDIR/dsset-example.com"

echo "=== 5. Publishing example.com DS into com and signing com ==="
cp "$ZONEDIR/db.com" "$ZONEDIR/db.com.unsigned"
cat "$KEYDIR/dsset-example.com" >> "$ZONEDIR/db.com.unsigned"
cat "$KEYDIR/$COM_ZSK.key" "$KEYDIR/$COM_KSK.key" >> "$ZONEDIR/db.com.unsigned"
dnssec-signzone -S -K "$KEYDIR" -o com -f "$ZONEDIR/db.com.signed" "$ZONEDIR/db.com.unsigned"
dnssec-dsfromkey -2 "$KEYDIR/$COM_KSK.key" > "$KEYDIR/dsset-com"

echo "=== 6. Publishing com DS into root and signing root (.) ==="
cp "$ZONEDIR/db.root" "$ZONEDIR/db.root.unsigned"
cat "$KEYDIR/dsset-com" >> "$ZONEDIR/db.root.unsigned"
cat "$KEYDIR/$ROOT_ZSK.key" "$KEYDIR/$ROOT_KSK.key" >> "$ZONEDIR/db.root.unsigned"
dnssec-signzone -S -K "$KEYDIR" -o . -f "$ZONEDIR/db.root.signed" "$ZONEDIR/db.root.unsigned"

echo "=== 7. Creating Resolver Trust Anchor and delv anchor file ==="
# Find the line containing DNSKEY in the ROOT_KSK key file, ignoring comments
# Line format: . IN DNSKEY 257 3 13 <pubkey>
KEY_LINE=$(grep -E '^[.]?[[:space:]]+IN[[:space:]]+DNSKEY' "$KEYDIR/$ROOT_KSK.key" || grep -E '^[.]?[[:space:]]+DNSKEY' "$KEYDIR/$ROOT_KSK.key" || grep -v '^;' "$KEYDIR/$ROOT_KSK.key" | grep 'DNSKEY')

FLAGS=$(echo "$KEY_LINE" | awk '{for(i=1;i<=NF;i++) if($i=="DNSKEY") print $(i+1)}')
PROTO=$(echo "$KEY_LINE" | awk '{for(i=1;i<=NF;i++) if($i=="DNSKEY") print $(i+2)}')
ALG=$(echo "$KEY_LINE" | awk '{for(i=1;i<=NF;i++) if($i=="DNSKEY") print $(i+3)}')
PUBKEY=$(echo "$KEY_LINE" | awk '{for(i=1;i<=NF;i++) if($i=="DNSKEY"){s=""; for(j=i+4;j<=NF;j++) s=s $j; print s; exit}}')

echo "Extracted Root Key: Flags=$FLAGS Proto=$PROTO Alg=$ALG PubKey=$PUBKEY"

cat > "$CONFIGDIR/trust-anchors.conf" <<TA_EOF
trust-anchors {
    . static-key $FLAGS $PROTO $ALG "$PUBKEY";
};
TA_EOF

echo "Done! Formatted trust anchor written to $CONFIGDIR/trust-anchors.conf"
