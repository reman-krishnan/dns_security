#!/bin/bash
# Phase 4 — Run B re-signing: the single deployment change.
#
# This re-signs ONLY the com zone, reusing the keys that sign-zones.sh already
# generated, but WITHOUT publishing example.com's DS. example.com itself stays
# fully signed and the root is untouched, so the root->com link is unchanged
# and the resolver's trust anchor still validates. The only difference is that
# com now carries NO secure delegation to example.com: its signed NSEC chain
# authenticatedly proves "example.com has no DS", so a root-anchored validating
# resolver treats example.com as an INSECURE delegation and stops validating
# its answers — which is exactly what reopens the forgery.
#
# Run on the HOST, AFTER sign-zones.sh and AFTER the hierarchy is already up:
#   sudo docker run --rm -v "$PWD:/lab" --entrypoint /bin/bash \
#        cs6008-dns-lab:local /lab/scripts/sign-zones-runB.sh
#   sudo docker compose restart tld-ns
#   sudo docker compose exec -T resolver rndc -k /run/named/rndc.key -s 127.0.0.1 flush
set -euo pipefail

WORKDIR="/lab"
KEYDIR="$WORKDIR/keys"
ZONEDIR="$WORKDIR/zones"

if [ ! -d "$KEYDIR" ] || [ -z "$(ls -A "$KEYDIR" 2>/dev/null)" ]; then
    echo "ERROR: run scripts/sign-zones.sh first (keys missing)." >&2
    exit 1
fi

# Rebuild com's unsigned input with its keys but WITHOUT dsset-example.com.
cp "$ZONEDIR/db.com" "$ZONEDIR/db.com.unsigned"
for k in "$KEYDIR"/Kcom.+*.key; do
    cat "$k" >> "$ZONEDIR/db.com.unsigned"
done

# Re-sign com, bumping the SOA serial so the reload is unambiguous.
dnssec-signzone -S -N increment -K "$KEYDIR" -o com \
    -f "$ZONEDIR/db.com.signed" "$ZONEDIR/db.com.unsigned"

echo "Run B: com re-signed WITHOUT example.com DS."
echo "example.com.signed and db.root.signed are unchanged; trust anchor unchanged."
echo "Now: docker compose restart tld-ns && flush the resolver cache."
