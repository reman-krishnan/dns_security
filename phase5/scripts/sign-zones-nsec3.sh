#!/bin/bash
# Phase 5 — the fix: re-sign example.com with NSEC3 instead of NSEC.
#
# NSEC (what sign-zones.sh produces) chains the EXISTING owner names in
# canonical order in cleartext, so a signed denial of existence for one name
# hands the attacker the NEXT real name — the zone can be walked end to end.
# NSEC3 replaces those names with salted SHA-1 HASHES of the names, so a denial
# no longer reveals a plaintext neighbour and the online walk recovers nothing
# (an enumerator is left with only hashes to attack offline, plus the zone size).
#
# Only example.com (the walk target) is re-signed; its keys are reused, so the
# DNSKEY/DS chain from com is unchanged. Run on the HOST AFTER sign-zones.sh and
# AFTER the hierarchy is up:
#   sudo docker run --rm -v "$PWD:/lab" --entrypoint /bin/bash \
#        cs6008-dns-lab:local /lab/scripts/sign-zones-nsec3.sh
#   sudo docker compose restart domain-ns
#   sudo docker compose exec -T resolver rndc -k /run/named/rndc.key -s 127.0.0.1 flush
set -euo pipefail

WORKDIR="/lab"
KEYDIR="$WORKDIR/keys"
ZONEDIR="$WORKDIR/zones"

if [ ! -d "$KEYDIR" ] || [ -z "$(ls -A "$KEYDIR" 2>/dev/null)" ]; then
    echo "ERROR: run scripts/sign-zones.sh first (keys missing)." >&2
    exit 1
fi

# A random salt; iterations kept low (NSEC3 best practice is few/zero iterations).
SALT=$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')

# Rebuild example.com's unsigned input with its existing keys.
cp "$ZONEDIR/db.example.com" "$ZONEDIR/db.example.com.unsigned"
for k in "$KEYDIR"/Kexample.com.+*.key; do
    cat "$k" >> "$ZONEDIR/db.example.com.unsigned"
done

# -3 <salt> selects NSEC3; -H 10 sets hash iterations; -N increment bumps SOA.
dnssec-signzone -S -3 "$SALT" -H 10 -N increment -K "$KEYDIR" -o example.com \
    -f "$ZONEDIR/db.example.com.signed" "$ZONEDIR/db.example.com.unsigned"

echo "example.com re-signed with NSEC3 (salt=$SALT). DNSKEY/DS unchanged."
echo "Now: docker compose restart domain-ns && flush the resolver."
