#!/bin/sh
# Permissive last-mile client: try DoT; on ANY failure fall back to cleartext.
set -u
echo "[permissive] trying DoT @resolver.cs6008.local..."
OUT=$(kdig +tls +tls-ca=/lab/pki/ca.crt +tls-hostname=resolver.cs6008.local \
          @resolver.cs6008.local example.com A +timeout=5 +retry=1 2>&1)
rc=$?
echo "$OUT"
if [ $rc -eq 0 ] && printf '%s' "$OUT" | grep -qE 'IN[[:space:]]+A[[:space:]]'; then
    echo "[permissive] DoT OK (encrypted)."; exit 0
fi
echo "[permissive] DoT failed -> FALLING BACK TO CLEARTEXT (insecure)."
dig +noall +answer @172.16.2.10 example.com A
