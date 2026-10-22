#!/bin/sh
# Strict last-mile client: DoT only, validate the resolver cert against the lab
# CA and the hostname, and REFUSE any cleartext fallback.
set -u
echo "[strict] DoT @resolver.cs6008.local (validating cert against lab CA)..."
kdig +tls +tls-ca=/lab/pki/ca.crt +tls-hostname=resolver.cs6008.local \
     @resolver.cs6008.local example.com A +timeout=5 +retry=1
rc=$?
[ $rc -ne 0 ] && echo "[strict] DoT failed (rc=$rc) -> refusing cleartext; NO answer."
exit $rc
