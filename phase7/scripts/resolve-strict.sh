#!/bin/sh
# Strict last-mile client: DoT only, validate the resolver cert against the lab
# CA and the hostname, and REFUSE any cleartext fallback.
set -u
echo "[strict] DoT @resolver.cs6008.local (validating cert against lab CA)..."
kdig +tls +tls-ca=/lab/pki/ca.crt +tls-hostname=resolver.cs6008.local \
     @resolver.cs6008.local example.com A +timeout=5 +retry=1
rc=$?

if [ $rc -ne 0 ]; then
    echo "[strict] DoT failed (rc=$rc) -> refusing cleartext; NO answer."

    # --- Diagnostic only: identify WHY the TLS session failed ----------------
    # Does not change the result/exit code above or retry the real DNS query;
    # a separate, low-level TLS probe (openssl s_client) against the same
    # endpoint, so the evidence distinguishes the three attack causes that all
    # surface identically to kdig as "DoT failed":
    #   - certificate/hostname rejected  -> handshake COMPLETES, then
    #     "Verification error: ..." (attempt ii, rogue cert)
    #   - stream corrupted / torn down   -> handshake starts but never reaches
    #     "CONNECTION ESTABLISHED" / "Verification: ..." (attempt i, break-dot)
    #   - no TLS session reachable at all -> a connect()-level error from
    #     openssl itself (attempt iii, transport blocked)
    probe="/tmp/strict-tls-probe.$$"
    echo "[strict] TLS diagnostic probe (openssl s_client) ..."
    printf '' | timeout 6 openssl s_client \
        -connect resolver.cs6008.local:853 \
        -CAfile /lab/pki/ca.crt \
        -brief > "$probe" 2>&1

    if grep -q "Verification: OK" "$probe"; then
        echo "[strict] TLS probe: certificate verification SUCCEEDED (unexpected for an attack run)"
    elif grep -q "Verification error:" "$probe"; then
        reason=$(grep "Verification error:" "$probe")
        echo "[strict] TLS probe: CERTIFICATE REJECTED -- $reason"
    elif grep -q "CONNECTION ESTABLISHED" "$probe"; then
        echo "[strict] TLS probe: TLS session started but never completed cleanly -- likely torn down by stream corruption"
    else
        echo "[strict] TLS probe: NO TLS SESSION ESTABLISHED -- transport unreachable, not a certificate issue"
    fi
    echo "[strict] --- raw openssl s_client output ---"
    cat "$probe"
    echo "[strict] --- end probe output ---"
    rm -f "$probe"
fi

exit $rc
