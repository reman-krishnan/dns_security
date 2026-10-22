#!/bin/sh
# Attack (iii): deny the encrypted transport (block TCP 853/443 to the resolver).
set -eu
echo "[edge-router] blocking DoT/DoH (TCP 853,443 -> 172.16.2.10)..."
iptables -I FORWARD -p tcp -d 172.16.2.10 -m multiport --dports 853,443 -j REJECT --reject-with tcp-reset
iptables -S FORWARD | grep -E '853|443' || true
