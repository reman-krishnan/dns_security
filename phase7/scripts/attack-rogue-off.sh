#!/bin/sh
set -eu
iptables -t nat -D PREROUTING -p tcp -d 172.16.2.10 --dport 853 -j REDIRECT --to-ports 8853 2>/dev/null || true
[ -f /tmp/rogue.pid ] && kill "$(cat /tmp/rogue.pid)" 2>/dev/null || true
pkill -f 's_server.*8853' 2>/dev/null || true
echo "[edge-router] rogue responder removed."
