#!/bin/sh
set -eu
DEV=$(ip -o -4 addr show | awk '$4 ~ /^172\.16\.2\./{print $2; exit}')
test -n "$DEV"
echo "[CORE-ROUTER] Removing diversion route, restoring direct delivery..."
ip route del 172.16.2.10 via 172.16.2.100 dev "$DEV" 2>/dev/null || true
ip route show
