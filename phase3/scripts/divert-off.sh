#!/bin/sh
set -eu
echo "[CORE-ROUTER] Removing diversion route, restoring direct delivery..."
ip route del 172.16.2.10 via 172.16.2.100 dev eth1 2>/dev/null || true
ip route show
