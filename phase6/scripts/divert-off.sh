#!/bin/sh
# edge-router: remove the last-mile diversion.
set -eu
echo "[EDGE-ROUTER] Removing diversion, restoring direct delivery..."
ip route del 172.16.1.10 via 172.16.1.100 2>/dev/null || true
ip route show
