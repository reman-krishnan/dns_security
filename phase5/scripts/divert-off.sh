#!/bin/sh
# core-router: remove the diversion route, restoring direct delivery to the
# resolver. Matches divert-on.sh (no hard-coded interface in the delete).
set -eu
echo "[CORE-ROUTER] Removing diversion, restoring direct delivery..."
ip route del 172.16.2.10 via 172.16.2.100 2>/dev/null || true
ip route show
