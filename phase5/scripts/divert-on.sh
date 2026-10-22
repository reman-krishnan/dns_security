#!/bin/sh
# core-router: divert resolver-bound replies (dst 172.16.2.10) through the
# attacker at 172.16.2.100. The resolver-subnet interface is detected by its
# address, so this works regardless of how Docker ordered ethN on this run.
set -eu
DEV=$(ip -o -4 addr show | awk '/172\.16\.2\./{print $2; exit}')
echo "[CORE-ROUTER] Diverting resolver-bound replies via attacker 172.16.2.100 on $DEV..."
ip route replace 172.16.2.10 via 172.16.2.100 dev "$DEV"
ip route show
