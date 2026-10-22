#!/bin/sh
set -eu
DEV=$(ip -o -4 addr show | awk '/172\.16\.2\./{print $2; exit}')
echo "[CORE-ROUTER] Diverting resolver-bound replies via attacker 172.16.2.100 on $DEV..."
ip route replace 172.16.2.10 via 172.16.2.100 dev "$DEV"
ip route show
