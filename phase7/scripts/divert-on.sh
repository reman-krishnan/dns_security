#!/bin/sh
# edge-router: divert resolver->client replies (dst 172.16.1.10) through the
# attacker at 172.16.1.100 on the client-subnet interface (detected by address).
# No ARP spoofing; the client's own config is untouched.
set -eu
DEV=$(ip -o -4 addr show | awk '/172\.16\.1\./{print $2; exit}')
echo "[EDGE-ROUTER] Diverting client-bound replies via attacker 172.16.1.100 on $DEV..."
ip route replace 172.16.1.10 via 172.16.1.100 dev "$DEV"
ip route show
