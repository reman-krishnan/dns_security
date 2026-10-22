#!/bin/sh
set -eu
iptables -D FORWARD -p tcp -d 172.16.2.10 -m multiport --dports 853,443 -j REJECT --reject-with tcp-reset 2>/dev/null || true
echo "[edge-router] transport block removed."
