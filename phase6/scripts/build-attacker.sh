#!/bin/sh
# Compile the Phase 6 last-mile forger inside the attacker container.
set -eu
gcc -O2 -Wall -Wextra -D_GNU_SOURCE /src/forge.c -lpcap -o /usr/local/bin/forge
echo "Build complete: /usr/local/bin/forge"
