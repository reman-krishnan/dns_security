#!/bin/sh
# Compile the Phase 5 NSEC zone-walker inside the attacker container.
set -eu
gcc -O2 -Wall -Wextra -D_GNU_SOURCE /src/walker.c -lpcap -o /usr/local/bin/walker
echo "Build complete: /usr/local/bin/walker"
