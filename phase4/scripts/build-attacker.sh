#!/bin/sh
# Compiles the Phase 4 strip-mode interceptor inside the attacker container.
# Source is mounted read-only at /src; the binary lands in /usr/local/bin.
set -eu
gcc -O2 -Wall -Wextra -D_GNU_SOURCE /src/stripper.c -lpcap -o /usr/local/bin/stripper
echo "Build complete: /usr/local/bin/stripper"
