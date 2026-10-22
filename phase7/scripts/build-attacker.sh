#!/bin/sh
set -eu
gcc -O2 -Wall -Wextra -D_GNU_SOURCE /src/mitm.c -lpcap -o /usr/local/bin/mitm
echo "Build complete: /usr/local/bin/mitm"
