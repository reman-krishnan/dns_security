#!/bin/sh
set -eu
gcc -O2 -Wall -Wextra /src/interceptor.c -lpcap -o /usr/local/bin/interceptor
echo "Build complete: /usr/local/bin/interceptor"
