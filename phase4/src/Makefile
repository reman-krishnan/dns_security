CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -D_GNU_SOURCE
LIBS = -lpcap

all: stripper

stripper: stripper.c
	$(CC) $(CFLAGS) -o stripper stripper.c $(LIBS)

clean:
	rm -f stripper
