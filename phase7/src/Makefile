CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -D_GNU_SOURCE
LIBS = -lpcap
all: mitm
mitm: mitm.c
	$(CC) $(CFLAGS) -o mitm mitm.c $(LIBS)
clean:
	rm -f mitm
