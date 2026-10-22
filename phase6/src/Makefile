CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -D_GNU_SOURCE
LIBS = -lpcap
all: forge
forge: forge.c
	$(CC) $(CFLAGS) -o forge forge.c $(LIBS)
clean:
	rm -f forge
