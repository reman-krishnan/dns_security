CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -D_GNU_SOURCE
LIBS = -lpcap

all: walker

walker: walker.c
	$(CC) $(CFLAGS) -o walker walker.c $(LIBS)

clean:
	rm -f walker
