CROSS_COMPILE=
CFLAGS=-Wall -Werror -g
CC=$(CROSS_COMPILE)gcc

default: all

all: aesdsocket

aesdsocket: aesdsocket.c
	$(CC) $(CFLAGS) aesdsocket.c -o aesdsocket

clean:
	rm -rf *.o aesdsocket
