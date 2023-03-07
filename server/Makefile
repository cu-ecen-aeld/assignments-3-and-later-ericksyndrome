CROSS_COMPILE=aarch64-none-linux-gnu-gcc
CFLAGS=-Wall -Werror -g
CC=gcc

default: all

all: aesdsocket

aesdsocket: aesdsocket.c
	$(CC) $(CFLAGS) aesdsocket.c -o aesdsocket

clean:
	rm -rf *.o aesdsocket
