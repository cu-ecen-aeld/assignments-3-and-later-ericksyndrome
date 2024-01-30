INCLUDE_DIRS =
LIB_DIRS =
CROSS_COMPILE=
CFLAGS ?= -Wall -Werror -g 
CC ?= $(CROSS_COMPILE)gcc
LDFLAGS ?= -lpthread -lrt
TARGET ?= aesdsocket
#might fix above

default: all

all: aesdsocket

aesdsocket: aesdsocket.c
	$(CC) $(CFLAGS) aesdsocket.c -o aesdsocket $(LDFLAGS) 

clean:
	rm -rf *.o aesdsocket
