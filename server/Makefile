CROSS_COMPILE ?=
#CROSS_COMPILE=aarch64-none-linux-gnu-
CC ?= gcc
TARGET ?= aesdsocket
OBJFILES ?= aesdsocket.o
CFLAGS ?= -g -Wall -Werror
LDFLAGS ?= -lpthread -lrt
#LDFLAGS ?= -pthread
#$(CC) -o aesdsocket aesdsocket.o $(CFLAGS) $(LDFLAGS) -lpthread; \
#"$(CROSS_COMPILE)$(CC)" -o aesdsocket aesdsocket.o $(CFLAGS) $(LDFLAGS) -lpthread; \


default: all

all: aesdsocket

aesdsocket: aesdsocket.o
	@if [ -z "$(CROSS_COMPILE)" ]; \
	then \
		$(CC) -g -o $(TARGET) $(OBJFILES) $(CFLAGS) $(LDFLAGS); \
	else \
		$(CROSS_COMPILE)$(CC) -o $(TARGET) $(OBJFILES) $(CFLAGS) $(LDFLAGS); \
	fi

aesdsocket.o: aesdsocket.c
	@if [ -z "$(CROSS_COMPILE)" ]; \
	then \
		$(CC) -c $(TARGET).c -g -o $(OBJFILES); \
	else \
		$(CROSS_COMPILE)$(CC) -c $(TARGET).c -o $(OBJFILES); \
	fi

clean:
	@rm -f aesdsocket aesdsocket.o
