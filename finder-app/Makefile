CC=aarch64-none-linux-gnu-gcc
CFLAGS=-Wall -g
OBJ=writer


# link default target to the rest of object files

all: $(OBJ)
	

writer: writer.c
	$(CC) $(CFLAGS) writer.c -o $(OBJ)

# rule used to clean objects and targets 

clean:
	rm -f *.o $(OBJ)	
