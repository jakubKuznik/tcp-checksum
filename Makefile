CC = gcc
LD = gcc

CFLAGS = -O2 -g -std=c11 -pedantic -Wall -Wextra -D_BSD_SOURCE -D_DEFAULT_SOURCE 
all: tcp-checksum 

##########################################################################

tcp-checksum: tcp-checksum.o 
	gcc $(CFLAGS) tcp-checksum.o -o tcp-checksum -lpcap -lz

tcp-checksum.o: tcp-checksum.c tcp-checksum.h 
	gcc $(CFLAGS) -c tcp-checksum.c -o tcp-checksum.o -lpcap -lz

clean:
	rm *.o tcp-checksum 

run: dos 
	./
