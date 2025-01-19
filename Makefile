#flags
CC = gcc
CFLAGS = -g -Wall -pedantic -std=gnu99
LIBS = -lpcap

#target
all: trace

#execute
trace: trace.o print.o checksum.o
	$(CC) $(CFLAGS) -o trace  trace.o print.o checksum.o $(LIBS)

#object files
trace.o: trace.c trace.h
	$(CC) $(CFLAGS) -c trace.c

print.o: print.c trace.h
	$(CC) $(CFLAGS) -c print.c

checksum.o: checksum.c checksum.h
	$(CC) $(CFLAGS) -c checksum.c

#for cleaning
clean:
	rm -f trace trace.o print.o checksum.o
