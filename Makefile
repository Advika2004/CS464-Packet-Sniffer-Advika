#flags
CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lpcap

#target
all: trace

#execute
trace: trace.o print.o
	$(CC) $(CFLAGS) -o trace  trace.o print.o $(LDFLAGS)

#object files
trace.o: trace.c trace.h
	$(CC) $(CFLAGS) -c trace.c

print.o: print.c trace.h
	$(CC) $(CFLAGS) -c print.c

#for cleaning
clean:
	rm -f trace trace.o print.o
