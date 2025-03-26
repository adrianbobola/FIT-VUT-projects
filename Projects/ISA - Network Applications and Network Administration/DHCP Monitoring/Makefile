CC=g++
CFLAGS=-std=c++17 -g -Wall

all:
	$(CC) $(CFLAGS) dhcp-stats.cpp -lpcap -o dhcp-stats -lncurses

clean:
	-rm dhcp-stats

makeTar:
	tar -cf xbobol00.tar dhcp-stats.cpp Makefile manual.pdf dhcp-stats.1 README.md
