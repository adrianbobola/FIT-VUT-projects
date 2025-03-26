CC=g++
CFLAGS=-std=c++17 -g

all:
	$(CC) $(CFLAGS) flow.cpp -lpcap -o flow

clean:
	-rm flow

makeTar:
	tar -cf xbobol00.tar flow.cpp flow.hpp Makefile flow.1 manual.pdf

run:
	./flow -f input.pcap
