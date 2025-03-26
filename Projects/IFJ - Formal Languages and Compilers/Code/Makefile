.PHONY:all build clean run copy package

all: | build copy clean
build:
	mkdir -p build
	cd build/ && cmake .. && make all --no-print-directory
copy:
	cp build/ifj20c ifj20c
clean:
	rm -rf build/
run:
	./build/ifj20c
package: all
	zip xruzan00.zip *.c *.h Makefile CMakeLists.txt rozdeleni dokumentace.pdf