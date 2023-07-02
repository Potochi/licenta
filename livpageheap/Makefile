.PHONY: runtest

pageheap: testprogram.c
	gcc -g $< -L./target/debug/ -llivpageheap -fPIC -o $@

lib: ./src/lib.rs
	cargo build

pagetest: pageheap lib
	LD_LIBRARY_PATH=./target/debug/ ./pageheap

pagegdb: pageheap lib
	gdb -ex 'set env LD_LIBRARY_PATH=./target/debug/' --args  ./pageheap
