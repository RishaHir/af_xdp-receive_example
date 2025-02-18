CC=gcc
CFLAGS=-Wall -Wextra -g
LDFLAGS=-lxdp -lelf -lz -lbpf
KERN_COMMAND=clang -O2 -g -Wall --target=bpf


all: xsk-receive xdp_prog.o

xsk-receive: xsk-receive.o
	$(CC) $^ -o $@ $(LDFLAGS)

xdp_prog.o: xdp_prog.c
	$(KERN_COMMAND) -c $< -o $@

xsk-receive.o: xsk-receive.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm *.o xsk-receive
