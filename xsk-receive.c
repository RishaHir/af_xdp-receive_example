#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <net/if.h>
#include <signal.h>

#include <xdp/libxdp.h>
#include <xdp/xsk.h>

#define NUM_FRAMES 4096
#define INVALID_ADDRESS UINT64_MAX

static long q_idx = 0;
static bool mode_generic = 0;
static char ifname[IF_NAMESIZE + 1] = {0, };
static unsigned ifindex = UINT32_MAX;

volatile int run = 1;

static uint64_t addresses[NUM_FRAMES];
static int addr_counter = 0;

void sig_handler(int sig) {
	sig = sig;
	run = 0;
}

// Get address from stack
uint64_t alloc_addr() {
	if (addr_counter == 0) {
		fprintf(stderr, "BUG out of adresses\n");
		exit(1);
	}
	uint64_t addr = addresses[--addr_counter];
	addresses[addr_counter] = INVALID_ADDRESS;
	return addr;
}

// Put adress to stack
void free_addr(uint64_t address) {
	if (addr_counter == NUM_FRAMES) {
		fprintf(stderr, "BUG counting adresses\n");
		exit(1);
	}
	addresses[addr_counter++] = address; 
}

void parseopts(int argc, char **argv) {
	int c;
  	while (1) {
		static struct option long_options[] =
		{
			{"queue",  required_argument, 0, 'q'},
			{"generic",  no_argument, 0, 'g'},
			{"interface",  required_argument, 0, 'i'},
			{0, 0, 0, 0}
		};
		/* getopt_long stores the option index here. */
		int option_index = 0;
		c = getopt_long(argc, argv, "q:gi:",
						long_options, &option_index);

		/* Detect the end of the options. */
		if (c == -1)
			break;

		switch (c) {
		case 'q':
			errno = 0;
			q_idx = strtol(optarg, NULL, 10);
			if (errno) {
				fprintf(stderr, "Error parsing args\n");
				abort();
			}
			break;
		case 'g':
			mode_generic = 1;
			break;
		case 'i':
			strncpy(ifname, optarg, IF_NAMESIZE);
			break;
		case '?':
			/* getopt_long already printed an error message. */
			break;
		default:
			fprintf(stderr, "Error parsing args\n");
			abort();
		}
    }
}

int main(int argc, char **argv)
{
	signal(SIGINT, sig_handler);

	parseopts(argc, argv);
	
	struct xdp_program *prog;
	int err;

	ifindex = if_nametoindex(ifname);

	// Open XDP program
	if(!(prog = xdp_program__open_file("xdp_prog.o", "xdp_prog", NULL))) {
		fprintf(stderr, "Error opening XDP program\n");
		err = 1;
		goto err_close;
	}

	// Attach XDP program to interface
	if ((err = xdp_program__attach(prog, ifindex, XDP_MODE_NATIVE, 0))) {
		fprintf(stderr, "Error attaching XDP program: %d\n", err);
		xdp_program__detach(prog, ifindex, XDP_MODE_NATIVE, 0);
		err = 1;
		goto err_close;
	}

	// Get xsk map
	int xsk_map_fd;
	xsk_map_fd = bpf_object__find_map_fd_by_name(xdp_program__bpf_obj(prog), "xsks_map");
	if (xsk_map_fd < 0) {
        fprintf(stderr, "Failed to get xsk_map\n");
        err = 1;
		goto err_detach;
    }

	// Allocate umem buffer and fill adresses[] with adresses to individual frames
	uint32_t pagesize = getpagesize();
	void *umem_buff;
	if(posix_memalign(&umem_buff, pagesize, pagesize * NUM_FRAMES)) {
		fprintf(stderr, "Failed to get allocate umem umem_buff\n");
        err = 1;
		goto err_detach;
	}
	for (addr_counter = 0; addr_counter < NUM_FRAMES; addr_counter++) {
		addresses[addr_counter] = addr_counter * pagesize;
	}

	// Register umem
	struct xsk_umem *umem;
	struct xsk_ring_prod fill_ring;
    struct xsk_ring_cons comp_ring;
	struct xsk_umem_config umem_cfg = {
		.comp_size = NUM_FRAMES,
		.fill_size = NUM_FRAMES,
		.frame_size = pagesize,
		.frame_headroom = 0,
		.flags = 0,
	};
	if(xsk_umem__create(&umem, umem_buff, pagesize * NUM_FRAMES, &fill_ring, &comp_ring, &umem_cfg)) {
		fprintf(stderr, "Failed to create umem\n");
        err = 1;
		goto err_free;
	}

	// Create XSK
	struct xsk_socket *xsk;
	struct xsk_ring_cons rx_ring;
	struct xsk_ring_prod tx_ring;
	struct xsk_socket_config xsk_cfg = {
		.bind_flags = 0,
		.libxdp_flags = 0,
		.rx_size = NUM_FRAMES,
		.tx_size = NUM_FRAMES,
		.xdp_flags = 0,
	};
	if(xsk_socket__create(&xsk, ifname, q_idx, umem, &rx_ring, &tx_ring, &xsk_cfg)) {
		fprintf(stderr, "Failed to create XSK\n");
        err = 1;
		goto err_free;
	}

	// Set the XDP XSK_MAP to redirect to the newly created XSK
	int xsk_sock_fd = xsk_socket__fd(xsk);
	if (bpf_map_update_elem(xsk_map_fd, &q_idx, &xsk_sock_fd, BPF_ANY)) {
        fprintf(stderr, "Failed to update XSK map\n");
        err = 1;
		goto err_delete;
    }

	// The receive loop
	while (run) {
		// Fill rx
		unsigned rx_idx = 0;
		unsigned fill_idx = 0;
		unsigned reserved = xsk_ring_prod__reserve(&fill_ring, addr_counter, &fill_idx);
		for(unsigned i = 0; i < reserved; i++) {
			uint64_t addr = alloc_addr();
			*xsk_ring_prod__fill_addr(&fill_ring, fill_idx++) = addr;
		}
		xsk_ring_prod__submit(&fill_ring, reserved);

		// Receive packets
		while(xsk_ring_cons__peek(&rx_ring, 1, &rx_idx)) {
			struct xdp_desc const *desc = xsk_ring_cons__rx_desc(&rx_ring, rx_idx);	
			// Process packets
			// void *data = xsk_umem__get_data(umem_buff, desc->addr);
			printf("Received packet of size %u bytes\n", desc->len);
			// Release descriptors
			free_addr(desc->addr);
            xsk_ring_cons__release(&rx_ring, 1);
		}
	}


err_delete:
	xsk_socket__delete(xsk);
err_free:	
	free(umem_buff);
	// Detach all programs present on interface since libxdp attaches multiple
	struct xdp_multiprog *mp;
	if(!(mp = xdp_multiprog__get_from_ifindex(ifindex))){
		fprintf(stderr, "Failed to get all progs for detach, there may be XDP progs left behind\n");
        err = 1;
		goto err_detach;
	}
	if((err = xdp_multiprog__detach(mp))) {
		fprintf(stderr, "Failed to detach all progs for detach, there may be XDP progs left behind\n");
        err = 1;
		goto err_detach;
	}
	xdp_multiprog__close(mp);
	return err;

err_detach:
	xdp_program__detach(prog, ifindex, XDP_MODE_NATIVE, 0);
err_close:
	xdp_program__close(prog);
	return err;
}
