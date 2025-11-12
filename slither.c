#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <linux/if_link.h>
#include <bpf/btf.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include "slither.h"
#include "slither.skel.h"
#include <net/if.h>


int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args){
	if (level > LIBBPF_INFO)
		return 0;
	return vfprintf(stderr, format, args);
}

void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

int handle_event(void *ctx, void *data, size_t data_sz)
{

	return 0;
}

const char interface[] = "lo";
static int ifindex = 0;

static void cleanup_iface() {
  __u32 curr_prog_id;
  if (!bpf_xdp_query_id(ifindex, 0, &curr_prog_id)) {
    if (curr_prog_id) {
      bpf_xdp_detach(ifindex, 0, NULL);
      printf("Detached XDP program from interface");
    }
  }
}

int main(){
	struct ring_buffer *rb = NULL;
	struct slither_bpf *skel;
	int err;

	libbpf_set_print(libbpf_print_fn);

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	ifindex = if_nametoindex(interface);
	if (!ifindex){
		fprintf(stderr, "Error retrieving interface index");
		return 1;
	}

	skel = slither_bpf__open();
	if (!skel){
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	bpf_program__set_type(skel->progs.http_filter, BPF_PROG_TYPE_XDP);

	if (slither_bpf__load(skel)){
		fprintf(stderr, "Failed to load BPF skeleton\n");
		return 1;
	}

	err = slither_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	int xdpErr = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.http_filter), 0, NULL);
	if (xdpErr) {
		fprintf(stderr, "Error attaching XDP program to the interface");
		return 1;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}


	while (!exiting) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

cleanup:
	cleanup_iface();
	ring_buffer__free(rb);
	slither_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
