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
#include <argp.h>

#define warn(...) fprintf(stderr, __VA_ARGS__)

static struct env env = {
	.connout = 5,
	.idleout = 5,
};

//Taken from: https://github.com/iovisor/bcc/blob/b63d7e38e8a0f6339fbd57f3a1ae7297e1993d92/libbpf-tools/tcptracer.c#L58
static int get_uint(const char *arg, unsigned int *ret,
		    unsigned int min, unsigned int max)
{
	char *end;
	long val;

	errno = 0;
	val = strtoul(arg, &end, 10);
	if (errno) {
		warn("strtoul: %s: %s\n", arg, strerror(errno));
		return -1;
	} else if (end == arg || val < min || val > max) {
		return -1;
	}
	if (ret)
		*ret = val;
	return 0;
}

static const struct argp_option opts[] = {
	{"conntime", 'd', "<seconds>", 0, "Set threshold for the length of time a connection can remain active before being verified.\n", 0},
	{"idletime", 'i', "<seconds>", 0, "Set threshold for the length of time between current and last packet sent by client for it to be verified.\n", 0},
	{NULL, 'h', NULL, OPTION_HIDDEN, "Present this help menu.\n", 0},
	{},
};

static const char argp_program_doc[] =
	"\nSlither\n"
	"An implementation of an HTTP packet verification method for SLOW attacks developed by Dau Anh Dung and Yasuhiro Nakamura.\n";


static error_t parser_arg(int key, char *arg, struct argp_state *state){
	int err;
	switch (key){
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'd':
		err = get_uint(arg, &env.connout, 0, 3);
		if (err) {
			fprintf(stderr, "999 seconds is the max that can be set");
			argp_usage(state);
		}
		break;
	case 'i':
		err = get_uint(arg, &env.idleout, 0, 3);
		if (err) {
			fprintf(stderr, "999 seconds is the max that can be set");
			argp_usage(state);
		}
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

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

int main(int argc, char **argv){
	struct ring_buffer *rb = NULL;
	struct slither_bpf *skel;
	int err;
	static const struct argp argp = {
		.options = opts,
		.parser = parser_arg,
		.doc = argp_program_doc,
		.args_doc = NULL,
	};

	libbpf_set_print(libbpf_print_fn);

	int argErr;
	argErr = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (argErr)
		return argErr;

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
