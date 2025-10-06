#include "network.h"
#include <bcc/proto.h>
#include <linux/pkt_cls.h>
#include "packet.h"

#define CONNOUT 10000000000000
#define IDLEOUT 10000000000000

BPF_HASH(connection, u32);
BPF_HASH(idle, u32);

BERP_PERF_OUTPUT(httpOut);

struct httpData_t {
	
}

int xdp(struct xdp_md *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	char addrArr[6];
	unsigned long long connTime = bpf_ktime_get_ns();

	long protocol = lookup_protocol(data, data_end);
	unsigned int srcAddr = lookup_src_addr(data, data_end);
	int port = tcp_lookup_port(data, data_end);

	if (protocol != 6) {
        	return XDP_PASS;
  	}

	if (port != 80) {
		return XDP_PASS;
	}

	unsigned long long *connFirst = connection.lookup(&srcAddr);
	unsigned long long *idlePrev = idle.lookup(&srcAddr);
	if (connFirst == NULL) {
		connection.update(&srcAddr, &connTime);
	}
	else{
		unsigned long long connElapsed = (connTime - *connFirst)/1000;
		bpf_trace_printk("Elapsed Time Since First Packet: %ld\n", connElapsed);
		if (idlePrev != NULL){
			unsigned long long idleElapsed = (connTime - *idlePrev)/1000;
			bpf_trace_printk("Elapsed Time Since Last Packet: %ld\n", idleElapsed);
			if (idleElapsed > IDLEOUT)
                        return XDP_DROP;
		}
		//USE CONFIG FILE FOR TIMEOUT TIMES
		if (connElapsed > CONNOUT)
                        return XDP_DROP;
	}
	idle.update(&srcAddr, &connTime);

	bpf_trace_printk("GOT PORT 80 PACKET");
	bpf_trace_printk("%ld \n", srcAddr);

	return XDP_PASS;
}



int http_accept(struct pt_regs *ctx, int sockfd, struct sockaddr *addr, size_t *addrlen, int flags){


	return 0;
}

int http_read(void* ctx){
}

int http_close(struct pt_regs *ctx, int fd){
}

