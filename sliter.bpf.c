#include "network.h"
#include <bcc/proto.h>
#include <linux/pkt_cls.h>
#include "packet.h"

#define CONNOUT 10000000000000
#define IDLEOUT 10000000000000
#define MAX_MSG_SIZE 1024

BPF_HASH(connection, u32);
BPF_HASH(idle, u32);

BERP_PERF_OUTPUT(httpOut);

struct httpData_t{
	struct attr_t{
		int event_type;
		int fd;
		int bytes;
		int msg_size;
	} attr;
	char msg[MAX_MSG_SIZE];
};

const int kEventTypeSyscallAddrEvent = 1;
const int kEventTypeSyscallWriteEvent = 2;
const int kEventTypeSyscallCloseEvent = 3;

BPF_PERCPU_ARRAY(write_buffer_heap, struct httpData_t, 1);
BPF_HASH(active_fds, int, bool);
BPF_HASH(active_sock_addr, u64, struct addr_info_t);


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



int http_accept_entry(struct pt_regs *ctx, int sockfd, struct sockaddr *addr, size_t *addrlen, int flags){
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	if (pid != $PID) {
		return 0;
	}

	struct addr_info_t* addr_info;
	addr_info.addr = addr;
	addr_info.addrlen = addrlen;
	active_sock_addr.update(&id, &addr_info);

	return 0;
}

int http_accept_ret(struct pt_regs *ctx, int sockfd, struct sockaddr *addr, size_t *addrlen, int flags) {
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	if (pid != $PID) {
		return 0;
	}

	struct addr_info_t* addr_info = active_sock_addr_lookup(&id);
	if (addr_info == NULL) {
		goto done;
	}

	int fd = PT_REGS_RC(ctx);
	if (fd < 0) {
		goto done;
	}
	bool t = true;
	active_fds.update(&fd, &t);

	int zero = 0;
	struct httpData_t *event = write_buffer_heap.lookup(&zero);
	if (event == 0) {
		goto done;
	}

	u64 addr_size = *(addr_info->addrlen);
	size_t buf_size = addr_size < sizeof(event->msg) ? addr_size : sizeof(event->msg);
	bpf_probe_read(&event->msg, buf_size, addr_info->addr);
	event->attr.event_type = kEventTypeSyscallAddrEvent;
	event->attr.fd = fd;
	event->attr.msg_size = buf_size;
	evnt->attr.bytes = buf.size;
	unsigned int size_to_submit =sizeof(event->attr_ + buf_size;
	syscall_write_events.perf_submit(ctx, event, size_to_submit);

	done:
		active_sock_addr.delete(&id);
		return 0;
}


int http_read(struct pt_regs *ctx, int fd, const void* buf, size_t count){
	int zero = 0;
	struct httpData_t *event = write_buffer_heap.lookup(&zero);


}

int http_close(struct pt_regs *ctx, int fd){
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	if (pid != $PID) {
		return 0;
	}

	int zero = 0;
	struct httpData_t *event = write_buffer_heap.lookup(&zero);
	if (event == NULL) {
		return 0;
	}

	event->attr.event_type = kEventTypeSyscallCloseEvent;
	event->attr.fd = fd;
	event->attr.bytes = 0;
	event->attr.msg_size = 0;
	syscall_write_events.perf_submit(ctx, event, sizeof(event->attr));

	active_fds.delete(&fd);
	return 0;
}

