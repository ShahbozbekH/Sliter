#include "network.h"
#include <bcc/proto.h>
#include <net/sock.h>
#include <uapi/linux/ptrace.h>
#include "packet.h"



#define IP_TCP 6
#define ETH_LEN 14
#define CONNOUT 10000000000000
#define IDLEOUT 10000000000000
#define MAX_MSG_SIZE 1024

struct Key {
	u32 src_ip;
	u32 dst_ip;
	unsigned short src_port;
	unsigned short dst_port;
};

struct Leaf {
	int timestamp;
};


BPF_HASH(sessions, struct Key, struct Leaf);
BPF_HASH(connection, u32);
BPF_HASH(idle, u32);




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

	if (port != 8080) {
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

//TC:

int http_filter(struct __sk_buff *skb){
	u8 * cursor = 0;

	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	if (!(ethernet->type == 0x800)) {
		return -1;
	}

	struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
	if (ip->nextp != IP_TCP) {
		return -1;
	}


	u32 tcp_header_length = 0;
	u32 ip_header_length = 0;
	u32 payload_offset = 0;
	u32 payload_length = 0;
	struct Key key;
	struct Leaf zero = {0};

	struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

	key.dst_ip = ip->dst;
	key.src_ip = ip->src;
	key.dst_port = tcp->dst_port;
	key.src_port =tcp->src_port;

	ip_header_length = ip->hlen << 2;
	tcp_header_length = tcp->offset << 2;

	payload_offset = ETH_HLEN  + ip_header_length + tcp_header_length;
	payload_length = ip->tlen - ip_header_length - tcp_header_length;


	if (payload_length < 7) {
		return -1;
	}


	unsigned long p[7];
	int i = 0;
	int j = 0;
	for (i = payload_offset ; i < (payload_offset + 7) ; i++) {
		p[j] = load_byte(skb , i);
		j++;
	}

	//find a match with an HTTP message
	//HTTP
	if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
		goto HTTP_MATCH;
	}
	//GET
	if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T')) {
		goto HTTP_MATCH;
	}
	//POST
	if ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T')) {
		goto HTTP_MATCH;
	}
	//PUT
	if ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T')) {
		goto HTTP_MATCH;
	}
	//DELETE
	if ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') && (p[5] == 'E')) {
		goto HTTP_MATCH;
	}
	//HEAD
	if ((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D')) {
		goto HTTP_MATCH;
	}

	struct Leaf * lookup_leaf = sessions.lookup(&key);
	if(lookup_leaf) {
		//send packet to userspace
		return 0;
	}
	return -1;

	HTTP_MATCH:
	//if not already present, insert into map <Key, Leaf>
		sessions.lookup_or_init(&key,&zero);


	return 0;
}



