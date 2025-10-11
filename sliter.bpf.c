#include <bcc/proto.h>
#include <net/sock.h>
#include <uapi/linux/ptrace.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define IP_TCP 6
#define ETH_LEN 14
#define CONNOUT 10000000000000
#define IDLEOUT 10000000000000
#define MAX_MSG_SIZE 1024
#define ETH_P_IP        0x0800


struct Key {
	u32 src_ip;
	u32 dst_ip;
	unsigned short src_port;
	unsigned short dst_port;
};

struct Leaf {
	unsigned long long prv_comm;
	unsigned long long first_comm;
};


BPF_HASH(sessions, struct Key, struct Leaf);

int xdp(struct xdp_md *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	u32 tcp_header_length = 0;
	u32 ip_header_length = 0;
	u32 payload_offset = 0;
	u32 payload_length = 0;
	unsigned long long commTime = bpf_ktime_get_ns();
	struct Key key;
	struct Leaf leaf;


	struct ethhdr *ethernet = data;
	if (data + sizeof(struct ethhdr) > data_end)
		return XDP_PASS;
	if (bpf_ntohs(ethernet->h_proto) != ETH_P_IP){
		return XDP_PASS;
	}
	struct iphdr *ip = data + sizeof(*ethernet);
	if (data + sizeof(*ethernet) + sizeof(struct iphdr) > data_end)
		return XDP_PASS;
	if (ip->protocol != IPPROTO_TCP){
		return XDP_PASS;
	}
	struct tcphdr *tcp = data + sizeof(*ethernet) + sizeof(*ip);
	if (data + sizeof(*ethernet) + sizeof(*ip) + sizeof(struct tcphdr) > data_end)
		return XDP_PASS;

	key.dst_ip = ip->daddr;
	key.src_ip = ip->saddr;
	key.dst_port = bpf_ntohs(tcp->source);
	key.src_port = bpf_ntohs(tcp->dest);

	payload_offset = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct tcphdr);
	payload_length = ip->tot_len - sizeof(struct iphdr) - sizeof(struct tcphdr);

	if (payload_length < 7){
		return XDP_PASS;
	}

	struct Leaf *commCheck = sessions.lookup(&key);
	if (commCheck == NULL){
		leaf.prv_comm = commTime;
		leaf.first_comm = commTime;
		sessions.update(&key, &leaf);
	}
	else{
		unsigned long long elapsedSinceFirst = (commTime - commCheck->first_comm)/1000000000;
		unsigned long long elapsedSinceLast = (commTime - commCheck->prv_comm)/1000000000;
		bpf_trace_printk("Elapsed Time Since First Packet: %ld\n", elapsedSinceFirst);
		bpf_trace_printk("Elapsed Time Since Previous Packet: %ld\n", elapsedSinceLast);
		if (elapsedSinceFirst > IDLEOUT || elapsedSinceLast > CONNOUT)
			return XDP_DROP;
		leaf.prv_comm = commTime;
		leaf.first_comm = commCheck->first_comm;
		sessions.update(&key, &leaf);
	}

	bpf_trace_printk("GOT PORT 80 PACKET");

	return XDP_PASS;
}

