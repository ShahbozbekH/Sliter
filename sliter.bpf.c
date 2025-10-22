#include <bcc/proto.h>
#include <net/sock.h>
#include <uapi/linux/ptrace.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define IP_TCP 6
#define ETH_LEN 14
#define CONNOUT 5
#define IDLEOUT 5
#define MAX_MSG_SIZE 1024
#define ETH_P_IP        0x0800
#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define MAX_STRING_LENGTH 0xFFFF

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

struct pLen{
	u32 len;
};

BPF_RINGBUF_OUTPUT(events, 64);
BPF_TABLE("hash", struct Key, struct Leaf, sessions, 1024);

int xdp(struct xdp_md *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	u32 tcp_header_length = 0;
	u32 ip_header_length = 0;
	u32 payload_offset = 0;
	u64 payload_length = 0;
	unsigned long long commTime = bpf_ktime_get_ns();
	struct Key key = {};
	struct Leaf leaf = {};


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

	unsigned int iHL = 0;
	bpf_xdp_load_bytes(ctx, ETH_LEN, &iHL, 1);
	u32 ip_hl = (iHL & 0xF) * 4;
	key.dst_ip = ip->daddr;
	key.src_ip = ip->saddr;
	key.dst_port = bpf_ntohs(tcp->source);
	key.src_port = bpf_ntohs(tcp->dest);

	u32 tcp_offset = ip_hl + ETH_LEN + 12;
	unsigned int data_offset = 0;
	bpf_xdp_load_bytes(ctx, tcp_offset, &data_offset, 1);
	u32 tcp_hl = ((data_offset >> 4) & 0xF) * 4;


	payload_offset = ETH_LEN + ip_hl + tcp_hl;
	payload_length = (data_end - data) - payload_offset;
	struct pLen payLen = {};
	payLen.len = payload_length;


	if (payload_length <= 0){
		return XDP_PASS;
	}

	struct Leaf *commCheck = sessions.lookup(&key);
	if (commCheck == NULL){
		leaf.prv_comm = commTime;
		leaf.first_comm = commTime;
		sessions.update(&key, &leaf);
		//return XDP_PASS;
	}
	else{
		unsigned long long elapsedSinceFirst = (commTime - commCheck->first_comm)/1000000000;
		unsigned long long elapsedSinceLast = (commTime - commCheck->prv_comm)/1000000000;
		bpf_trace_printk("Elapsed Time Since First Packet: %ld\n", elapsedSinceFirst);
		bpf_trace_printk("Elapsed Time Since Previous Packet: %ld\n", elapsedSinceLast);
		leaf.prv_comm = commTime;
		leaf.first_comm = commCheck->first_comm;
		sessions.update(&key, &leaf);
		if (elapsedSinceFirst > IDLEOUT || elapsedSinceLast > CONNOUT)
			return XDP_DROP;//CHANGE TO PASS AFTER
	}
	//check last 4 bytes (data_end - 4) for rnrn
	//if post,parse for "Content-length" and check if request body is equal in size
	//if content-length > total size of Response Body
	//send back RST+ACK and FIN+ACK
	//u32 payKey = 123;
	//char zero = '0';
	//bpf_xdp_load_bytes(ctx, payload_offset, arrCPU.lookup_or_try_init(&payKey, &zero), payload_length);
	char *bufPoint = events.ringbuf_reserve(65535);
	if (bufPoint != NULL){
		bpf_xdp_load_bytes(ctx, payload_offset, bufPoint, payLen.len);
		bpf_trace_printk("Head Type %s", bufPoint);
		events.ringbuf_discard(bufPoint, 0);
	}
	/*if (headType[0] == 'G' && headType[1] == 'E' && headType[2] == 'T'){
		char crlf[4];
		bpf_xdp_load_bytes(ctx, (payload_offset + payload_length) - 4, crlf, 4);
		bpf_trace_printk("STRING: %s", crlf);
		if (crlf[0] == '\r' && crlf[1] == '\n' && crlf[2] == '\r' && crlf[3] == '\n'){
			bpf_trace_printk("CRLF PASS");
			return XDP_PASS;}
		else{
			bpf_trace_printk("CRLF DROP");
			return XDP_DROP;
			//goto: end connection
		}
	}*/
	/*if (headType[0] == 'P' && headType[1] == 'O' && headType[2] == 'S' && headType[3] == 'T'){
		unsigned int content_length;
		char headers[];
		char conLen[] = "Content-Length";
		bpf_xdp_load_bytes(ctx, payload_offset, headers, 250);
		if (strstr(headers, conLen) != NULL){
			bpf_trace_printk("FOUND CONTENT LEN");
		}
	}*/

	bpf_trace_printk("SADDR: %ld\n", key.src_ip);
	bpf_trace_printk("DEST_IP %ld\n,", key.dst_ip);
	bpf_trace_printk("DST_PORT: %ld\n", key.dst_port);
	bpf_trace_printk("SRC_PORT: %ld\n", key.src_port);

	bpf_trace_printk("TOT LEN: %ld\n", data_end - data);
	bpf_trace_printk("PAYLOAD OFFSET: %ld\n", payload_offset);
	bpf_trace_printk("PAYLOAD LEN: %ld\n", payload_length);

	bpf_trace_printk("GOT PORT 80 PACKET");

	return XDP_PASS;
}





