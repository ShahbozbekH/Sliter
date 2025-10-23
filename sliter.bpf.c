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


struct RingBuff{
	char msg[MAX_STRING_LENGTH];
};

BPF_RINGBUF_OUTPUT(events, 64);
BPF_TABLE("hash", struct Key, struct Leaf, sessions, 1024);

int xdp(struct xdp_md *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	u32 tcp_header_length = 0;
	u32 ip_header_length = 0;
	u64 payload_offset = 0;
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
	payload_length = (u64)(data_end - data) - payload_offset;

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
	struct RingBuff *payload = events.ringbuf_reserve(sizeof(struct RingBuff));
	if (payload){
		__u32 payLen = bpf_probe_read_kernel_str(payload->msg, ip->tot_len, data + payload_offset);
		if (payLen < 0){
			events.ringbuf_discard(payload, 0);
			return -1;
		}
		if (payload->msg[0] == 'G' && payload->msg[1] == 'E' && payload->msg[2] == 'T'){
			unsigned long long crlf = payLen - 4;
				/*for (int i = 0; i < 4; i++){
					if (crlf+i < payLen){
					if (payload->msg[crlf+i] == '\r')
						bpf_trace_printk("R");
					if (payload->msg[crlf+i] == '\n')
						bpf_trace_printk("N");
					}
				}*/
				if (payload->msg[crlf < 65535 ? crlf : 0] == '\r' && payload->msg[crlf + 1 < 65535 ? crlf+1 : 0] == '\n' && payload->msg[crlf + 2 < 65535 ? crlf+2 : 0] == '\r' && payload->msg[crlf + 3 < 65535 ? crlf+3 : 0] == '\n'){
					bpf_trace_printk("CRLF PASS");
					events.ringbuf_discard(payload, 0);
					return XDP_PASS;}
				else{
					bpf_trace_printk("CRLF DROP");
					events.ringbuf_discard(payload, 0);
					return XDP_DROP;
					//goto: end connection
			}
		}
		/*if (payload[0] == 'P' && payload[1] == 'O' && payload[2] == 'S' && payload[3] == 'T'){
			unsigned int content_length;
			char conLen[] = "Content-Length";
			if (strstr(payload, conLen) != NULL){
				bpf_trace_printk("FOUND CONTENT LEN");
			}
		}*/
		events.ringbuf_discard(payload, 0);
	}

	bpf_trace_printk("SADDR: %ld\n", key.src_ip);
	bpf_trace_printk("DEST_IP %ld\n,", key.dst_ip);
	bpf_trace_printk("DST_PORT: %ld\n", key.dst_port);
	bpf_trace_printk("SRC_PORT: %ld\n", key.src_port);

	bpf_trace_printk("TOT LEN: %ld\n", (u64)(data_end - data) - payload_offset);
	bpf_trace_printk("PAYLOAD OFFSET: %ld\n", payload_offset);
	bpf_trace_printk("PAYLOAD LEN: %ld\n", payload_length);

	bpf_trace_printk("GOT PORT 80 PACKET");

	return XDP_PASS;
}





