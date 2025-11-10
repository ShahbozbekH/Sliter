#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

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

struct{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, sizeof(struct RingBuff));
} events SEC(".maps");

struct{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct Key);
	__type(value, struct Leaf);
	} sessions SEC(".maps");

SEC("xdp")
int http_filter(struct xdp_md *ctx) {
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
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

	struct Leaf *commCheck = bpf_map_lookup_elem(&sessions, &key);
	if (commCheck == NULL){
		leaf.prv_comm = commTime;
		leaf.first_comm = commTime;
		bpf_map_update_elem(&sessions, &key, &leaf, BPF_NOEXIST);
		//return XDP_PASS;
	}
	else{
		unsigned long long elapsedSinceFirst = (commTime - commCheck->first_comm)/1000000000;
		unsigned long long elapsedSinceLast = (commTime - commCheck->prv_comm)/1000000000;
		bpf_printk("Elapsed Time Since First Packet: %ld\n", elapsedSinceFirst);
		bpf_printk("Elapsed Time Since Previous Packet: %ld\n", elapsedSinceLast);
		leaf.prv_comm = commTime;
		leaf.first_comm = commCheck->first_comm;
		bpf_map_update_elem(&sessions, &key, &leaf, BPF_EXIST);
		if (elapsedSinceFirst > IDLEOUT || elapsedSinceLast > CONNOUT)
			return XDP_DROP;//CHANGE TO PASS AFTER
	}
	//check last 4 bytes (data_end - 4) for rnrn
	//if post,parse for "Content-length" and check if request body is equal in size
	//if content-length > total size of Response Body
	//send back RST+ACK and FIN+ACK
	struct RingBuff *payload = bpf_ringbuf_reserve(&events, sizeof(struct RingBuff), 0);
	//bpf_trace_printk("HERE HERE %ld", events.ringbuf_query(BPF_RB_CONS_POS));
	if (payload){
		__u32 payLen = bpf_probe_read_kernel_str(payload->msg, ip->tot_len, data + payload_offset);
		if (payLen < 0){
			bpf_ringbuf_discard(payload, BPF_RB_FORCE_WAKEUP);
			return -1;
		}
		bpf_printk("Payload: %s", payload->msg);
		if (payload->msg[0] == 'G' && payload->msg[1] == 'E' && payload->msg[2] == 'T'){
			unsigned long long crlf = payLen - 5;
			if (payload->msg[crlf < 65534 ? crlf : 0] == '\r' && payload->msg[crlf + 1 < 65534 ? crlf + 1 : 0] == '\n' && payload->msg[crlf + 2 < 65534 ? crlf + 2 : 0] == '\r' && payload->msg[crlf + 3 < 65534 ? crlf + 3 : 0] == '\n'){
				bpf_printk("CRLF PASS");
				bpf_ringbuf_discard(payload, BPF_RB_FORCE_WAKEUP);
				return XDP_PASS;
				}
			else{
				bpf_printk("CRLF DROP");
				bpf_ringbuf_discard(payload, BPF_RB_FORCE_WAKEUP);
				return XDP_DROP;
				//goto: end connection
			}
		}
		int end = 0;
		int start = 0;
		if (payload->msg[0] == 'P' && payload->msg[1] == 'O' && payload->msg[2] == 'S' && payload->msg[3] == 'T'){
			bool exist = 0;
			for (int i = 0; i < 500; i++){
				if (payload->msg[i] == '\r' && payload->msg[i+1] == '\n'){
					if (payload->msg[i] == '\r' && payload->msg[i+1] == '\n'){
					int nextChar = payload->msg[i+2];
					//bpf_trace_printk("Content-Length: %ld", nextChar);
					if (nextChar == '\r')
						break;
						//goto end;
					if (nextChar == 'C' || nextChar == 'c'){
						//bpf_trace_printk("Content-Length: %c", payload->msg[i+15]);
						if (payload->msg[i+15] == 'h' || payload->msg[i+15] == 'H')
							break;
							//bpf_trace_printk("Content-Length: %c %c", payload->msg[i+18], payload->msg[i+19]);
						else
							break;
					/*bpf_trace_printk("HELLO");
					if (exist){
							end = i;
							int lenLen = end - start;
							bpf_trace_printk("lenLen %ld", lenLen);
							long contentLength = 0;
							for (int j = 0; j < lenLen; j++){
								contentLength += payload->msg[start];
							}
							bpf_trace_printk("contLen %ld", contentLength);
							goto stop;
						}
					else{
						char nextChar = payload->msg[i+2];
						switch (nextChar){
							case('\r'):
								goto stop;
							case('C'):
								goto check;
							case('c'):
								goto check;
						}
						check:
						bpf_trace_printk("Content-Length: %c", payload->msg[i+15]);
						if ((payload->msg[i+3] == 'o' || payload->msg[i+3] == 'O') && (payload->msg[i+4] == 'n' || payload->msg[i+13] == 'G') && (payload->msg[i+14] == 't' || payload->msg[i+14] == 'T') && (payload->msg[i+15] == 'h' || payload->msg[i+15] == 'H')){
							bpf_trace_printk("18 and 19: %c %c", payload->msg[i+18], payload->msg[i+19]);
							exist = 1;
							start = i+18;
							i += 18;
							continue;*/
						}
					}
				}
			}
		}
		//stop:
		bpf_ringbuf_discard(payload, BPF_RB_FORCE_WAKEUP);
	}
	/*
	bpf_trace_printk("SADDR: %ld\n", key.src_ip);
	bpf_trace_printk("DEST_IP %ld\n,", key.dst_ip);
	bpf_trace_printk("DST_PORT: %ld\n", key.dst_port);
	bpf_trace_printk("SRC_PORT: %ld\n", key.src_port);

	bpf_trace_printk("TOT LEN: %ld\n", (u64)(data_end - data) - payload_offset);
	bpf_trace_printk("PAYLOAD OFFSET: %ld\n", payload_offset);
	bpf_trace_printk("PAYLOAD LEN: %ld\n", payload_length);

	bpf_trace_printk("GOT PORT 80 PACKET");
	*/
	return XDP_PASS;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";
