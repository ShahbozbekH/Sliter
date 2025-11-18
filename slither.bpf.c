#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "slither.h"

#define ETH_LEN 14
#define ETH_P_IP        0x0800

#define bpf_for(i, start, end) for (                                \
    /* initialize and define destructor */                          \
    struct bpf_iter_num ___it __attribute__((aligned(8), /* enforce, just in case */    \
                         cleanup(bpf_iter_num_destroy))),       \
    /* ___p pointer is necessary to call bpf_iter_num_new() *once* to init ___it */     \
                *___p __attribute__((unused)) = (                   \
                bpf_iter_num_new(&___it, (start), (end)),           \
    /* this is a workaround for Clang bug: it currently doesn't emit BTF */         \
    /* for bpf_iter_num_destroy() when used from cleanup() attribute */         \
                (void)bpf_iter_num_destroy, (void *)0);             \
    ({                                          \
        /* iteration step */                                \
        int *___t = bpf_iter_num_next(&___it);                      \
        /* termination and bounds check */                      \
        (___t && ((i) = *___t, (i) >= (start) && (i) < (end)));             \
    });                                         \
)

struct Key {
	u32 src_ip;
	u32 dst_ip;
	unsigned short src_port;
	unsigned short dst_port;
};

struct Leaf {
	unsigned long long prv_comm;
	unsigned long long first_comm;
	bool drop;
};

//BPF Map structs
struct{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct Key);
	__type(value, struct Leaf);
} sessions SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_STACK);
        __type(value, __u32);
        __uint(max_entries, 10);
} stack SEC(".maps");

struct{
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 256 * 1024);
} timeout SEC(".maps");

struct{
	__uint(type, BPF_MAP_TYPE_STACK);
	__type(value, struct env);
	__uint(max_entries, 1);
} toutStack SEC(".maps");


static long read_protocol_msg(struct bpf_dynptr *dynptr, void *context){
	const struct env *timeoutStruct;
	timeoutStruct = bpf_dynptr_data(dynptr, 0, sizeof(struct env));
	if (!timeoutStruct){
		return 1;
	}
	struct env tempTimeout = {
		.connout = timeoutStruct->connout,
		.idleout = timeoutStruct->idleout,
	};
	bpf_map_push_elem(&toutStack, &tempTimeout, BPF_ANY);
	return 1;
}

SEC("xdp")
int http_filter(struct xdp_md *ctx) {
	//get bounds of the packet
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	u64 payload_offset = 0;
	u64 payload_length = 0;

	//get timestamp
	unsigned long long commTime = bpf_ktime_get_ns();

	struct Key key = {};
	struct Leaf leaf = {};

	//cast data into ether header struct, check if bounds are violated and if it is a ip packet
	struct ethhdr *ethernet = data;
	if (data + sizeof(struct ethhdr) > data_end)
		return XDP_PASS;
	if (bpf_ntohs(ethernet->h_proto) != ETH_P_IP){
		return XDP_PASS;
	}
	//same as above but with ip header
	struct iphdr *ip = data + sizeof(*ethernet);
	if (data + sizeof(*ethernet) + sizeof(struct iphdr) > data_end)
		return XDP_PASS;
	if (ip->protocol != IPPROTO_TCP){
		return XDP_PASS;
	}
	//same as above
	struct tcphdr *tcp = data + sizeof(*ethernet) + sizeof(*ip);
	if (data + sizeof(*ethernet) + sizeof(*ip) + sizeof(struct tcphdr) > data_end)
		return XDP_PASS;

	//add required values to key and check ip header length
	unsigned int iHL = 0;
	bpf_xdp_load_bytes(ctx, ETH_LEN, &iHL, 1);
	u32 ip_hl = (iHL & 0xF) * 4;
	key.dst_ip = ip->daddr;
	key.src_ip = ip->saddr;
	key.dst_port = bpf_ntohs(tcp->source);
	key.src_port = bpf_ntohs(tcp->dest);

	//calculate payload offset and length
	u32 tcp_offset = ip_hl + ETH_LEN + 12;
	unsigned int data_offset = 0;
	bpf_xdp_load_bytes(ctx, tcp_offset, &data_offset, 1);
	u32 tcp_hl = ((data_offset >> 4) & 0xF) * 4;
	payload_offset = ETH_LEN + ip_hl + tcp_hl;
	payload_length = (u64)(data_end - data) - payload_offset;
	if (payload_length <= 0){
		return XDP_PASS;
	}

	//check if key exists
	struct Leaf *commCheck = bpf_map_lookup_elem(&sessions, &key);
	if (commCheck == NULL){
		//add leaf values to new connection
		leaf.prv_comm = commTime;
		leaf.first_comm = commTime;
		leaf.drop = 0;
		bpf_map_update_elem(&sessions, &key, &leaf, BPF_NOEXIST);
		return XDP_PASS;
	}
	else{
		//check if packet violates timeout values
		if (commCheck->drop)
			return XDP_DROP;
		unsigned long long elapsedSinceFirst = (commTime - commCheck->first_comm)/1000000000;
		unsigned long long elapsedSinceLast = (commTime - commCheck->prv_comm)/1000000000;
		leaf.prv_comm = commTime;
		leaf.first_comm = commCheck->first_comm;
		bpf_map_update_elem(&sessions, &key, &leaf, BPF_EXIST);

		//read user timeout input
		bpf_user_ringbuf_drain(&timeout, read_protocol_msg, NULL, 0);
		struct env timeOut;
		bpf_map_peek_elem(&toutStack, &timeOut);

		if (elapsedSinceFirst < timeOut.connout || elapsedSinceLast < timeOut.idleout)
			return XDP_PASS;
	}
	//reserve space for payload from ringbuf
	struct RingBuff *payload = bpf_ringbuf_reserve(&events, sizeof(struct RingBuff), 0);
	if (payload){
		//read into reserved space
		__u32 payLen = bpf_probe_read_kernel_str(payload->msg, ip->tot_len, data + payload_offset);
		if (payLen < 0){
			bpf_ringbuf_submit(payload, BPF_RB_FORCE_WAKEUP);
			return -1;
		}
		//check if GET
		if (bpf_strncmp(payload->msg, 3, "GET") == 0){
			unsigned long long crlf = payLen - 5;
			char *crlfPtr = payload->msg + (crlf < 65532 ? crlf : 0);
			//check if last 4 bytes are CRLF
			if (bpf_strncmp(crlfPtr, 4, "\r\n\r\n") == 0){
				bpf_ringbuf_submit(payload, BPF_RB_FORCE_WAKEUP);
				return XDP_PASS;
				}
			else{
				leaf.drop = 1;
				bpf_map_update_elem(&sessions, &key, &leaf, BPF_EXIST);
				bpf_ringbuf_submit(payload, BPF_RB_FORCE_WAKEUP);
				return XDP_DROP;
			}
		}
		//check if post or response
		if (!bpf_strncmp(payload->msg, 4, "POST") || !bpf_strncmp(payload->msg, 8, "HTTP/1.1.")){
			u32 i = 0;
			bool j = 0;
			int size = 0;
			//loop through HTTP and find content length
			bpf_for(i, 0, payLen){
				if (i < 65513) {
					if (bpf_strncmp(&payload->msg[i], 2, "\r\n") == 0){
						if (bpf_strncmp(&payload->msg[i], 4, "\r\n\r\n") == 0){
							leaf.drop = 1;
							bpf_map_update_elem(&sessions, &key, &leaf, BPF_EXIST);
							bpf_ringbuf_submit(payload, BPF_RB_FORCE_WAKEUP);
							return XDP_DROP;
						}
						if ((payload->msg[i+2] == 'C' || payload->msg[i+2] == 'c') && payload->msg[i+9] == '-' && payload->msg[i+16] == ':'){
							j = 1;
							continue;
						}
					}
					if (j){
						//once content-length header is found it checks ahead 17 characters, where the value is
						//if the value 17 chars ahead is CRLF it breaks the loop
						if (!bpf_strncmp(&payload->msg[i+17], 2, "\r\n"))
							break;
						bpf_map_push_elem(&stack, &payload->msg[i+17], BPF_ANY);
						size++;
					}
					continue;
				}
				leaf.drop = 1;
				bpf_map_update_elem(&sessions, &key, &leaf, BPF_EXIST);
				bpf_ringbuf_submit(payload, BPF_RB_FORCE_WAKEUP);
				return XDP_DROP;
			}
			//the value grabbed from memory is written in individual ascii chars
			//it is converted to an int value here
			u32 z = 0;
			int valAddr[1];
			int value = 0;
			int decExp = 1;
			int cLen = 0;
			bpf_for(z, 0, size){
				bpf_map_pop_elem(&stack, valAddr);
				bpf_probe_read_kernel(&value, 1, valAddr);
				cLen += (value-48)*decExp;
				decExp *= 10;
			}
			if (cLen > payLen){
				leaf.drop = 1;
				bpf_map_update_elem(&sessions, &key, &leaf, BPF_EXIST);
				bpf_ringbuf_submit(payload, BPF_RB_FORCE_WAKEUP);
				return XDP_DROP;
			}
			bpf_ringbuf_submit(payload, BPF_RB_FORCE_WAKEUP);
			return XDP_PASS;
		}
		bpf_ringbuf_submit(payload, BPF_RB_FORCE_WAKEUP);
	}
	return XDP_PASS;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";
