#define TC_ACT_UNSPEC       (-1)
#define TC_ACT_OK		    0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		    2

#define ETH_P_IP	0x0800
#define ICMP_PING 8

#define ETH_ALEN 6
#define ETH_HLEN 14

#define IP_SRC_OFF (ETH_HLEN + offsetof(struct iphdr, saddr))
#define IP_DST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))

#define ICMP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))
#define ICMP_TYPE_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, type))
#define ICMP_CSUM_SIZE sizeof(__u16)

// Returns the protocol byte for an IP packet, 0 for anything else
// static __always_inline unsigned char lookup_protocol(struct xdp_md *ctx)

bool ipChecks(void *data, void *data_end, struct ethhdr *eth){
	if (data + sizeof(struct ethhdr) > data_end)
		return false;

	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return false;

	return true;
}

//Assumes that it is a ip packet
bool tcpChecks(void *data, void *data_end, struct ethhdr *eth, struct iphdr *iph){
	if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
		return false;

	if (iph->protocol != IPPROTO_TCP)
		return false;

	return true;
}

unsigned char lookup_protocol(void *data, void *data_end){
    unsigned char protocol = 0;
    struct ethhdr *eth = data;

    // Check that it's an IP packet
    if (ipChecks(data, data_end, eth))
    {
        // Return the protocol of this packet
        // 1 = ICMP
        // 6 = TCP
        // 17 = UDP
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end)
            protocol = iph->protocol;
    }
    return protocol;
}


int tcp_lookup_port(void *data, void *data_end){
	int port = 0;
	struct ethhdr *eth = data;

	// Check that it's an IP packet
	if (ipChecks(data, data_end, eth))
	{
        	// Return the protocol of this packet
        	// 1 = ICMP
        	// 6 = TCP
        	// 17 = UDP
		struct iphdr *iph = data + sizeof(struct ethhdr);
		if (tcpChecks(data, data_end, eth, iph)){
			struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
			if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) <= data_end)
				port = bpf_ntohs(tcp->dest);
		}
	}
	return port;
}

unsigned int lookup_src_addr(void *data, void *data_end){
	unsigned int srcAddr = 0;
        struct ethhdr *eth = data;

	if (ipChecks(data, data_end, eth)){
		struct iphdr *iph = data + sizeof(struct ethhdr);
		if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end)
				srcAddr = iph->saddr;
	}
	return srcAddr;
}


