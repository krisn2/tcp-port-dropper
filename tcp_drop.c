#include <stdint.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "tcp_drop.h"

// License
char _license[] SEC("license") = "GPL";

// Maps
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PORTS);
    __type(key, struct port_key);
    __type(value, struct port_value);
} port_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} config_map SEC(".maps");

// Helper function to parse Ethernet header
static __always_inline int parse_eth(void *data, void *data_end, struct ethhdr **eth) {
    *eth = data;
    if ((void *)(*eth + 1) > data_end)
        return -1;
    return (*eth)->h_proto;
}

// Helper function to parse IP header
static __always_inline int parse_ip(void *data, void *data_end, struct iphdr **ip) {
    *ip = data;
    if ((void *)(*ip + 1) > data_end)
        return -1;
    
    // Check IP version
    if ((*ip)->version != 4)
        return -1;
    
    // Check header length
    if ((*ip)->ihl < 5)
        return -1;
        
    return (*ip)->protocol;
}

// Helper function to parse TCP header
static __always_inline int parse_tcp(void *data, void *data_end, struct tcphdr **tcp) {
    *tcp = data;
    if ((void *)(*tcp + 1) > data_end)
        return -1;
    return 0;
}

SEC("xdp")
int tcp_port_drop(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    
    // Get configuration
    __u32 config_key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config_map, &config_key);
    if (!cfg || !cfg->enabled) {
        return XDP_PASS;
    }
    
    // Parse Ethernet header
    int eth_type = parse_eth(data, data_end, &eth);
    if (eth_type < 0) {
        return XDP_PASS;
    }
    
    // Check if it's IPv4
    if (eth_type != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    
    // Parse IP header
    int ip_proto = parse_ip(data + sizeof(*eth), data_end, &ip);
    if (ip_proto < 0) {
        return XDP_PASS;
    }
    
    // Check if it's TCP
    if (ip_proto != IPPROTO_TCP) {
        return XDP_PASS;
    }
    
    // Parse TCP header
    void *tcp_data = data + sizeof(*eth) + (ip->ihl * 4);
    if (parse_tcp(tcp_data, data_end, &tcp) < 0) {
        return XDP_PASS;
    }
    
    // Get destination port
    __u16 dest_port = bpf_ntohs(tcp->dest);
    
    // Update statistics
    struct port_key key = { .port = dest_port };
    struct port_value *stats = bpf_map_lookup_elem(&port_stats, &key);
    
    if (!stats) {
        // Initialize new entry
        struct port_value new_stats = { .packet_count = 1, .drop_count = 0 };
        
        // Check if we should drop this port
        if (dest_port == cfg->target_port) {
            new_stats.drop_count = 1;
            bpf_map_update_elem(&port_stats, &key, &new_stats, BPF_ANY);
            return XDP_DROP;
        } else {
            bpf_map_update_elem(&port_stats, &key, &new_stats, BPF_ANY);
            return XDP_PASS;
        }
    } else {
        // Update existing entry
        stats->packet_count++;
        
        if (dest_port == cfg->target_port) {
            stats->drop_count++;
            return XDP_DROP;
        }
        
        return XDP_PASS;
    }
}
