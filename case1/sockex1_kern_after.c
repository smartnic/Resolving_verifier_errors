#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include "bpf_helpers.h"
#include <uapi/linux/tcp.h>
#include <uapi/linux/in.h>

struct bpf_map_def SEC("maps") my_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(u32),
	.value_size = sizeof(long),
	.max_entries = 256,
};
struct bpf_map_def SEC("maps") my_map2 = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(u32),
        .value_size = sizeof(long),
        .max_entries = 65536,
};

struct bpf_map_def SEC("maps") my_map3 = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(u32),
        .value_size = sizeof(long),
        .max_entries = 65536,
};
struct bpf_map_def SEC("maps") my_map4 = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(u32),
        .value_size = sizeof(long),
        .max_entries = 256,
};
struct bpf_map_def SEC("maps") my_map5 = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(u32),
        .value_size = sizeof(long),
        .max_entries = 65536,
};
struct bpf_map_def SEC("maps") my_map6 = {
        .type = BPF_MAP_TYPE_ARRAY,
        .key_size = sizeof(u32),
        .value_size = sizeof(long),
        .max_entries = 65536,
};

SEC("socket1")
int bpf_prog1(struct __sk_buff *skb)
{
	int index = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
	long *value;
	//char a = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));	
	int index2 = load_half(skb, offsetof(struct ethhdr, h_proto));
	long *value2;

	int index3 = load_half(skb, ETH_HLEN + offsetof(struct iphdr, id));
        long *value3;

	int index4 = load_byte(skb, ETH_HLEN);	

	long *value4;
 
	//Based on index4, calculate the value of the ip header length
	int ihl = index4 & 15;
	int ihl_bytes = ihl*4;
	
	int index5 = load_half(skb, ETH_HLEN + offsetof(struct iphdr, tot_len));
	long * value5;
	
	int index6 = 0;
	long * value6;
	if(index == IPPROTO_ICMP){

		index6 = load_byte(skb, ETH_HLEN+ihl_bytes+8);

	}	
	
 
	if (skb->pkt_type != PACKET_OUTGOING)
		return 0;

	value = bpf_map_lookup_elem(&my_map, &index);
	if (value)
		__sync_fetch_and_add(value, 1);
	

	value2 = bpf_map_lookup_elem(&my_map2, &index2);
        if (value2)
                __sync_fetch_and_add(value2, 1);
	
	value3 = bpf_map_lookup_elem(&my_map3, &index3);
        if (value3)
                __sync_fetch_and_add(value3, 1);	
	
	value4 = bpf_map_lookup_elem(&my_map4, &index4);
	if(value4)
		__sync_fetch_and_add(value4, 1);
		
	value5 = bpf_map_lookup_elem(&my_map5, &index5);
        if(value5)
                __sync_fetch_and_add(value5, 1);
	
	value6 = bpf_map_lookup_elem(&my_map6, &index6);
        if(value6)
                __sync_fetch_and_add(value6, 1);
	
	return 0;
}
char _license[] SEC("license") = "GPL";
