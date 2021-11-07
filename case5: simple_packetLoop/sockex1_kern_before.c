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
//creating a map that stores first 4 bytes of application payload for tcp and udp packets
struct bpf_map_def SEC("maps") my_map7 = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(u32),
        .value_size = sizeof(long),
        .max_entries = 65536,
}; 
SEC("socket1")
int bpf_prog1(struct __sk_buff *skb)
{

	for(int i = 0; i < skb->len; i++){
		char a = load_byte(skb, i);
                const char data[] = "%x ";
                bpf_trace_printk(data, sizeof(data), a);	

	}
	
	return 0;
}
char _license[] SEC("license") = "GPL";
