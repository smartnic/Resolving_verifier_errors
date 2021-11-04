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
	int offset_of_data = ETH_HLEN;	
	int length_of_data = 0;
	
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
	
	offset_of_data += ihl_bytes;	
	
	int index5 = load_half(skb, ETH_HLEN + offsetof(struct iphdr, tot_len));
	long * value5;

	length_of_data = index5 - ihl_bytes;
	
	int index6 = 0;
	long * value6;
	int gotValue6 = 0;	
	if(index == IPPROTO_ICMP){
		const char str1[] = "ICMP PACKET\n";
		bpf_trace_printk(str1, sizeof(str1));	
		index6 = load_byte(skb, ETH_HLEN+ihl_bytes+8);
		gotValue6 = 1;
		length_of_data -= 8;
		offset_of_data += 8;	
	}
		
	int index7 = 0;
	long * value7;
	int gotValue7 = 0;
	if(index == IPPROTO_UDP){
		const char str1[] = "UDP PACKET\n";
		bpf_trace_printk(str1, sizeof(str1));   
		//UDP HEADER LENGTH: 8 BYTES	
		index7 = load_word(skb, ETH_HLEN+ihl_bytes+8);
		gotValue7 = 1;	
		length_of_data -= 8;
		offset_of_data += 8;	
	}
		
	if(index == IPPROTO_TCP){
		const char str1[] = "TCP PACKET\n";
		bpf_trace_printk(str1, sizeof(str1));  	
		//get the tcp header length
		int tcp_byte_with_hlen = load_byte(skb, ETH_HLEN+ihl_bytes+12);
		int imt = tcp_byte_with_hlen >> 4; 
		int thl = imt & 15;
		int thl_bytes = thl*4;
		index7 = load_word(skb, ETH_HLEN+ihl_bytes+thl_bytes);  
		gotValue7 = 1;
		length_of_data -= thl_bytes;		
		offset_of_data += thl_bytes;	

	}


	//At this point length_of_data has the total length of the transport payload (application header + data)
	//offset_of_data has the offset from skb where the data (application header + data) starts	
	 
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

	if (gotValue6 == 1){	
		value6 = bpf_map_lookup_elem(&my_map6, &index6);
        	if(value6)
                	__sync_fetch_and_add(value6, 1);
	}
	
	if (gotValue7 == 1){ 
		value7 = bpf_map_lookup_elem(&my_map7, &index7);
        	long value7default = 1; 
		if(value7)
               		 __sync_fetch_and_add(value7, 1);
		else
			bpf_map_update_elem(&my_map7, &index7, &value7default, BPF_NOEXIST);		
	}

	//goal: to print the length_of_data bytes from offset offset_of_data 

	const char params[] = "Length of data = %d.\n";
	bpf_trace_printk(params, sizeof(params), length_of_data);
	
	const char str[] = "This is the data payload\n";
	bpf_trace_printk(str, sizeof(str));
	
	int len = skb -> len;	
	/*	
	void * data;
	if(offset_of_data + length_of_data < len)	
		bpf_skb_load_bytes((void *)skb, offset_of_data, data, 56); 
       */	
	
	if(length_of_data > 200){
		return 0;

	}	
	

	//length_of_data &= 31;
	
	for (int i = 0; i < length_of_data; i++){ 
		
		char a = load_byte(skb, offset_of_data+i); 
		int a_int = a;
		const char data[] = "%x ";
		bpf_trace_printk(data, sizeof(data), a);
        	
	}
	

	

	
	const char lstr[] = "\n\n";
	bpf_trace_printk(lstr, sizeof(lstr));	
	return 0;
}
char _license[] SEC("license") = "GPL";
