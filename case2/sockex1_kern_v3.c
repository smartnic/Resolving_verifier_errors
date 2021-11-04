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
	
	char *data = (char *)(long)skb->data;
        char *data_end = (char *)(long)skb->data_end;	

	char tpc;	
	if ((data + ETH_HLEN + offsetof(struct iphdr, protocol)) < data_end)
		 tpc = *(data + ETH_HLEN + offsetof(struct iphdr, protocol));  
	else
		return 0;	
	/*
	int  tp = tpc;
  	
	char ihc = *(data + ETH_HLEN);
	int ih = ihc;
	//Based on ih, calculate the value of the ip header length
	int ihl = ih & 15;
	int ihl_bytes = ihl*4;
	
	offset_of_data += ihl_bytes;
	
	int totalLen = 0; 
	bpf_skb_load_bytes(skb, ETH_HLEN + offsetof(struct iphdr, tot_len), &totalLen, 2);	

	length_of_data = totalLen - ihl_bytes;	
		
	
	
	if(tp == IPPROTO_ICMP){
		const char str1[] = "ICMP PACKET\n";
		bpf_trace_printk(str1, sizeof(str1));	
		length_of_data -= 8;
		offset_of_data += 8;	
	}
		
	if(tp == IPPROTO_UDP){
		const char str1[] = "UDP PACKET\n";
		bpf_trace_printk(str1, sizeof(str1));   
		//UDP HEADER LENGTH: 8 BYTES	
		length_of_data -= 8;
		offset_of_data += 8;	
	}
		
	if(tp == IPPROTO_TCP){
		return 0;
	}
	

	
	
	//At this point length_of_data has the total length of the transport payload (application header + data)
	//offset_of_data has the offset from skb where the data (application header + data) starts	
	 
	if (skb->pkt_type != PACKET_OUTGOING)
		return 0;
	

	//goal: to print the length_of_data bytes from offset offset_of_data 
	const char str[] = "This is the data payload\n";

	bpf_trace_printk(str, sizeof(str));

	char * a = (data + offset_of_data);
	
	if(a<data_end){	
		int a_int = *(a);
        	if (a_int >= 32 && a_int <= 126){
               		const char data[] = "%c ";
               		bpf_trace_printk(data, sizeof(data), *(a));
        	} 
	}	
	*/	
	const char lstr[] = "\n\n";
	bpf_trace_printk(lstr, sizeof(lstr));	
	return 0;
}
char _license[] SEC("license") = "GPL";
