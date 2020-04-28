#pragma once
//#define _CRT_SECURE_NO_WARNINGS
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
//#include <sys/uio.h>
//#include <unistd.h>
#include <fcntl.h>
#include <string.h>



typedef unsigned char mac_addr_t[6];


#define MAX_HASH_LENGTH  131072
#define MAX_NUM_PACKETS  10000//0//0
//#define MAX_FLOWS  100
#define MAX_PACKET_SIZE 1600// 1024
#define MAX_LOAD_SIZE 1400//1460// 1024
//type



struct pcap_hdr_s {
	uint32_t magic_number;   /* magic number */
	uint16_t version_major;  /* major version number */
	uint16_t version_minor;  /* minor version number */
	int32_t  thiszone;       /* GMT to local correction */
	uint32_t sigfigs;        /* accuracy of timestamps */
	uint32_t snaplen;        /* max length of captured packets, in bytes */
	uint32_t network;        /* data link type */
};

struct pcaprec_hdr_s {
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
	uint32_t incl_len;       /* number of octets of packet saved in file */
	uint32_t orig_len;       /* actual length of packet */
};

struct ethernet_hdr_s {
	mac_addr_t dst_mac;
	mac_addr_t src_mac;
	uint16_t type_length;  /* NETWORK ORDER */
};

struct ipv4_hdr_s {
	uint8_t vers_hdrlen;
	uint8_t dscp_ecn;
	uint16_t total_len;         /* NETWORK ORDER */
	uint16_t identification;         /* NETWORK ORDER */
	uint16_t flags_frag_ofs;        /* NETWORK ORDER */
	uint8_t ttl;
	uint8_t proto;
	uint16_t hdr_checksum;         /* NETWORK ORDER */
	uint32_t src_ip;         /* NETWORK ORDER */
	uint32_t dst_ip;         /* NETWORK ORDER */
};

struct tcp_hdr_s {
	uint16_t src_port;        /* NETWORK ORDER */
	uint16_t dst_port;         /* NETWORK ORDER */
	uint32_t seq_num;         /* NETWORK ORDER */
	uint32_t ack_num;        /* NETWORK ORDER */
	uint16_t ofs_ctrl;        /* NETWORK ORDER */
	uint16_t window_size;         /* NETWORK ORDER */
	uint16_t checksum;         /* NETWORK ORDER */
	uint16_t urgent_pointer;         /* NETWORK ORDER */
};

struct udp_hdr_s {
	uint16_t src_port;        /* NETWORK ORDER */
	uint16_t dst_port;         /* NETWORK ORDER */
	uint16_t total_len;        /* NETWORK ORDER */
	uint16_t checksum;         /* NETWORK ORDER */
};

struct icmp_hdr_s {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;  /* NETWORK ORDER */
};


struct counters {
	uint32_t num_tcp_flows;
	uint32_t num_ipsec_flows;
	uint32_t non_eth;
	uint32_t num_ip_pkts;
	/*	uint32_t num_not_ip_pkts; */
	uint32_t num_icmp_pkts;
	uint32_t num_udp_pkts;
	uint32_t num_tcp_pkts;
	uint32_t num_esp_pkts;
	uint32_t num_not_tcp_udp_icmp_esp_pkts;
	uint32_t num_ipv6_pkts;
	uint32_t num_arp_pkts;
	uint32_t num_isakmp_pkts;
	
};

//struct tcp_flow_s {
//	uint32_t flow_id;
//	uint32_t src_ip;
//	uint32_t dst_ip;
//	uint16_t src_port;
//	uint16_t dst_port;
//	uint32_t num_pkts;
//	uint32_t seq_num;
//	uint8_t is_open;
//	uint32_t num_bytes1; /* from initiator */
//	uint32_t num_bytes2; /* from responder */
//	uint32_t start_time; /* first syn */
//	uint32_t end_time; /* fin_ack or ack */
//	uint8_t closed;
//	uint32_t num_init_pkts;
//	uint32_t num_resp_pkts;
//	uint64_t src_timestamps[MAX_NUM_PACKETS]; /* timestamps on pkts from initiator i.e. who sent first syn */
//	uint64_t dst_timestamps[MAX_NUM_PACKETS]; /* timestamps on pkts from responder */
//	uint32_t src_seq_nums[MAX_NUM_PACKETS];
//	uint32_t src_ack_nums[MAX_NUM_PACKETS];
//	uint32_t dst_seq_nums[MAX_NUM_PACKETS];
//	uint32_t dst_ack_nums[MAX_NUM_PACKETS];
//	uint32_t packets[MAX_NUM_PACKETS];
//	//FILE* fd;
//	//uint32_t miss_len; //unused
//	uint8_t isgmtls;
//	uint8_t istls;
//	struct tcp_flow_s *next;
//};



/*
*
*output_info1:tls
*output_info2:ipsec 
s*/
int parse_pcap_file(const char *input_file,  int debug);
