#pragma once
#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
//#include <sys/uio.h>
//#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include "tls.h"

typedef unsigned int uint32;
typedef unsigned short uint16;
typedef signed int int32;
typedef unsigned char uint8;
typedef unsigned long long uint64;
typedef unsigned char mac_addr_t[6];

#define MAX_HASH_LENGTH  131072 
#define MAX_NUM_PACKETS  1000000
#define MAX_PACKET_SIZE  1024


struct pcap_hdr_s {
	uint32 magic_number;   /* magic number */
	uint16 version_major;  /* major version number */
	uint16 version_minor;  /* minor version number */
	int32  thiszone;       /* GMT to local correction */
	uint32 sigfigs;        /* accuracy of timestamps */
	uint32 snaplen;        /* max length of captured packets, in bytes */
	uint32 network;        /* data link type */
};

struct pcaprec_hdr_s {
	uint32 ts_sec;         /* timestamp seconds */
	uint32 ts_usec;        /* timestamp microseconds */
	uint32 incl_len;       /* number of octets of packet saved in file */
	uint32 orig_len;       /* actual length of packet */
};

struct ethernet_hdr_s {
	mac_addr_t dst_mac;
	mac_addr_t src_mac;
	uint16 type_length;  /* NETWORK ORDER */
};

struct ipv4_hdr_s {
	uint8 vers_hdrlen;
	uint8 dscp_ecn;
	uint16 total_len;         /* NETWORK ORDER */
	uint16 identification;         /* NETWORK ORDER */
	uint16 flags_frag_ofs;        /* NETWORK ORDER */
	uint8 ttl;
	uint8 proto;
	uint16 hdr_checksum;         /* NETWORK ORDER */
	uint32 src_ip;         /* NETWORK ORDER */
	uint32 dst_ip;         /* NETWORK ORDER */
};

struct tcp_hdr_s {
	uint16 src_port;        /* NETWORK ORDER */
	uint16 dst_port;         /* NETWORK ORDER */
	uint32 seq_num;         /* NETWORK ORDER */
	uint32 ack_num;        /* NETWORK ORDER */
	uint16 ofs_ctrl;        /* NETWORK ORDER */
	uint16 window_size;         /* NETWORK ORDER */
	uint16 checksum;         /* NETWORK ORDER */
	uint16 urgent_pointer;         /* NETWORK ORDER */
};

struct udp_hdr_s {
	uint16 src_port;        /* NETWORK ORDER */
	uint16 dst_port;         /* NETWORK ORDER */
	uint16 total_len;        /* NETWORK ORDER */
	uint16 checksum;         /* NETWORK ORDER */
};

struct icmp_hdr_s {
	uint8 type;
	uint8 code;
	uint16 checksum;  /* NETWORK ORDER */
};


struct counters {
	uint32 num_tcp_flows;
	uint32 non_eth;
	uint32 num_ip_pkts;
	/*	uint32 num_not_ip_pkts; */
	uint32 num_icmp_pkts;
	uint32 num_udp_pkts;
	uint32 num_tcp_pkts;
	uint32 num_not_tcp_udp_icmp_pkts;
	uint32 num_ipv6_pkts;
	uint32 num_arp_pkts;
};

struct flow_s {
	uint32 flow_id;
	uint32 src_ip;
	uint32 dst_ip;
	uint16 src_port;
	uint16 dst_port;
	uint32 num_pkts;
	uint32 seq_num;
	uint8 is_open;
	uint32 num_bytes1; /* from initiator */
	uint32 num_bytes2; /* from responder */
	uint32 start_time; /* first syn */
	uint32 end_time; /* fin_ack or ack */
	uint8 closed;
	uint32 num_init_pkts;
	uint32 num_resp_pkts;
	uint64 src_timestamps[MAX_NUM_PACKETS]; /* timestamps on pkts from initiator i.e. who sent first syn */
	uint64 dst_timestamps[MAX_NUM_PACKETS]; /* timestamps on pkts from responder */
	uint32 src_seq_nums[MAX_NUM_PACKETS];
	uint32 src_ack_nums[MAX_NUM_PACKETS];
	uint32 dst_seq_nums[MAX_NUM_PACKETS];
	uint32 dst_ack_nums[MAX_NUM_PACKETS];
	uint32 packets[MAX_NUM_PACKETS];
	struct flow_s *next;
};

struct ip_info_s {
	uint32 ip_addr;
	uint32 num_pkts_sent;
	uint32 num_pkts_received;
	uint32 num_bytes_sent;
	uint32 num_bytes_received;
	struct ip_info_s *next;
};





int parse_pcap_file(const char *input_file, const char *output_info,  int debug);
