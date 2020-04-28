#pragma once
//#define _CRT_SECURE_NO_WARNINGS
#include <string>
#include <iostream>

#include"pcap.h"
#include"flow.h"


using namespace std;
uint32_t num_ip_info_elements = 0;

extern const char* output_folder1;
extern const char* output_folder2;



struct ip_info_s {
	uint32_t ip_addr;
	uint32_t num_pkts_sent;
	uint32_t num_pkts_received;
	uint32_t num_bytes_sent;
	uint32_t num_bytes_received;
	struct ip_info_s* next;

};


struct ip_info_s* ip_infos = NULL;

struct ip_info_s*
	find_ip(uint32_t ip)
{
	struct ip_info_s* tmp;

	tmp = ip_infos;
	while (tmp != NULL) {
		if (ip == tmp->ip_addr) {
			return (tmp);
		}
		tmp = tmp->next;
	}
	return (NULL);
}


void add_to_ip_list(ip_info_s* f)
{
	f->next = ip_infos;
	ip_infos = f;
	num_ip_info_elements++;
}


void get_output_file_name(char * file_name,int n, int flow_type) {
	//char file_name[25];
	if (flow_type == TCP_FLOW) {
		strcpy(file_name, output_folder1);
		strcat(file_name, "tcp_flow");

	}
	else if (flow_type == IP_FLOW) {
		strcpy(file_name, output_folder2);
		strcat(file_name, "ipsec_flow");
	}
	else {
		printf("get_file_name err : wrong flow type!");
	}
	char number[10];
	_itoa(n, number, 10);
	strcat(file_name, number);
	strcat(file_name, ".txt");
	//return  file_name;
}



void print_global_hdr(struct pcap_hdr_s* p_hdr)
{
	printf("magic number = %x\n", p_hdr->magic_number);
	printf("version_major = %u\n", p_hdr->version_major);
	printf("version_minor = %u\n", p_hdr->version_minor);
	printf("thiszone = %d\n", p_hdr->thiszone);
	printf("sigfigs = %u\n", p_hdr->sigfigs);
	printf("snaplen = %u\n", p_hdr->snaplen);
	printf("network = %u\n", p_hdr->network);
	printf("\n");
}


void copy_bytes(void* _from, void* _to, int num)
{
	int i;
	uint8_t* from = (uint8_t*)_from;
	uint8_t* to = (uint8_t*)_to;

	for (i = 0; i < num; i++) {
		to[i] = from[i];
	}
#if 0
	while (i < num)
		*to = *from;
	to = to + 1;
	from = from + 1;
	i++;
#endif
}

void print_counters(struct counters* c)
{
	printf("number non ethernet = %u\n", c->non_eth);
	printf("number ip packets = %u\n", c->num_ip_pkts);
	printf("num ipv6 packets = %u\n", c->num_ipv6_pkts);
	printf("num arp packets = %u\n", c->num_arp_pkts);
	printf("number icmp packets = %u\n", c->num_icmp_pkts);
	printf("number udp packets = %u\n", c->num_udp_pkts);
	printf("number tcp packets = %u\n", c->num_tcp_pkts);
	printf("number esp packets = %u\n", c->num_esp_pkts);
	printf("number isakmp packets %u\n", c->num_isakmp_pkts);
	printf("number non tcp udp or icmp packets %u\n", c->num_not_tcp_udp_icmp_esp_pkts);
	printf("\nnumber ipsec flows = %u\n", c->num_ipsec_flows);
	printf("number tls flows = %u\n", c->num_tls_flows);
}




void
print_tcp_flows(TCP_Flow* tmp)
{
	printf("\n-------------------------------------- ");
	printf("TCP Flow %u-------------------------------------\n", tmp->m_flow_id);
	printf("Pakets Number:");
	for (int j = 0; j < tmp->m_num_pkts; j++) {
		printf(" %d ", tmp->m_packets[j] + 1);
	}
	printf(" \n");
	printf("Source IP ");
	print_dotted_ips(&tmp->m_src_ip);
	printf("\n");
	printf("Dst IP ");
	print_dotted_ips(&tmp->m_dst_ip);
	printf("\n");
	printf("Source port %u\n", tmp->m_src_port);
	printf("Dst port %u\n", tmp->m_dst_port);
	printf("num pkts %u\n", tmp->m_num_pkts);
	printf("\n");

}
void
print_ipsec_flows(IP_Flow* tmp)
{
	printf("\n-------------------------------------- ");
	printf("Ipsec Flow %u-------------------------------------\n", tmp->m_flow_id);
	printf("Pakets Number:");
	for (int j = 0; j < tmp->m_num_pkts; j++) {
		printf(" %d ", tmp->m_packets[j] + 1);
	}
	printf(" \n");
	printf("Source IP ");
	print_dotted_ips(&tmp->m_src_ip);
	printf("\n");
	printf("Dst IP ");
	print_dotted_ips(&tmp->m_dst_ip);
	printf("\n");
	printf("num pkts %u\n", tmp->m_num_pkts);
	printf("\n");

}

string
return_dotted_ips(uint32_t* ip)
{
	string ret;
	char retchar[5];
	int tmp = 0;
	tmp = (*ip & 0xff000000) >> 24;
	sprintf(retchar, "%d.", tmp);
	ret += retchar;
	tmp = (*ip & 0x00ff0000) >> 16;
	sprintf(retchar, "%d.", tmp);
	ret += retchar;
	tmp = (*ip & 0x0000ff00) >> 8;
	sprintf(retchar, "%d.", tmp);
	ret += retchar;
	tmp = (*ip & 0x000000ff);
	sprintf(retchar, "%d", tmp);
	ret += retchar;
	return ret;
}

