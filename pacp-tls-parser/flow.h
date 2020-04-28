#pragma once
#include "pcap.h"
#include <stdint.h>



class IP_Flow   //基类的声明
{
public:
	uint32_t m_flow_id;
	uint32_t m_src_ip;
	uint32_t m_dst_ip;
	uint32_t m_num_pkts;
	uint32_t num_init_pkts;
	uint32_t num_resp_pkts;
	uint64_t src_timestamps[MAX_NUM_PACKETS]; /* timestamps on pkts from initiator i.e. who sent first syn */
	uint64_t dst_timestamps[MAX_NUM_PACKETS]; /* timestamps on pkts from responder */

	uint32_t m_packets[MAX_NUM_PACKETS];

	IP_Flow* next;

	IP_Flow()
	{
		m_num_pkts = 0;
		next = NULL;

	}

	//IP_Flow(uint32_t src_ip, uint32_t dst_ip)
	//{
	//	m_num_pkts = 0;
	//	next = NULL;
	//	m_src_ip = src_ip;
	//	m_dst_ip = dst_ip;
	//}
	void init(uint32_t src_ip, uint32_t dst_ip)
	{
		m_src_ip = src_ip;
		m_dst_ip = dst_ip;
	}
	void add_packet(int n)
	{
		m_packets[m_num_pkts++] = n;
	}

private:

};



class TCP_Flow :public IP_Flow
{
public:

	uint16_t m_src_port;
	uint16_t m_dst_port;
	uint32_t m_src_seq_nums[MAX_NUM_PACKETS];
	uint32_t m_src_ack_nums[MAX_NUM_PACKETS];
	uint32_t m_dst_seq_nums[MAX_NUM_PACKETS];
	uint32_t m_dst_ack_nums[MAX_NUM_PACKETS];
	uint8_t isgmtls;
	uint8_t istls;
	uint32_t m_seq_num;
	//uint8_t is_open;
	uint8_t closed;
	//uint32_t m_num_bytes1; /* from initiator */
	//uint32_t m_num_bytes2; /* from responder */
	uint32_t start_time; /* first syn */
	uint32_t end_time; /* fin_ack or ack */
	TCP_Flow() {
		closed = 0;
		isgmtls = 0;
		istls = 0;
	};
	//TCP_Flow(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint32_t seq_num) :
	//	m_src_port(src_port), m_dst_port(dst_port), m_seq_num(seq_num), IP_Flow(src_ip, dst_ip)
	//{
	//	closed = 0;
	//	isgmtls = 0;
	//	istls = 0;
	//}
	void init(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint32_t seq_num)
	{
		m_src_ip = src_ip;
		m_dst_ip = dst_ip;
		m_src_port = src_port;
		m_dst_port = dst_port;
		m_seq_num = seq_num;

		closed = 0;
		isgmtls = 0;
		istls = 0;
	}


	// needs cleanup - different pcap files seem to have different timestamp resolution  ??
	void
		record_timestamp_and_seq_ack_nums(struct pcaprec_hdr_s* pkt_hdr,
			struct ipv4_hdr_s* ip_hdr, struct tcp_hdr_s* tcp_hdr)
	{
		if (ip_hdr->src_ip == this->m_dst_ip) {
			this->m_dst_seq_nums[this->m_num_pkts] = tcp_hdr->seq_num;
			if ((tcp_hdr->ofs_ctrl & 0x10) == 0x10) {
				this->m_dst_ack_nums[this->m_num_pkts] = tcp_hdr->ack_num;
			}
			this->dst_timestamps[this->m_num_pkts] = (((uint64_t)pkt_hdr->ts_sec) * 1000000LL) + (uint64_t)pkt_hdr->ts_usec;
		}
		else {
			this->m_src_seq_nums[this->m_num_pkts] = tcp_hdr->seq_num;
			if ((tcp_hdr->ofs_ctrl & 0x10) == 0x10) {
				this->m_src_ack_nums[this->m_num_pkts] = tcp_hdr->ack_num;
			}

			this->src_timestamps[this->m_num_pkts] = (uint64_t)pkt_hdr->ts_sec * 1000000;
			if (pkt_hdr->ts_usec > 1000000) {
				/* possibly nanosecond pcap file */
				this->src_timestamps[this->m_num_pkts] += (pkt_hdr->ts_usec / 1000);
			}
			else {
				this->src_timestamps[this->m_num_pkts] += pkt_hdr->ts_usec;
			}
		}
	}
private:
};

#define IP_FLOW 0
#define TCP_FLOW 1


extern TCP_Flow* list_of_tcp_flows;
extern TCP_Flow* tls_flow_table[];
extern IP_Flow* ipsec_flow_table[];
extern TCP_Flow* accroding_flow[];

extern uint32_t g_tls_flow_id ;
extern uint32_t g_ipsec_flow_id ;





void add_to_tcp_list(TCP_Flow* f)
{
	f->next = list_of_tcp_flows;
	list_of_tcp_flows = f;
}


void add_to_hash_list(IP_Flow* f, IP_Flow** l)
{
	f->next = *l;
	*l = f;
}

void add_to_hash_table(IP_Flow* flow, int flow_type)
{
	uint32_t x, y, num;

	x = (flow->m_src_ip) & 0x0000ffff;
	y = (flow->m_dst_ip) & 0x0000ffff;
	num = x + y;

	if (flow_type == IP_FLOW) {
		flow->m_flow_id = g_ipsec_flow_id++;
		add_to_hash_list(flow, &ipsec_flow_table[num % MAX_HASH_LENGTH]);
	}
	else if (flow_type == TCP_FLOW) {
		flow->m_flow_id = g_tls_flow_id++;
		add_to_hash_list(flow, (IP_Flow**)&tls_flow_table[num % MAX_HASH_LENGTH]);
	}
	else {
		printf("err: wrong flow type!");
	}

}

TCP_Flow*
find_tcp_flow(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint32_t seq_num)
{
	TCP_Flow* tmp;
	tmp = list_of_tcp_flows;

	while (tmp != NULL) {
		if (((tmp->m_src_ip == src_ip) && (tmp->m_dst_ip == dst_ip) &&
			(tmp->m_src_port == src_port) && (tmp->m_dst_port == dst_port))
			|| ((tmp->m_src_ip == dst_ip) && (tmp->m_dst_ip == src_ip) && (tmp->m_src_port == dst_port) &&
				(tmp->m_dst_port == src_port))) {
			return (tmp);
		}
		tmp = (TCP_Flow*)tmp->next;
	}
	return (NULL);
}



int spec_tcp_flow(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, TCP_Flow* tmp)
{
	if (((tmp->m_src_ip == src_ip) && (tmp->m_dst_ip == dst_ip) &&
		(tmp->m_src_port == src_port) && (tmp->m_dst_port == dst_port))
		|| ((tmp->m_src_ip == dst_ip) && (tmp->m_dst_ip == src_ip) && (tmp->m_src_port == dst_port) && (tmp->m_dst_port == src_port))) {
		return(1);
	}
	return (0);
}

TCP_Flow*
search_tcp_hash_list_to_edit(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port)
{
	uint32_t x = (src_ip) & 0x0000ffff;
	uint32_t y = (dst_ip) & 0x0000ffff;
	uint32_t num = x + y;

	TCP_Flow* tmp = tls_flow_table[num % MAX_HASH_LENGTH];

	while (tmp != NULL) {
		if (spec_tcp_flow(src_ip, dst_ip, src_port, dst_port, tmp)) {  // && (tmp->closed == 0)
			return (tmp);
		}
		tmp = (TCP_Flow*)tmp->next;
	}
	return NULL;
}




int are_flows_equal(uint32_t src_ip, uint32_t dst_ip, IP_Flow* flow)
{
	if (((src_ip == flow->m_src_ip) && (dst_ip == flow->m_dst_ip)) || ((dst_ip == flow->m_src_ip) && (src_ip == flow->m_dst_ip))) {
		return (1);
	}
	return(0);
}
IP_Flow*
search_IP_hash_list(uint32_t src_ip, uint32_t dst_ip)
{
	uint32_t x, y, num;
	x = (src_ip) & 0x0000ffff;
	y = (dst_ip) & 0x0000ffff;
	num = x + y;

	IP_Flow* f = ipsec_flow_table[num % MAX_HASH_LENGTH];

	while (f != NULL) {
		if (are_flows_equal(src_ip, dst_ip, f)) {
			return f;
		}
		else {
			f = f->next;
		}

	}
	return (f);
}