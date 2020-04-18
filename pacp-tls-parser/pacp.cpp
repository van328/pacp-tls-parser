#include "pch.h"
#define _CRT_SECURE_NO_WARNINGS
#include "pacp.h"

uint8 packets[MAX_NUM_PACKETS][MAX_PACKET_SIZE];
uint32 g_flow_id = 0;
struct ip_info_s *ip_infos = NULL;
uint32 num_ip_info_elements = 0;
struct flow_s *list_of_flows = NULL;
struct flow_s *table[MAX_HASH_LENGTH];
struct counters cnt;

struct ip_info_s *
	find_ip(uint32 ip)
{
	struct ip_info_s *tmp;

	tmp = ip_infos;
	while (tmp != NULL) {
		if (ip == tmp->ip_addr) {
			return (tmp);
		}
		tmp = tmp->next;
	}
	return (NULL);
}
void add_to_ip_list(struct ip_info_s * f)
{
	f->next = ip_infos;
	ip_infos = f;
	num_ip_info_elements++;
}


void print_global_hdr(struct pcap_hdr_s *p_hdr)
{
	printf("magic number = %x\n", p_hdr->magic_number);
	printf("version_major = %u\n", p_hdr->version_major);
	printf("version_minor = %u\n", p_hdr->version_minor);
	printf("thiszone = %d\n", p_hdr->thiszone);
	printf("sigfigs = %u\n", p_hdr->sigfigs);
	printf("snaplen = %u\n", p_hdr->snaplen);
	printf("network = %u\n", p_hdr->network);
}


void copy_bytes(void *_from, void *_to, int num)
{
	int i;
	uint8 *from = (uint8 *)_from;
	uint8 *to = (uint8 *)_to;

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

void print_counters(struct counters *c)
{
	printf("number non ethernet = %u\n", c->non_eth);
	printf("number of ip packets = %u\n", c->num_ip_pkts);
	printf("num ipv6 packets = %u\n", c->num_ipv6_pkts);
	printf("num arp packets = %u\n", c->num_arp_pkts);
	printf("number icmp packets = %u\n", c->num_icmp_pkts);
	printf("number udp packets = %u\n", c->num_udp_pkts);
	printf("number tcp packets = %u\n", c->num_tcp_pkts);
	printf("number non tcp udp or icmp packets %u\n", c->num_not_tcp_udp_icmp_pkts);
}


unsigned short _short_switcher(unsigned short *x)
{
	char *p;
	char *p2;
	char temp;

	p = (char *)x;
	p2 = p + 1;
	temp = *p;
	*p = *p2;
	*p2 = temp;
	return (*x);
}

unsigned int _int_switcher(unsigned int *x)
{
	char *b1;
	char temp;

	b1 = (char *)x;
	temp = *b1;
	*b1 = *(b1 + 3);
	*(b1 + 3) = temp;

	temp = *(b1 + 1);
	*(b1 + 1) = *(b1 + 2);
	*(b1 + 2) = temp;
	return (*x);
}




void add_to_list(struct flow_s *f)
{
	f->next = list_of_flows;
	list_of_flows = f;
}

struct flow_s *
	find_flow1(uint32 src_ip, uint32 dst_ip, uint16 src_port, uint16 dst_port, uint32 seq_num)
{
	struct flow_s *tmp;
	tmp = list_of_flows;

	while (tmp != NULL) {
		if (((tmp->src_ip == src_ip) && (tmp->dst_ip == dst_ip) &&
			(tmp->src_port == src_port) && (tmp->dst_port == dst_port))
			|| ((tmp->src_ip == dst_ip) && (tmp->dst_ip == src_ip) && (tmp->src_port == dst_port) &&
			(tmp->dst_port == src_port))) {
			return (tmp);
		}
		tmp = tmp->next;
	}
	return (NULL);
}

void
conv_ip_to_str(char *str, uint32 ip)
{
	sprintf(str, "%u.%u.%u.%u",
		(ip & 0xff000000) >> 24,
		(ip & 0x00ff0000) >> 16,
		(ip & 0x0000ff00) >> 8,
		(ip & 0x000000ff));
}

void
print_dotted_ips(uint32 *ip)
{
	int tmp = 0;
	tmp = (*ip & 0xff000000) >> 24;
	printf("%d.", tmp);
	tmp = (*ip & 0x00ff0000) >> 16;
	printf("%d.", tmp);
	tmp = (*ip & 0x0000ff00) >> 8;
	printf("%d.", tmp);
	tmp = (*ip & 0x000000ff);
	printf("%d", tmp);
}

void
print_hash_table_flows()
{
	int i;
	int counter = 0;
	struct flow_s *tmp;

	for (i = 0; i < MAX_HASH_LENGTH; i++) {
		tmp = table[i];
		while (tmp != NULL) {
			counter++;
			printf("-------------------------------------- ");
			printf("Flow %u\n", counter);
			printf("Source IP ");
			print_dotted_ips(&tmp->src_ip);
			printf("\n");
			printf("Dst IP ");
			print_dotted_ips(&tmp->dst_ip);
			printf("\n");
			printf("Source port %u\n", tmp->src_port);
			printf("dst port %u\n", tmp->dst_port);
			printf("num pkts %u\n", tmp->num_pkts);
			tmp = tmp->next;
		}
	}
}

void
print_flows()
{
	uint32 counter = 1;
	while (list_of_flows != NULL) {
		printf("-------------------------------------- ");
		printf("Flow %u\n", counter);
		printf("Source IP ");
		print_dotted_ips(&list_of_flows->src_ip);
		printf("\n");
		printf("Dst IP ");
		print_dotted_ips(&list_of_flows->dst_ip);
		printf("\n");
		printf("Source port %u\n", list_of_flows->src_port);
		printf("dst port %u\n", list_of_flows->dst_port);
		printf("num pkts %u\n", list_of_flows->num_pkts);
		list_of_flows = list_of_flows->next;
		counter++;
	}
}

// needs cleanup - different pcap files seem to have different timestamp resolution
static void
record_timestamp_and_seq_ack_nums(struct flow_s *flow, struct pcaprec_hdr_s *pkt_hdr,
	struct ipv4_hdr_s *ip_hdr, struct tcp_hdr_s *tcp_hdr)
{
	if (ip_hdr->src_ip == flow->dst_ip) {
		flow->dst_seq_nums[flow->num_pkts] = tcp_hdr->seq_num;
		if ((tcp_hdr->ofs_ctrl & 0x10) == 0x10) {
			flow->dst_ack_nums[flow->num_pkts] = tcp_hdr->ack_num;
		}
		flow->dst_timestamps[flow->num_pkts] = (((uint64)pkt_hdr->ts_sec) * 1000000LL) + (uint64)pkt_hdr->ts_usec;
	}
	else {
		flow->src_seq_nums[flow->num_pkts] = tcp_hdr->seq_num;
		if ((tcp_hdr->ofs_ctrl & 0x10) == 0x10) {
			flow->src_ack_nums[flow->num_pkts] = tcp_hdr->ack_num;
		}

		flow->src_timestamps[flow->num_pkts] = (uint64)pkt_hdr->ts_sec * 1000000;
		if (pkt_hdr->ts_usec > 1000000) {
			/* possibly nanosecond pcap file */
			flow->src_timestamps[flow->num_pkts] += (pkt_hdr->ts_usec / 1000);
		}
		else {
			flow->src_timestamps[flow->num_pkts] += pkt_hdr->ts_usec;
		}
	}
}

void add_to_hash_list(struct flow_s *f, struct flow_s **l)
{
	f->next = *l;
	*l = f;
}

void add_to_hash_table(struct flow_s *flow)
{
	uint32 x, y, num;

	x = (flow->src_ip) & 0x0000ffff;
	y = (flow->dst_ip) & 0x0000ffff;
	num = x + y;

	flow->flow_id = g_flow_id++;
	add_to_hash_list(flow, &table[num % MAX_HASH_LENGTH]);
}

int are_flows_equal(uint32 src_ip, uint32 dst_ip, struct flow_s *flow)
{
	if (((src_ip == flow->src_ip) && (dst_ip == flow->dst_ip)) || ((dst_ip == flow->src_ip) && (src_ip == flow->dst_ip))) {
		return (1);
	}
	return(0);
}

int spec_flow(uint32 src_ip, uint32 dst_ip, uint16 src_port, uint16 dst_port, struct flow_s *tmp)
{
	if (((tmp->src_ip == src_ip) && (tmp->dst_ip == dst_ip) &&
		(tmp->src_port == src_port) && (tmp->dst_port == dst_port))
		|| ((tmp->src_ip == dst_ip) && (tmp->dst_ip == src_ip) && (tmp->src_port == dst_port) && (tmp->dst_port == src_port))) {
		return(1);
	}
	return (0);
}

struct flow_s *
	search_hash_list_to_edit(uint32 src_ip, uint32 dst_ip, uint16 src_port, uint16 dst_port)
{
	uint32 x = (src_ip) & 0x0000ffff;
	uint32 y = (dst_ip) & 0x0000ffff;
	uint32 num = x + y;

	struct flow_s *tmp = table[num % MAX_HASH_LENGTH];

	while (tmp != NULL) {
		if (spec_flow(src_ip, dst_ip, src_port, dst_port, tmp)) {
			return (tmp);
		}
		tmp = tmp->next;
	}
	return NULL;
}

struct flow_s *
	search_hash_list(uint32 src_ip, uint32 dst_ip)
{
	uint32 x, y, num;
	x = (src_ip) & 0x0000ffff;
	y = (dst_ip) & 0x0000ffff;
	num = x + y;

	struct flow_s *hash_flow = table[num % MAX_HASH_LENGTH];
	struct flow_s *tmp = hash_flow;
	struct flow_s *return_list = NULL;
	struct flow_s *tmp2 = NULL;

	while (tmp != NULL) {
		if (are_flows_equal(src_ip, dst_ip, tmp)) {
			tmp2 = (struct flow_s *)malloc(sizeof(struct flow_s));
			*tmp2 = *tmp;
			add_to_hash_list(tmp2, &return_list);
		}
		tmp = tmp->next;
	}
	return (return_list);
}


int
parse_pcap_file(const char *input_file, const char *output_info, int debug)
{
	FILE *in_fd,*out_fd;
	int n, rc, size_of_data;
	struct pcap_hdr_s global_hdr;
	struct pcaprec_hdr_s pkt_hdr;
	struct ethernet_hdr_s *eth_hdr;
	struct ipv4_hdr_s *ip_hdr;
	struct tcp_hdr_s tcp_hdr;
	struct ip_info_s *ip_info;
	struct flow_s *f;
	uint8 dummy[16000];
	uint32 extra_read;
	//struct udp_hdr_s *udp_hdr; 
	//struct icmp_hdr_s *icmp_hdr; 


	memset(&cnt, 0, sizeof(cnt));


	in_fd = fopen(input_file, "rb");
	if (in_fd == NULL) {
		printf("error reading file %s\n", input_file);
		return -1;
	}
	out_fd = fopen(output_info, "a");
	if (out_fd == NULL) {
		printf("Open info file fail£¡\n");//fg
		return 0;
	}

	rc = fread(&global_hdr, sizeof(struct pcap_hdr_s), 1, in_fd);
	if (rc < 1) {
		printf("could not read global hdr\n");
		return -2;
	}

	if (debug) {
		printf("------------------------------------------------------------------------------------ \n");
		print_global_hdr(&global_hdr);
	}

	memset(table, 0, sizeof(table));

	n = 0;
	while (n < MAX_NUM_PACKETS) {
		rc = fread(&pkt_hdr, sizeof(struct pcaprec_hdr_s), 1, in_fd);
		if (rc < 1) {
			break;
		}

		if (pkt_hdr.incl_len > 1024) {
			if (debug) {
				printf("####### length of packet = %u\n", pkt_hdr.incl_len);
			}
			extra_read = pkt_hdr.incl_len - 1024;
			pkt_hdr.incl_len = 1024;
		}
		else {
			extra_read = 0;
		}

		rc = fread(packets[n], pkt_hdr.incl_len, 1, in_fd);
		if (rc < 1) {
			printf("NeedData..\n");
			break;
		}

		if (extra_read > 0) {
			rc = fread(dummy, extra_read, 1, in_fd);
			if (rc < 1) {
				printf("read extra_read fail..\n");

			}

		}

		eth_hdr = (struct ethernet_hdr_s *) packets[n];
		eth_hdr->type_length = _short_switcher(&eth_hdr->type_length);

		if (eth_hdr->type_length > 1500) {

			if (eth_hdr->type_length == 0x800) {  /* IPv4 Packet */

				cnt.num_ip_pkts++;

				ip_hdr = (struct ipv4_hdr_s *) (packets[n] + sizeof(struct ethernet_hdr_s));

				if (debug) {
					printf("ip packet %u ", cnt.num_ip_pkts);
				}

				_int_switcher(&ip_hdr->src_ip);
				_int_switcher(&ip_hdr->dst_ip);

				if (debug) {
					printf(" src ip ");
					print_dotted_ips(&ip_hdr->src_ip);
					printf(" dst ip ");
					print_dotted_ips(&ip_hdr->dst_ip);
					printf("\n");
				}

				size_of_data = _short_switcher(&ip_hdr->total_len);
				size_of_data = (size_of_data - sizeof(*ip_hdr) - sizeof(tcp_hdr) -
					sizeof(struct ethernet_hdr_s));

				ip_info = find_ip(ip_hdr->src_ip);
				if (ip_info == NULL) {
					ip_info = (struct ip_info_s *)malloc(sizeof(struct ip_info_s));
					ip_info->ip_addr = ip_hdr->src_ip;
					ip_info->num_pkts_sent = 0;
					ip_info->num_pkts_received = 0;
					ip_info->num_bytes_sent = 0;
					ip_info->num_bytes_received = 0;
					ip_info->next = NULL;
					add_to_ip_list(ip_info);
				}

				ip_info->num_pkts_sent++;
				ip_info->num_bytes_sent += size_of_data;

				ip_info = find_ip(ip_hdr->dst_ip);
				if (ip_info == NULL) {
					ip_info = (struct ip_info_s *)malloc(sizeof(struct ip_info_s));
					ip_info->ip_addr = ip_hdr->dst_ip;
					ip_info->num_pkts_sent = 0;
					ip_info->num_pkts_received = 0;
					ip_info->num_bytes_sent = 0;
					ip_info->num_bytes_received = 0;
					ip_info->next = NULL;
					add_to_ip_list(ip_info);
				}

				ip_info->num_pkts_received++;
				ip_info->num_bytes_received += size_of_data;
				//fg
				//printf("pkt_hdr.incl_len=%d\n", pkt_hdr.incl_len);
				//printf("sizeof(*eth_hdr)=%d\n", sizeof(*eth_hdr));
				//printf("sizeof(*ip_hdr)=%d\n", sizeof(*ip_hdr));
				//printf("sizeof(tcp_hdr)=%d\n", sizeof(tcp_hdr));
				int load_size = pkt_hdr.incl_len - sizeof(*eth_hdr) - sizeof(*ip_hdr) - sizeof(tcp_hdr);
				//printf("load_size=%d\n", load_size);
				unsigned char *buf = (unsigned char*)malloc(load_size);

				switch (ip_hdr->proto) {

				case 6: /* TCP */

					cnt.num_tcp_pkts++;

					copy_bytes(packets[n] + sizeof(*eth_hdr) + sizeof(*ip_hdr), &tcp_hdr, sizeof(tcp_hdr));
					
					if (load_size > 0) {
						memcpy(buf, packets[n] + sizeof(*eth_hdr) + sizeof(*ip_hdr)+ sizeof(tcp_hdr),load_size);

				/*		unsigned char ch;
						for(int i = 0; i < load_size; i++) {
							ch = *(buf + i*sizeof(char));
							printf("%02x ", ch);
						}
						printf("\n");*/
						int err = handlePacket(buf, load_size, out_fd);///tls
						/*if (!err) {
							printf("\n[OK]: Finished parsing of message!\n");
						}
						else
							printf("\n[NOT OK]: err = %d!\n", err);*/

					}

					_short_switcher(&tcp_hdr.ofs_ctrl);
					_int_switcher(&tcp_hdr.seq_num);
					_int_switcher(&tcp_hdr.ack_num);

					tcp_hdr.src_port = _short_switcher(&tcp_hdr.src_port);
					tcp_hdr.dst_port = _short_switcher(&tcp_hdr.dst_port);

					f = search_hash_list_to_edit(ip_hdr->src_ip, ip_hdr->dst_ip,
						tcp_hdr.src_port, tcp_hdr.dst_port);

					if ((tcp_hdr.ofs_ctrl & 0x02) == 0x02) {
						/* syn + syn ack */
						if (f == NULL || f->closed == 1) {
							/* if f == NULL assume that this is first syn pkt */
							f = (struct flow_s *)malloc(sizeof(struct flow_s));
							f->src_ip = ip_hdr->src_ip;
							f->dst_ip = ip_hdr->dst_ip;

							f->src_port = 0;
							f->dst_port = 0;
							f->src_port = tcp_hdr.src_port;
							f->dst_port = tcp_hdr.dst_port;
							f->seq_num = tcp_hdr.seq_num;
							f->num_pkts = 0;
							f->packets[f->num_pkts] = n;

							record_timestamp_and_seq_ack_nums(f, &pkt_hdr, ip_hdr, &tcp_hdr);

							f->num_pkts++;
							f->next = NULL;

							add_to_hash_table(f);
							cnt.num_tcp_flows++;
						}
						else {
							/* this could be retransmission of syn pkt */
							/* or syn+ack */

							f->packets[f->num_pkts] = n;
							f->num_pkts++;

							record_timestamp_and_seq_ack_nums(f, &pkt_hdr, ip_hdr, &tcp_hdr);
						}
					}
					else if ((tcp_hdr.ofs_ctrl & 0x01) == 0x01) {
						if (f != NULL) {
							f->packets[f->num_pkts] = n;
							f->num_pkts++;
							record_timestamp_and_seq_ack_nums(f, &pkt_hdr, ip_hdr, &tcp_hdr);
							f->closed = 1;
						}
					}
					else {
						if (f != NULL) {
							f->packets[f->num_pkts] = n;
							f->num_pkts++;
							record_timestamp_and_seq_ack_nums(f, &pkt_hdr, ip_hdr, &tcp_hdr);
						}
					}
					break;

				case 17:
					cnt.num_udp_pkts++;
					//copy_bytes(packet+sizeof(eth_hdr) + sizeof(ip_hdr), &udp_hdr, sizeof(udp_hdr));
					break;

				case 1:
					cnt.num_icmp_pkts++;
					//copy_bytes(packet+sizeof(eth_hdr) + sizeof(ip_hdr), &icmp_hdr, sizeof(icmp_hdr));
					break;

				default:
					cnt.num_not_tcp_udp_icmp_pkts++;

				}
				//fg
				if (buf) {
					free(buf);
				}
			}
			else if (eth_hdr->type_length == 0x86dd) {
				cnt.num_ipv6_pkts++;
			}
			else if (eth_hdr->type_length == 0x806) {
				cnt.num_arp_pkts++;
			}
		}
		else {
			cnt.non_eth++;
		}

		n++;
	}

	if (debug) {
		printf("num pkts read = %d\n", n);
		print_counters(&cnt);
	}

	fclose(in_fd);

	if (debug) {
		printf("Printing hash table...\n");
		print_hash_table_flows();
		printf("------------------------------------------------------------------------------------\n");
	}

	return 0;
}