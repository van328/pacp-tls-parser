#include "pch.h"
//#define _CRT_SECURE_NO_WARNINGS
#include "pcap.h"
#include "tls.h"
#include "ipsec.h"
#include "utils.h"
#include "flow.h"

#include <string>
#include <iostream>

using namespace std;

uint8_t packets[MAX_NUM_PACKETS][MAX_PACKET_SIZE];
struct counters cnt;

extern TCP_Flow* list_of_tcp_flows;
extern TCP_Flow* tls_flow_table[];
extern IP_Flow* ipsec_flow_table[];
extern TCP_Flow* accroding_flow[];


int is_padding(int n, int pkt_len, int loadsize) {
	if (loadsize > 30)
		return 0;
	for (int i = 0; i < 2 && i < loadsize; i++) {
		int a = packets[n][sizeof(pcaprec_hdr_s) + pkt_len - loadsize + i];
		if (a != 0)
			return 0;
	}
	return 1;
}

void
print_tls_flow_hash_table()
{
	int i, j;
	//int counter = 0;
	TCP_Flow* tmp;

	for (i = 0; i < MAX_HASH_LENGTH; i++) {
		tmp = tls_flow_table[i];
		while (tmp != NULL) {

			print_tcp_flows(tmp);

			if (tmp->isgmtls || tmp->istls) {
				char file_name[35];
				get_output_file_name(file_name, tmp->m_flow_id, TCP_FLOW);
				FILE* out_fd = fopen(file_name, "w");
				if (out_fd == NULL) {
					printf("Open txt file fail！\n");//fg
				}
				else {
					fprintf(out_fd, "--------TCP Flow %u----------\n", tmp->m_flow_id);
				}
				struct pcaprec_hdr_s* pkt_hdr;
				struct tcp_hdr_s tcp_hdr;
				int load_size = 0;
				int last_load_size = 0;
				int err = 0;
				int pkt_sqc_num;
				uint8_t* buf = NULL;
				for (j = 0; j < tmp->m_num_pkts; j++) {
					pkt_sqc_num = tmp->m_packets[j];
					pkt_hdr = (pcaprec_hdr_s*)packets[pkt_sqc_num];
					copy_bytes(packets[pkt_sqc_num] + sizeof(pcaprec_hdr_s) + sizeof(ethernet_hdr_s) + sizeof(ipv4_hdr_s), &tcp_hdr, sizeof(tcp_hdr));
					_short_switcher(&tcp_hdr.ofs_ctrl);
					if ((tcp_hdr.ofs_ctrl & 0x03) != 0x00) { //syn or fins
						continue;
					}
					load_size = pkt_hdr->incl_len - sizeof(ethernet_hdr_s) - sizeof(ipv4_hdr_s) - sizeof(tcp_hdr_s);
					if (pkt_sqc_num == 45)
						int a = 0;
					if (load_size < 16)  //64-14-20-20=10
						if (is_padding(pkt_sqc_num, pkt_hdr->incl_len, load_size))  //maybe is ethernet padding  //to improve
							continue;
					if (load_size > MIN_RECORD_LAYER_SIZE) {
						if (last_load_size > MIN_RECORD_LAYER_SIZE)
						{
							if (buf)
								buf = (uint8_t*)realloc(buf, load_size + last_load_size);
							else
								printf("err,buf == NULL!");
						}
						else {
							buf = (uint8_t*)malloc(load_size);
						}
						memcpy(buf + last_load_size, packets[pkt_sqc_num] + sizeof(pcaprec_hdr_s) + sizeof(ethernet_hdr_s) + sizeof(ipv4_hdr_s) + sizeof(tcp_hdr_s), load_size);
						/*if (load_size >= MAX_LOAD_SIZE) {
							last_load_size += load_size;
							continue;
						}*/

						err = handleTLSPacket(buf, load_size + last_load_size, out_fd, 0);
						if (err == NEED_MORE) {
							last_load_size += load_size;
							continue;
						}
						if (err) {
							printf("handleTLSPacket: err = %d, pkt_sqc_num = %d.\n", err, pkt_sqc_num + 1);
						}
					}
					last_load_size = 0;
					if (buf) {
						free(buf);
						buf = NULL;
					}
				}
				if (out_fd)
					fclose(out_fd);
			}
			tmp = (TCP_Flow*)tmp->next;
		}
	}
}

void
print_ipsec_flow_hash_table()
{
	int i, j;
	//int counter = 0;
	IP_Flow* tmp;

	for (i = 0; i < MAX_HASH_LENGTH; i++) {
		tmp = ipsec_flow_table[i];
		while (tmp != NULL) {
			print_ipsec_flows(tmp);
			char file_name[35];
			get_output_file_name(file_name, tmp->m_flow_id, IP_FLOW);
			FILE* out_fd = fopen(file_name, "w");
			if (out_fd == NULL) {
				printf("Open txt file fail！\n");//fg
			}
			else {
				fprintf(out_fd, "--------IPSec Flow %u----------\n", tmp->m_flow_id);
			}
			struct pcaprec_hdr_s* pkt_hdr;
			int load_size = 0;
			int err = 0;
			int pkt_sqc_num;
			struct ipv4_hdr_s* ipv4_hdr;
			uint8_t* buf = NULL;

			for (j = 0; j < tmp->m_num_pkts; j++) {
				pkt_sqc_num = tmp->m_packets[j];
				pkt_hdr = (pcaprec_hdr_s*)packets[pkt_sqc_num];
				ipv4_hdr = (ipv4_hdr_s*)(packets[pkt_sqc_num] + sizeof(pcaprec_hdr_s) + sizeof(ethernet_hdr_s));
				if (ipv4_hdr->proto == 50) {//esp
					load_size = pkt_hdr->incl_len - sizeof(ethernet_hdr_s) - sizeof(ipv4_hdr_s);
					buf = (uint8_t*)malloc(load_size);
					memcpy(buf, packets[pkt_sqc_num] + sizeof(pcaprec_hdr_s) + sizeof(ethernet_hdr_s) + sizeof(ipv4_hdr_s), load_size);
					err = handleESPPacket(buf, load_size, out_fd, 0);
				}
				else if (ipv4_hdr->proto == 17) { //udp

					int b = sizeof(pcaprec_hdr_s) + sizeof(ethernet_hdr_s) + sizeof(ipv4_hdr_s) + sizeof(udp_hdr_s) + 17;
					int isakmp_type = isakmp_version_type(packets[pkt_sqc_num][b]);
					if (isakmp_type) {
						int load_size = pkt_hdr->incl_len - sizeof(ethernet_hdr_s) - sizeof(ipv4_hdr_s) - sizeof(udp_hdr_s);
						buf = (uint8_t*)malloc(load_size);
						memcpy(buf, packets[pkt_sqc_num] + sizeof(pcaprec_hdr_s) + sizeof(ethernet_hdr_s) + sizeof(ipv4_hdr_s) + sizeof(udp_hdr_s), load_size);
						err = handleISAKMPPacket(buf, load_size, out_fd, 0);
					}
				}
				if (buf) {
					free(buf);
					buf = NULL;
				}
			}
			if (out_fd)
				fclose(out_fd);

			tmp = (TCP_Flow*)tmp->next;
		}
	}
}


int
parse_pcap_file(const char* input_file, int debug)
{
	FILE* in_fd, * out_fd;
	int n, size_of_data;
	size_t rc;
	struct pcap_hdr_s global_hdr;
	struct pcaprec_hdr_s pkt_hdr;
	struct ethernet_hdr_s* eth_hdr;
	struct ipv4_hdr_s* ip_hdr;
	struct tcp_hdr_s tcp_hdr;
	struct ip_info_s* ip_info;
	struct udp_hdr_s udp_hdr;
	struct icmp_hdr_s* icmp_hdr;
	IP_Flow* ipsec_flow;
	uint8_t dummy[16000];
	uint32_t extra_read;
	const char* packet_type;
	string packet_addr;



	memset(&cnt, 0, sizeof(cnt));

	in_fd = fopen(input_file, "rb");
	if (in_fd == NULL) {
		printf("error reading file %s\n", input_file);
		return -1;
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

	n = 0;
	packet_type = "---";
	packet_addr = "";
	while (n < MAX_NUM_PACKETS) {
		rc = fread(&pkt_hdr, sizeof(struct pcaprec_hdr_s), 1, in_fd);
		if (rc < 1) {
			break;
		}

		if (pkt_hdr.incl_len > MAX_PACKET_SIZE) {
			if (0) {
				printf("####### length of packet = %u :\n", pkt_hdr.incl_len);
			}
			extra_read = pkt_hdr.incl_len - MAX_PACKET_SIZE;
			pkt_hdr.incl_len = MAX_PACKET_SIZE;
		}
		else {
			extra_read = 0;
		}

		memcpy(packets[n], &pkt_hdr, sizeof(pcaprec_hdr_s));

		rc = fread(packets[n] + sizeof(pcaprec_hdr_s), pkt_hdr.incl_len, 1, in_fd);
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

		eth_hdr = (struct ethernet_hdr_s*) (packets[n] + sizeof(pcaprec_hdr_s));
		eth_hdr->type_length = _short_switcher(&eth_hdr->type_length);

		if (eth_hdr->type_length > 1500) {

			if (eth_hdr->type_length == 0x800) {  /* IPv4 Packet */

				cnt.num_ip_pkts++;

				packet_type = "IPv4";

				ip_hdr = (struct ipv4_hdr_s*) (packets[n] + sizeof(pcaprec_hdr_s) + sizeof(struct ethernet_hdr_s));

				if (0) {
					printf("ip packet %u ", cnt.num_ip_pkts);
				}

				_int_switcher(&ip_hdr->src_ip);
				_int_switcher(&ip_hdr->dst_ip);

				if (0) {
					printf(" src ip ");
					print_dotted_ips(&ip_hdr->src_ip);
					printf(" dst ip ");
					print_dotted_ips(&ip_hdr->dst_ip);
					printf("\n");
				}
				packet_addr = " src ip ";
				packet_addr += return_dotted_ips(&ip_hdr->src_ip);
				packet_addr += "   dst ip ";
				packet_addr += return_dotted_ips(&ip_hdr->dst_ip);

				size_of_data = _short_switcher(&ip_hdr->total_len);
				size_of_data = (size_of_data - sizeof(*ip_hdr) - sizeof(tcp_hdr) -
					sizeof(struct ethernet_hdr_s));

				ip_info = find_ip(ip_hdr->src_ip);
				if (ip_info == NULL) {
					ip_info = (struct ip_info_s*)malloc(sizeof(struct ip_info_s));
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
					ip_info = (struct ip_info_s*)malloc(sizeof(struct ip_info_s));
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


				switch (ip_hdr->proto) {

				case 6: /* TCP */
				{
					TCP_Flow* f;
					cnt.num_tcp_pkts++;
					packet_type = "TCP";
					int tls_type = 0;
					//NOTE: sometimes there are eth_padding in the end of the packet
					int load_size = pkt_hdr.incl_len - sizeof(*eth_hdr) - sizeof(*ip_hdr) - sizeof(tcp_hdr);
					if (is_padding(n, pkt_hdr.incl_len, load_size))  //maybe is ethernet padding  //to improve
						load_size = 0;

					copy_bytes(packets[n] + sizeof(pcaprec_hdr_s) + sizeof(*eth_hdr) + sizeof(*ip_hdr), &tcp_hdr, sizeof(tcp_hdr));

					_short_switcher(&tcp_hdr.ofs_ctrl);
					_int_switcher(&tcp_hdr.seq_num);
					_int_switcher(&tcp_hdr.ack_num);

					tcp_hdr.src_port = _short_switcher(&tcp_hdr.src_port);
					tcp_hdr.dst_port = _short_switcher(&tcp_hdr.dst_port);

					f = search_tcp_hash_list_to_edit(ip_hdr->src_ip, ip_hdr->dst_ip,
						tcp_hdr.src_port, tcp_hdr.dst_port);

					//if ((tcp_hdr.ofs_ctrl & 0x02) == 0x02) {  //syn==1
					//	/* syn + syn ack */
					//	if (f == NULL || f->closed == 1) {    //f->closed ==1 ?
					//		/* if f == NULL assume that this is first syn pkt */
					//		//f = new TCP_Flow;
					//		//f->init(ip_hdr->src_ip, ip_hdr->dst_ip, tcp_hdr.src_port, tcp_hdr.dst_port, tcp_hdr.seq_num);//(TCP_Flow*)malloc(sizeof(TCP_Flow));
					//		//f->add_packet(n);
					//		//f->record_timestamp_and_seq_ack_nums(&pkt_hdr, ip_hdr, &tcp_hdr);
					//		//f->next = NULL;
					//		//add_to_hash_table(f, TCP_FLOW);
					//		//cnt.num_tcp_flows++;
					//	}
					//	else {
					//		f->add_packet(n);
					//		f->record_timestamp_and_seq_ack_nums(&pkt_hdr, ip_hdr, &tcp_hdr);
					//	}
					//} //ack=1
					//else if ((tcp_hdr.ofs_ctrl & 0x01) == 0x01) {  //fin==1
					//	if (f != NULL) {
					//		f->add_packet(n);
					//		f->record_timestamp_and_seq_ack_nums(&pkt_hdr, ip_hdr, &tcp_hdr);
					//		f->closed = 1;
					//	}
					//}
					//else
					{
						if (f != NULL) {
							f->add_packet(n);
							f->record_timestamp_and_seq_ack_nums(&pkt_hdr, ip_hdr, &tcp_hdr);
						}
						if (load_size > 0) {
							//memcpy(buf, packets[n] + sizeof(*eth_hdr) + sizeof(*ip_hdr) + sizeof(tcp_hdr), load_size);
							if (load_size > MIN_RECORD_LAYER_SIZE) {
								tls_type = tls_version_type(packets[n][1 + sizeof(pcaprec_hdr_s) + sizeof(*eth_hdr) + sizeof(*ip_hdr) + sizeof(tcp_hdr)], packets[n][2 + sizeof(pcaprec_hdr_s) + sizeof(*eth_hdr) + sizeof(*ip_hdr) + sizeof(tcp_hdr)]);  //只要第一个判断出来就行了 //todo...
								if (f != NULL) {
									if (f->isgmtls == 1) {
										packet_type = "GMTLS";
										accroding_flow[n] = f;
									}
									if (f->istls == 1) {
										packet_type = "TLS";
										accroding_flow[n] = f;
									}
								}
								else {
									if (tls_type == GMTLS || tls_type == TLS) {
										f = new TCP_Flow;
										f->init(ip_hdr->src_ip, ip_hdr->dst_ip, tcp_hdr.src_port, tcp_hdr.dst_port, tcp_hdr.seq_num);//(TCP_Flow*)malloc(sizeof(TCP_Flow));
										f->add_packet(n);
										f->record_timestamp_and_seq_ack_nums(&pkt_hdr, ip_hdr, &tcp_hdr);
										f->next = NULL;
										add_to_hash_table(f, TCP_FLOW);
										cnt.num_tls_flows++;

										if (f->isgmtls == 0 && tls_type == GMTLS) {
											f->isgmtls = 1;		
											packet_type = "GMTLS";
											accroding_flow[n] = f;
										}


										if (f->istls == 0 && tls_type == TLS) {
											f->istls = 1;
											packet_type = "TLS";
											accroding_flow[n] = f;
										}
										
									}
									//printf("error:load_size > MIN_RECORD_LAYER_SIZE, but f == NULL\n");
								}
								//else {

								//	//if (f->isgmtls == 0 && tls_type == GMTLS)
								//	//	f->isgmtls = 1;//										

								//	//if (f->istls == 0 && tls_type == TLS)
								//	//	f->istls = 1;

								/*if (f->isgmtls == 1) {
									packet_type = "GMTLS";
									accroding_flow[n] = f;
								}
								if (f->istls == 1) {
									packet_type = "TLS";
									accroding_flow[n] = f;
								}*/
								//}
							}
						}
					}

					break;
				}
				case 17: { //udp

					cnt.num_udp_pkts++;
					packet_type = "UDP";
					int isakmp_type = 0;
					int load_size = pkt_hdr.incl_len - sizeof(*eth_hdr) - sizeof(*ip_hdr) - sizeof(udp_hdr_s);
					if (is_padding(n, pkt_hdr.incl_len, load_size))  //maybe is ethernet padding  //to improve
						load_size = 0;

					copy_bytes(packets[n] + sizeof(pcaprec_hdr_s) + sizeof(*eth_hdr) + sizeof(*ip_hdr), &udp_hdr, sizeof(udp_hdr));

					if (load_size > 18) {  //18?
						int b = sizeof(pcaprec_hdr_s) + sizeof(*eth_hdr) + sizeof(*ip_hdr) + sizeof(udp_hdr_s) + 17;
						isakmp_type = isakmp_version_type(packets[n][b]);
						if (isakmp_type) {
							cnt.num_isakmp_pkts++;
							packet_type = "ISAKMP";

							ipsec_flow = search_IP_hash_list(ip_hdr->src_ip, ip_hdr->dst_ip);
							if (ipsec_flow == NULL) {
								ipsec_flow = new IP_Flow;
								ipsec_flow->init(ip_hdr->src_ip, ip_hdr->dst_ip);

								ipsec_flow->add_packet(n);
								ipsec_flow->next = NULL;

								add_to_hash_table(ipsec_flow, IP_FLOW);
								cnt.num_ipsec_flows++;
							}
							else {
								ipsec_flow->add_packet(n);
							}
						}
					}

					break;
				}
				case 1:
					cnt.num_icmp_pkts++;
					packet_type = "ICMP";
					//copy_bytes(packet+sizeof(eth_hdr) + sizeof(ip_hdr), &icmp_hdr, sizeof(icmp_hdr));

					break;
				case 50:
					cnt.num_esp_pkts++;
					packet_type = "ESP";

					ipsec_flow = search_IP_hash_list(ip_hdr->src_ip, ip_hdr->dst_ip);
					if (ipsec_flow == NULL) {
						ipsec_flow = new IP_Flow;
						ipsec_flow->init(ip_hdr->src_ip, ip_hdr->dst_ip);

						ipsec_flow->add_packet(n);
						ipsec_flow->next = NULL;

						add_to_hash_table(ipsec_flow, IP_FLOW);
						cnt.num_ipsec_flows++;
					}
					else {
						ipsec_flow->add_packet(n);
					}

					break;
				default:
					cnt.num_not_tcp_udp_icmp_esp_pkts++;

				}
			}
			else if (eth_hdr->type_length == 0x86dd) {
				cnt.num_ipv6_pkts++;
				packet_type = "IPV6";
			}
			else if (eth_hdr->type_length == 0x806) {
				cnt.num_arp_pkts++;
				packet_type = "ARP";
			}
		}
		else {
			cnt.non_eth++;
		}

		n++;
		if (debug) {
			printf("%d %s ", n, packet_type);
			cout << packet_addr;
			printf("\n");
		}
	}

	if (1) {
		printf("\nSummary:\n");
		printf("num pkts read = %d\n", n);
		print_counters(&cnt);
	}

	fclose(in_fd);

	if (debug) {
		printf("------------------------------------------------------------------------------------\n");
		printf("\nPrinting tcp hash table...\n");
		print_tls_flow_hash_table();
		printf("------------------------------------------------------------------------------------\n");
		printf("\nPrinting ipsec hash table...\n");
		print_ipsec_flow_hash_table();
		printf("------------------------------------------------------------------------------------\n");
	}

	return 0;
}