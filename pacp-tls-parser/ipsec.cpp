#include "pch.h"
#include "ipsec.h"
#include "tls.h"
using namespace ipsec;
int isakmp_version_type(uint8_t version) {
	if (version == 0x10)
		return 1;
	else if (version == 0x11)
		return 2;
	return 0;
}



int handleESPPacket(unsigned char* buf, int file_size, FILE* out_fd, int debug) {

	int err, type = 0;
	// Parse the record layer headers and save the actual handshake message into tls_message->body
	esp_packet_t* esp_packet = (esp_packet_t*)buf;


	if (debug)
		out_fd = NULL;


	info_printf(out_fd, "---------------------------------------\n");
	info_printf(out_fd, "esp packet:\n");
	//info_printf(out_fd, "spi: %u\n", esp_packet->spi);
	//info_printf(out_fd, "seq: %u\n", esp_packet->seq);
	info_printf(out_fd, "spi: %u\n", _int_switcher(&esp_packet->spi));
	info_printf(out_fd, "seq: %u\n", _int_switcher(&esp_packet->seq));
	return 0;
}


int handleISAKMPPacket(unsigned char* buf, int file_size, FILE* out_fd, int debug) {

	int err, type = 0;
	// Parse the record layer headers and save the actual handshake message into tls_message->body
	IkeV2Header* header = (IkeV2Header*)buf;

	if (debug)
		out_fd = NULL;


	info_printf(out_fd, "---------------------------------------\n");
	info_printf(out_fd, "ISAKMP packet:\n");
	//info_printf(out_fd, "init_spi: %x\n", header->init_spi);
	info_printf(out_fd, "init_spi: %x%x\n", _int_switcher((unsigned int*)&header->init_spi), _int_switcher((unsigned int*)&header->init_spi + 1));
	info_printf(out_fd, "resp_spi: %x%x\n", _int_switcher((unsigned int*)&header->resp_spi), _int_switcher((unsigned int*)&header->resp_spi + 1));
	switch (isakmp_version_type(header->version)) {
	case 1:
		info_printf(out_fd, "version: 1.0\n");
		break;
	case 2:
		info_printf(out_fd, "version: 1.1(gm)\n");
		break;
	default:
		info_printf(out_fd, "wrong version\n");
	}
	info_printf(out_fd, "exchange type: %u\n", header->exch_type);
	info_printf(out_fd, "flags: %x\n", header->flags);
	info_printf(out_fd, "msg_id: 0x%x\n", _int_switcher(&header->msg_id));
	info_printf(out_fd, "length: %u\n", _int_switcher(&header->length));
	return 0;
}

unsigned short _short_switcher(unsigned short* x)
{
	char* p;
	char* p2;
	char temp;

	p = (char*)x;
	p2 = p + 1;
	temp = *p;
	*p = *p2;
	*p2 = temp;
	return (*x);
}

unsigned int _int_switcher(unsigned int* x)
{
	char* b1;
	char temp;

	b1 = (char*)x;
	temp = *b1;
	*b1 = *(b1 + 3);
	*(b1 + 3) = temp;

	temp = *(b1 + 1);
	*(b1 + 1) = *(b1 + 2);
	*(b1 + 2) = temp;
	return (*x);
}





void
conv_ip_to_str(char* str, uint32_t ip)
{
	sprintf(str, "%u.%u.%u.%u",
		(ip & 0xff000000) >> 24,
		(ip & 0x00ff0000) >> 16,
		(ip & 0x0000ff00) >> 8,
		(ip & 0x000000ff));
}

void
print_dotted_ips(uint32_t* ip)
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