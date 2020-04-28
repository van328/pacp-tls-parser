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
	info_printf(out_fd, "spi: %u\n", esp_packet->spi);
	info_printf(out_fd, "seq: %u\n", esp_packet->seq);
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
	info_printf(out_fd, "init_spi: %u\n", header->init_spi);
	info_printf(out_fd, "resp_spi: %u\n", header->resp_spi);
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
	return 0;
}