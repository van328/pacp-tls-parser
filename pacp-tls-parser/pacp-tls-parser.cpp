// pacp-tls-parser.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include "pacp.h"
#include "debug.h"
#include "tls.h"
#define _CRT_SECURE_NO_WARNINGS

//#include <iostream>


Debug DebugOut;
//int main(int argc, char* argv[]) {
//	const char * filedir = "./mypacket/data1";
//	if (!filedir) {
//		printf("filedir == NULL!\n");
//
//		return 0;
//	}
//	int debugLevel = 2; //fg
//	DebugOut.SetDebugLevel(debugLevel);//fg
//
//	int err = 0;
//	
//	unsigned char *buf;
//	int file_size = -1;
//
//	// Check whether the path provided links to a reguler file and checks it's size
//	if (((buf = get_safe_input_file((char *)filedir, &file_size)) == NULL) || (file_size == -1)) {
//		return 0;
//	}
//	err = handlePacket(buf, file_size);
//	if (!err) {
//		printf("\n[OK]: Finished parsing of message!\n");
//	}else
//		printf("\n[NOT OK]: err = %d!\n",err);
//	
//	return 0;
//}


int main(int argc, char *argv[])
{
	int debugLevel = 2; //fg
	DebugOut.SetDebugLevel(debugLevel);//fg
	const char * input_file = "./4.pcap";
	const char * output_info = "info.txt";
	const char * output_data = "data";
	parse_pcap_file(input_file, output_info, output_data, 1);
	//输出作为参数
}