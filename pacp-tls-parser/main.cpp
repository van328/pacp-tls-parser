// pacp-tls-parser.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include "pacp.h"
#include "tls.h"
#define _CRT_SECURE_NO_WARNINGS


const char* input_file = "gmssl20.pcap";
const char* output_info = "info.txt";
//const char* output_data = "data";

int main(int argc, char *argv[])
{
	
	parse_pcap_file(input_file, output_info, 1);
	//输出作为参数
}