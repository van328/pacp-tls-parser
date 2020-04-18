#pragma once
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <sys/stat.h>
#include <time.h>
#include <iostream>

#define NO_ERROR 0
#define INVALID_FILE_LENGTH 1
#define INVALID_CONTENT_TYPE 2
#define INVALID_VERSION 3
#define UNSUPPORTED_MESSAGE_TYPE 4
#define INVALID_FILE_LENGTH_FOR_CLIENT_KEY_EXCHANGE 5

#define MIN_RECORD_LAYER_SIZE 3 // Has to be atleast (ContentType + TLS version)
#define MIN_CLIENT_HELLO_SIZE 38 // A client hello has to be atleast 38 bytes
#define MIN_SERVER_HELLO_SIZE 38 // A server hello has to be atleast 38 bytes
#define HELLO_RANDOM_BYTES_SIZE 28 // As specified in RFC
#define MAXIMUM_FILE_SIZE 20000000 // bytes => 20 MB


static int myContentType;//fg

typedef struct {
	uint8_t major;
	uint8_t minor;
} ProtocolVersion;

typedef struct {
	uint32_t time;
	unsigned char random_bytes[28];
} Random;

typedef struct {
	uint8_t length;
	unsigned char *sessionId;
} SessionID;

typedef struct {
	uint16_t length;
	unsigned char *cipherSuites; // The individual suites are not in scope of the parser
} CipherSuiteCollection;

typedef struct {
	uint8_t length;
	uint8_t compresionMethod; // The individual method is not in scope of the parser
} CompresionMethod;

// All messages parseable using this parser should start with 0x16 indicating the hand-shake protocol
// Any other value is considered invalid
typedef enum {
	CHANGE_CIPHER_SPEC = 20,  // 0x14
	ALERT = 21,               // 0x15
	HANDSHAKE = 22,           // 0x16
	APPLICATION_DATA = 23,    // 0x17
	ENCRYPTED_HANDSHAKE = 99, 

} ContentType;

// This parser is capable of parsing messages 1, 2, 11, 12, 14 and 16
// Any other message is considered invalid
typedef enum {
	HELLO_REQUEST = 0,        // 0x00
	CLIENT_HELLO = 1,         // 0x01
	SERVER_HELLO = 2,         // 0x02
	CERTIFICATE = 11,         // 0x0B
	SERVER_KEY_EXCHANGE = 12, // 0x0C
	CERTIFICATE_REQUEST = 13, // 0x0D
	SERVER_HELLO_DONE = 14,   // 0x0E
	CERTIFICATE_VERIFY = 15,  // 0x0F
	CLIENT_KEY_EXCHANGE = 16, // 0x10
	FINISHED = 20,            // 0x14

} HandshakeType;

// This is how the message looks like as a whole (record layer + actual message)
typedef struct {
	ContentType cType;
	ProtocolVersion version;
	uint16_t fLength;         // Length of file = type (1 byte) + mLength (3 bytes)
	HandshakeType hsType;
	uint32_t mLength;         // Length of body
	unsigned char *body;      // We need to allocate "length" bytes at runtime
} HandshakeMessage;


typedef struct {
	ProtocolVersion version;
	Random random;
	SessionID sessionId;
	CipherSuiteCollection csCollection;
	CompresionMethod compresionMethod;
	uint8_t hasExtensions;
	unsigned char *extensions; // We need to calculate correct size runtime
} ClientHello;

typedef struct {
	ProtocolVersion version;
	Random random;
	SessionID sessionId;
	unsigned char cipherSuite[2];
	uint8_t compresionMethod;
	uint8_t hasExtensions;
	unsigned char *extensions; // We need to calculate correct size runtime
} ServerHello;

typedef struct { } Certificate;       // This message contains only a chain of certificates, which is not subject of parsing
typedef struct { } ServerKeyExchange; // Contains KeyExchangeAlgorithm parameters, which are not subject of parsing
typedef struct { } ClientKeyExchange; // Contains either a PreMasterSecret or DH Client Parameters like (key) and is not subject of parsing
typedef struct { } ServerHelloDone;   // This message contains nothing, it's defined just for the sake of complentness

int initialize_tls_structure(unsigned char *raw, int size, HandshakeMessage *tls_message, int *nextSizef);
void fprint_tls_record_layer_info(FILE *fp, HandshakeMessage *tls_message);//fg
void print_tls_record_layer_info(HandshakeMessage *tls_message);

int parse_application_data(FILE *fp, unsigned char *message, uint16_t size);
int parse_other_ctype(FILE *fp, unsigned char *message, uint16_t size);
//int print_application_message(unsigned char *message, uint16_t size);

int parse_client_hello(FILE *fp, unsigned char *message, uint16_t size);
void fprint_client_hello_message(FILE *fp, ClientHello *client_hello, int size);//fg
void print_client_hello_message(ClientHello *client_hello, int size);
int parse_server_hello(FILE *fp, unsigned char *message, uint16_t size);
void fprint_server_hello_message(FILE *fp, ServerHello *message, int extensions_length);
void print_server_hello_message(ServerHello *message, int extensions_length);
void fprint_tls_version(FILE *fp, uint8_t minor);
void print_tls_version(uint8_t minor);
int parse_certificate(uint16_t size);
int parse_server_key_exchange(uint16_t size);
int parse_server_hello_done(uint16_t size);
int parse_client_key_exchange(unsigned char *message, uint16_t size);
void clean_client_hello(ClientHello message);
void clean_server_hello(ServerHello message);
int is_valid_tls_version(unsigned char major, unsigned char minor);
unsigned char* get_safe_input_file(char *path, int *file_size);
void fclose_safe(FILE * stream);
void handle_errors(int error_code);
int handlePacket(unsigned char *buf, int file_size, FILE * out_fd);