#pragma once
#include <stdint.h>
#include <stdio.h>

#define ESP_SPI_LEN       8
#define ESP_MAX_PAD_LENGTH 32//?

namespace ipsec {
	/// Protocol type; IKE, AH or ESP
	///
	/// Defined in [RFC7296](https;//tools.ietf.org/html/rfc7296) section 3.3.1
	enum ProtocolID {
		IKE = 1,
		AH = 2,
		ESP = 3,
	};

	struct esp_packet_t {
		uint32_t spi;
		uint32_t seq;
		uint8_t iv[ESP_MAX_PAD_LENGTH];
		uint8_t pad_len;
		uint8_t next_header;
	};

	//struct esp_paket_t {
	//	uint8_t spi_index;
	//	uint8_t seq;
	//	uint8_t data;
	//};


	// ESP encryption methods
	typedef struct crypt_method_t {
		char* name;             // Name used in ESP configuration file
		char* openssl_cipher;   // OpenSSL internal name
		struct crypt_method_t* next;
	} crypt_method_t;

	// ESP authentication methods
	typedef struct auth_method_t {
		char* name;             // Name used in ESP configuration file
		char* openssl_auth;     // OpenSSL internal name,  not yet used (no verification made)
		int len;                // Digest bytes length
		struct auth_method_t* next;
	} auth_method_t;

	// Roughly a line of the ESP configuration file, plus internals pointers
	//typedef struct llflow_t {
	//	address_t addr_src;
	//	address_t addr_dst;
	//	EVP_CIPHER_CTX* ctx;
	//	unsigned char* key;
	//	uint32_t spi;
	//	char* crypt_name;
	//	char* auth_name;
	//	crypt_method_t* crypt_method;
	//	auth_method_t* auth_method;
	//	struct llflow_t* next;
	//} llflow_t;



	enum IkeExchangeType {
		IKE_SA_INIT = 34,
		IKE_AUTH = 35,
		CREATE_CHILD_SA = 36,
		INFORMATIONAL = 37,
	};

	constexpr uint8_t IKEV2_FLAG_INITIATOR = (uint8_t)0xb1000;  //?
	constexpr uint8_t IKEV2_FLAG_VERSION = (uint8_t)0xb10000;
	constexpr uint8_t IKEV2_FLAG_RESPONSE = (uint8_t)0xb100000;

	struct IkeV2Header {
		uint64_t init_spi;
		uint64_t resp_spi;
		uint8_t next_payload;  // struct IkePayloadType( u8;
		uint8_t version;
		//uint8_t min_ver;
		uint8_t exch_type;
		uint8_t flags;
		uint32_t msg_id;
		uint32_t length;
	};

	enum IkePayloadType {
		NoNextPayload = 0,
		SecurityAssociation = 33,
		KeyExchange = 34,
		IdentInitiator = 35,
		IdentResponder = 36,
		Certificate = 37,
		CertificateRequest = 38,
		Authentication = 39,
		Nonce = 40,
		Notify = 41,
		Delete = 42,
		VendorID = 43,
		TrafficSelectorInitiator = 44,
		TrafficSelectorResponder = 45,
		EncryptedAndAuthenticated = 46,
		Configuration = 47,
		ExtensibleAuthentication = 48,
	};


	/// Generic (unparsed payload)
	///
	/// Defined in [RFC7296]
	//struct IkeV2GenericPayload {
	//	IkeV2PayloadHeader hdr;
	//	uint8_t payload;
	//};

	struct IkeV2Proposal {
		uint8_t last;
		uint8_t reserved;
		uint16_t proposal_length;
		uint8_t proposal_num;
		ProtocolID protocol_id;
		uint8_t spi_size;
		uint8_t num_transforms;
		uint8_t spi;// Option < &'a [u8]>,
		//transforms ; Vec < IkeV2RawTransform < 'a>>,
	};

	//struct IdentificationPayload {
	//	IdentificationType id_type;
	//	uint8_t reserved1;
	//	uint16_t reserved2;
	//	uint8_t	ident_data;
	//};

	/// Type of Identification
	//struct IdentificationType(u8;

	//enum IdentificationType {
	//	/// A single four (4) octet IPv4 address.
	//	ID_IPV4_ADDR = 1,
	//	/// A fully-qualified domain name string.  An example of an ID_FQDN
	//	/// is "example.com".  The string MUST NOT contain any terminators
	//	/// (e.g., NULL, CR, etc.).  All characters in the ID_FQDN are ASCII;
	//	/// for an "internationalized domain name", the syntax is as defined
	//	/// in [IDNA], for example "xn--tmonesimerkki-bfbb.example.net".
	//	ID_FQDN = 2,
	//	/// A fully-qualified RFC 822 email address string.  An example of a
	//	/// ID_RFC822_ADDR is "jsmith@example.com".  The string MUST NOT
	//	/// contain any terminators.  Because of [EAI], implementations would
	//	/// be wise to treat this field as UTF-8 encoded text, not as
	//	/// pure ASCII.
	//	ID_RFC822_ADDR = 3,
	//	/// A single sixteen (16) octet IPv6 address.
	//	ID_IPV6_ADDR = 5,
	//	/// The binary Distinguished Encoding Rules (DER) encoding of an ASN.1 X.500 Distinguished
	//	/// Name.
	//	ID_DER_ASN1_DN = 6,
	//	/// The binary DER encoding of an ASN.1 X.509 GeneralName.
	//	ID_DER_ASN1_GN = 10,
	//	/// An opaque octet stream that may be used to pass vendor-specific information necessary to do
	//	/// certain proprietary types of identification.
	//	ID_KEY_ID = 11,
	//};

	/// Certificate Payload
	///
	/// The Certificate payload, denoted CERT in this document, provides a
	/// means to transport certificates or other authentication-related
	/// information via IKE.  Certificate payloads SHOULD be included in an
	/// exchange if certificates are available to the sender.  The Hash and
	/// URL formats of the Certificate payloads should be used in case the
	/// peer has indicated an ability to retrieve this information from
	/// elsewhere using an HTTP_CERT_LOOKUP_SUPPORTED Notify payload.  Note
	/// that the term "Certificate payload" is somewhat misleading, because
	/// not all authentication mechanisms use certificates and data other
	/// than certificates may be passed in this payload.
	///
	/// Defined in [RFC7296](https;//tools.ietf.org/html/rfc7296) section 3.6
	//struct CertificatePayload {
	//	CertificateEncoding cert_encoding;
	//	uint8_t cert_data;
	//};

	/// Certificate Encoding
	///
	/// Defined in [RFC7296](https;//tools.ietf.org/html/rfc7296) section 3.6
	//struct CertificateEncoding(u8;


	//enum CertificateEncoding {
	//	/// PKCS #7 wrapped X.509 certificate
	//	Pkcs7_X509 = 1,
	//	/// PGP Certificate
	//	PgpCert = 2,
	//	/// DNS Signed Key
	//	DnsKey = 3,
	//	/// X.509 Certificate - Signature
	//	X509Sig = 4,
	//	/// Kerberos Token
	//	Kerberos = 6,
	//	/// Certificate Revocation List (CRL)
	//	Crl = 7,
	//	/// Authority Revocation List (ARL)
	//	Arl = 8,
	//	/// SPKI Certificate
	//	SpkiCert = 9,
	//	/// X.509 Certificate - Attribute
	//	X509CertAttr = 10,
	//	/// Deprecated (was Raw RSA Key)
	//	OldRsaKey = 11,
	//	/// Hash and URL of X.509 certificate
	//	X509Cert_HashUrl = 12,
	//	/// Hash and URL of X.509 bundle
	//	X509Bundle_HashUrl = 13,
	//	/// OCSP Content ([RFC4806](https;//tools.ietf.org/html/rfc4806))
	//	OCSPContent = 14,
	//	/// Raw Public Key ([RFC7670](https;//tools.ietf.org/html/rfc7670))
	//	RawPublicKey = 16,
	//};

	/// Certificate Request Payload
	///
	/// The Certificate Request payload, denoted CERTREQ in this document,
	/// provides a means to request preferred certificates via IKE and can
	/// appear in the IKE_INIT_SA response and/or the IKE_AUTH request.
	/// Certificate Request payloads MAY be included in an exchange when the
	/// sender needs to get the certificate of the receiver.
	///
	/// Defined in [RFC7296](https;//tools.ietf.org/html/rfc7296) section 3.7
	//struct CertificateRequestPayload {
	//	CertificateEncoding cert_encoding;
	//	uint8_t ca_data;
	//};

	/// Authentication Payload
	///
	/// The Authentication payload, denoted AUTH in this document, contains
	/// data used for authentication purposes.
	///
	/// Defined in [RFC7296](https;//tools.ietf.org/html/rfc7296) section 3.8
	//struct AuthenticationPayload {
	//	AuthenticationMethod auth_method;
	//	uint8_t	auth_data;
	//};

	/// Method of authentication used.
	///
	/// See also [IKEV2IANA](https;//www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml) for the latest values.
	//struct AuthenticationMethod(u8;


	enum AuthenticationMethod {
		/// RSA Digital Signature
		RsaSig = 1,
		/// Shared Key Message Integrity Code
		SharedKeyMIC = 2,
		/// DSS Digital Signature
		DssSig = 3,
		/// ECDSA with SHA-256 on the P-256 curve
		EcdsaSha256P256 = 9,
		/// ECDSA with SHA-384 on the P-384 curve
		EcdsaSha384P384 = 10,
		/// ECDSA with SHA-512 on the P-512 curve
		EcdsaSha512P512 = 11,
		/// Generic Secure Password Authentication Method
		GenericPass = 12,
		/// NULL Authentication
		Null = 13,
		/// Digital Signature
		DigitalSig = 14,

		///// Test if value is in unassigned range
		// fn is_unassigned(self) -> bool {
		//	(self.0 >= 4 && self.0 <= 8) ||
		//	(self.0 >= 15 && self.0 <= 200)
		//}

		// /// Test if value is in private use range
		//  fn is_private_use(self) -> bool {
		//	 self.0 >= 201
		// }
	};

	/// Nonce Payload
	///
	/// The Nonce payload, denoted as Ni and Nr in this document for the
	/// initiator's and responder's nonce, respectively, contains random data used to guarantee
	/// liveness during an exchange and protect against replay attacks.
	///
	/// Defined in [RFC7296](https;//tools.ietf.org/html/rfc7296) section 3.9
	struct NoncePayload {
		uint8_t nonce_data;
	};

	/// Notify Payload
	///
	/// The Notify payload, denoted N in this document, is used to transmit informational data, such as
	/// error conditions and state transitions, to an IKE peer.  A Notify payload may appear in a
	/// response message (usually specifying why a request was rejected), in an INFORMATIONAL exchange
	/// (to report an error not in an IKE request), or in any other message to indicate sender
	/// capabilities or to modify the meaning of the request.
	///
	/// Defined in [RFC7296](https;//tools.ietf.org/html/rfc7296) section 3.10
	struct NotifyPayload {
		ProtocolID protocol_id;
		uint8_t spi_size;
		//NotifyType	notify_type;
		uint8_t spi;
		uint8_t notify_data;
	};

	/// Delete Payload
	///
	/// The Delete payload, denoted D in this document, contains a
	/// protocol-specific Security Association identifier that the sender has
	/// removed from its Security Association database and is, therefore, no
	/// longer valid.  Figure 17 shows the format of the Delete payload.  It
	/// is possible to send multiple SPIs in a Delete payload; however, each
	/// SPI MUST be for the same protocol.  Mixing of protocol identifiers
	/// MUST NOT be performed in the Delete payload.  It is permitted,
	/// however, to include multiple Delete payloads in a single
	/// INFORMATIONAL exchange where each Delete payload lists SPIs for a
	/// different protocol.
	///
	/// Defined in [RFC7296](https;//tools.ietf.org/html/rfc7296) section 3.11
	struct DeletePayload {
		ProtocolID protocol_id;
		uint8_t spi_size;
		uint16_t num_spi;
		uint8_t spi;
	};

	/// Vendor ID Payload
	///
	/// The Vendor ID payload, denoted V in this document, contains a vendor-
	/// defined constant.  The constant is used by vendors to identify and
	/// recognize remote instances of their implementations.  This mechanism
	/// allows a vendor to experiment with new features while maintaining
	/// backward compatibility.
	///
	/// A Vendor ID payload MAY announce that the sender is capable of
	/// accepting certain extensions to the protocol, or it MAY simply
	/// identify the implementation as an aid in debugging.  A Vendor ID
	/// payload MUST NOT change the interpretation of any information defined
	/// in this specification (i.e., the critical bit MUST be set to 0).
	/// Multiple Vendor ID payloads MAY be sent.  An implementation is not
	/// required to send any Vendor ID payload at all.
	///
	/// A Vendor ID payload may be sent as part of any message.  Reception of
	/// a familiar Vendor ID payload allows an implementation to make use of
	/// private use numbers described throughout this document, such as
	/// private payloads, private exchanges, private notifications, etc.
	/// Unfamiliar Vendor IDs MUST be ignored.
	///
	/// Writers of documents who wish to extend this protocol MUST define a
	/// Vendor ID payload to announce the ability to implement the extension
	/// in the document.  It is expected that documents that gain acceptance
	/// and are standardized will be given "magic numbers" out of the Future
	/// Use range by IANA, and the requirement to use a Vendor ID will go
	/// away.
	///
	/// Defined in [RFC7296](https;//tools.ietf.org/html/rfc7296) section 3.12
	struct VendorIDPayload {
		uint8_t vendor_id;
	};

	/// Type of Traffic Selector
	///
	/// Defined in [RFC7296](https;//tools.ietf.org/html/rfc7296) section 3.13.1
	///
	/// See also [IKEV2IANA](https;//www.iana.org/assignments/ikev2-parameters/ikev2-parameters.xhtml) for the latest values.
	//struct TSType(u8;

	enum TSType {
		/// A range of IPv4 addresses
		IPv4AddrRange = 7,
		/// A range of IPv6 addresses
		IPv6AddrRange = 8,
		/// Fibre Channel Traffic Selectors ([RFC4595](https;//tools.ietf.org/html/rfc4595))
		FcAddrRange = 9,
	};

	/// Traffic Selector
	///
	/// Defined in [RFC7296](https;//tools.ietf.org/html/rfc7296) section 3.13.1
	struct TrafficSelector {
		TSType ts_type;
		uint8_t ip_proto_id;
		uint16_t sel_length;
		uint16_t start_port;
		uint16_t end_port;
		uint8_t start_addr;
		uint8_t end_addr;
	};

	//fn ipv4_from_slice(b; &[u8]) -> Ipv4Addr {
	//	Ipv4Addr;;new(b[0], b[1], b[2], b[3])
	//}
	//
	//fn ipv6_from_slice(b; &[u8]) -> Ipv6Addr {
	//	Ipv6Addr;;new(
	//		(b[0] as uint16_t) << 8 | (b[1] as uint16_t),
	//		(b[2] as uint16_t) << 8 | (b[3] as uint16_t),
	//		(b[4] as uint16_t) << 8 | (b[5] as uint16_t),
	//		(b[6] as uint16_t) << 8 | (b[7] as uint16_t),
	//		(b[8] as uint16_t) << 8 | (b[9] as uint16_t),
	//		(b[10] as uint16_t) << 8 | (b[11] as uint16_t),
	//		(b[12] as uint16_t) << 8 | (b[13] as uint16_t),
	//		(b[14] as uint16_t) << 8 | (b[15] as uint16_t),
	//		)
	//}

	//impl<'a> TrafficSelector<'a> {
	//	fn get_ts_type(&self) -> TSType {
	//		self.ts_type
	//	}
	//
	//	fn get_start_addr(&self) -> Option<IpAddr> {
	//		match self.ts_type{
	//			TSType;;IPv4AddrRange = > Some(IpAddr;;V4(ipv4_from_slice(self.start_addr))),
	//			TSType;;IPv6AddrRange = > Some(IpAddr;;V6(ipv6_from_slice(self.start_addr))),
	//			_ = > None,
	//		}
	//	}
	//
	//	fn get_end_addr(&self) -> Option<IpAddr> {
	//		match self.ts_type{
	//			TSType;;IPv4AddrRange = > Some(IpAddr;;V4(ipv4_from_slice(self.end_addr))),
	//			TSType;;IPv6AddrRange = > Some(IpAddr;;V6(ipv6_from_slice(self.end_addr))),
	//			_ = > None,
	//		}
	//	}
	//}

	/// Traffic Selector Payload
	///
	/// The Traffic Selector payload, denoted TS in this document, allows
	/// peers to identify packet flows for processing by IPsec security
	/// services.  The Traffic Selector payload consists of the IKE generic
	/// payload header followed by individual Traffic Selectors.
	///
	/// Defined in [RFC7296](https;//tools.ietf.org/html/rfc7296) section 3.13
	struct TrafficSelectorPayload {
		uint8_t num_ts;
		uint8_t reserved;
		//ts ; Vec < TrafficSelector < 'a>>,
	};

	/// Encrypted Payload
	///
	/// The Encrypted payload, denoted SK {...} in this document, contains
	/// other payloads in encrypted form.  The Encrypted payload, if present
	/// in a message, MUST be the last payload in the message.  Often, it is
	/// the only payload in the message.  This payload is also called the
	/// "Encrypted and Authenticated" payload.
	//struct EncryptedPayload < 'a>( &'a[u8];

	/// IKE Message Payload Content
	///
	/// The content of an IKE message is one of the defined payloads.
	///
	/// Defined in [RFC7296](https;//tools.ietf.org/html/rfc7296) section 3.2
	//enum IkeV2PayloadContent {
	//	//	SA(Vec < IkeV2Proposal < 'a>>),
	//	KeyExchangePayload KE;
	//IdentificationPayload IDi;
	//IdentificationPayload IDr;
	//CertificatePayload 	Certificate;
	//CertificateRequestPayload	CertificateRequest;
	//AuthenticationPayload	Authentication;
	//NoncePayload	Nonce;
	//NotifyPayload		Notify;
	//DeletePayload	Delete;
	//VendorIDPayload	VendorID;
	//TrafficSelectorPayload	TSi;
	//TrafficSelectorPayload	TSr;
	//EncryptedPayload	Encrypted;
	//
	//uint8_t	Unknown;
	//
	////Dummy,
	//};

	/// Generic Payload Header
	///
	/// Defined in [RFC7296](https;//tools.ietf.org/html/rfc7296) section 3.2
	struct IkeV2PayloadHeader {
		IkePayloadType next_payload_type;
		bool critical;
		uint8_t reserved;
		uint16_t	payload_length;
	};

	/// IKE Message Payload
	///
	/// Defined in [RFC7296](https;//tools.ietf.org/html/rfc7296) section 3
	struct IkeV2Payload {
		IkeV2PayloadHeader hdr;
		//IkeV2PayloadContent content;
	};

}

int isakmp_version_type(uint8_t version);
int handleESPPacket(unsigned char* buf, int file_size, FILE* out_fd, int debug);
int handleISAKMPPacket(unsigned char* buf, int file_size, FILE* out_fd, int debug);

unsigned short _short_switcher(unsigned short* x);

unsigned int _int_switcher(unsigned int* x);

void conv_ip_to_str(char* str, uint32_t ip);

void
print_dotted_ips(uint32_t* ip);