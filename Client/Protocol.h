#pragma once
#include <cstdint>


constexpr uint8_t VERSION = 3;
constexpr size_t CLIENT_ID_SIZE = 16;
constexpr size_t MAX_CLIENT_NAME = 255;
constexpr size_t PUBLIC_KEY_SIZE = 160;
constexpr size_t MAX_FILE_NAME = 255;
constexpr size_t CHUNK_SIZE = 1024;
constexpr size_t HEADER_SIZE = 7;
constexpr size_t CONTENT_SIZE = 4;


// Responses and requests structs.

#pragma pack(push, 1)
struct RequestHeader {
	unsigned char client_id[CLIENT_ID_SIZE] = { 0 };
	uint8_t version = VERSION;
	uint16_t code;
	unsigned int payload_size;
};


enum RequestsCode : uint16_t {
	Register = 1025,
	SentPublicKey = 1026,
	Reconnect = 1027,
	SendFile = 1028,
	ValidCRCrequestCode = 1029,
	InvalidCRCretry = 1030,
	InvalidCRCabort = 1031
};


struct RegisterRequest {
	char client_name[MAX_CLIENT_NAME] = { 0 };
};

struct SendPublicKeyRequest {
	char client_name[MAX_CLIENT_NAME] = { 0 };
	char public_key[PUBLIC_KEY_SIZE] = { 0 };
};

struct ReconnecrRequest {
	char client_name[MAX_CLIENT_NAME] = { 0 };
};

struct SendFileRequest {
	unsigned int content_size;
	char file_name[MAX_FILE_NAME] = { 0 };
};

struct ValidCRCrequest {
	char file_name[MAX_FILE_NAME] = { 0 };
};

struct InvalidCRCretryRequest {
	char file_name[MAX_FILE_NAME] = { 0 };
};

struct InvalidCRCabortRequest {
	char file_name[MAX_FILE_NAME] = { 0 };
};

/* -------------------Responses---------------------------  */
struct ResponseHeader {
	unsigned char  version;
	uint16_t       code;
	unsigned int   payload_size;
};



enum ResponseCode : uint16_t {
	SuccessfulRegistration = 2100,
	RegistrationFailed = 2101,
	KeySentGetAES = 2102,
	ValidCRCresponseCode = 2103,
	ConfirmMessage = 2104,
	ApproveReconnect = 2105,
	ReconnectDenied = 2106,
	ServerFailed = 2107
};

struct SuccessfulRegistrationResponse {
	unsigned char client_id[CLIENT_ID_SIZE];
};


struct KeySentGetAESresponse {
	unsigned char* client_id;
	unsigned char* symetric_key;
};

struct ApproveReconnectResponse {
	unsigned char* client_id;
	unsigned char* symetric_key;

};

struct ValidCRCResponse {
	unsigned char client_id[CLIENT_ID_SIZE];
	unsigned int content_size;
	char file_name[MAX_FILE_NAME];
	unsigned int checksum;
};

struct ConfirmMessageResponse {
	unsigned char client_id[CLIENT_ID_SIZE];
};

struct ReconnectDeniedResponse {
	unsigned char client_id[CLIENT_ID_SIZE];
};
#pragma pack(pop)
