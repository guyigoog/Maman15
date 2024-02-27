#include "Client.h"
#include <iostream>
#include <filesystem>
#include "SocketHandler.h"

using namespace boost::asio;
using ip::tcp;


Client::Client(const TransferInfo& transferInfo)
	: resolver(io_context),
	socket(io_context),
	connected(false),
	meInfo(new MeInfo()), // Allocating new MeInfo object
	rsaWrapper(new RSAWrapper()), // Allocating new RSAWrapper object
	registration_required(meInfo->getRegistrationRequired()),
	file_to_send_path(transferInfo.getFilePath()),
	client_name(meInfo->getRegistrationRequired() ? transferInfo.getClientName() : meInfo->getClientName()) {

	// Connect to server
	auto ip = ip::make_address(transferInfo.getHostIP());
	socket.connect(tcp::endpoint(ip, transferInfo.getPort()));

	// Additional client setup
	if (!meInfo->getRegistrationRequired()) {
		std::memcpy(client_id, meInfo->getClientId(), CLIENT_ID_SIZE);
		rsaWrapper->loadKey(meInfo->getPrivateKey());  // Assuming loadKey expects a RSAWrapper*
	}
}




void Client::buildRequestHeader(struct RequestHeader* header, uint16_t code, uint32_t payload_size)
{
	memcpy_s(header->client_id, sizeof(header->client_id), &client_id, CLIENT_ID_SIZE);
	header->version = VERSION;
	header->code = code;
	header->payload_size = payload_size;
}

void Client::registration() {
	// Build the header
	RequestHeader* header = new RequestHeader;
	buildRequestHeader(header, RequestsCode::Register, MAX_CLIENT_NAME);

	// Build the request
	RegisterRequest request;
	errno_t err = strncpy_s(request.client_name, sizeof(request.client_name), client_name.c_str(), _TRUNCATE);
	if (err != 0) {
		// Handle the error appropriately
		throw std::runtime_error("Error copying client name.");
	}

	// Send header and request
	SocketHandler::sendBytes(header, socket);
	SocketHandler::sendBytes(&request, socket);
}



void Client::generateKeys()
{
	rsaWrapper->generateKeys();
	private_key_str = rsaWrapper->getPrivateKey();
	public_key_str = rsaWrapper->getPublicKey();
}

void Client::sendPublicKey() {
	RequestHeader* header = new RequestHeader;
	const size_t payload_size = MAX_CLIENT_NAME + PUBLIC_KEY_SIZE;
	buildRequestHeader(header, RequestsCode::SentPublicKey, payload_size);

	SocketHandler::sendBytes(header, socket);

	SendPublicKeyRequest request;
	errno_t err = strncpy_s(request.client_name, sizeof(request.client_name), client_name.c_str(), _TRUNCATE);
	if (err != 0) {
		// Handle the error appropriately
		throw std::runtime_error("Error copying client name.");
	}

	// Assuming public_key_str is std::string
	memcpy_s(request.public_key, sizeof(request.public_key), this->public_key_str.c_str(), this->public_key_str.length());


	SocketHandler::sendBytes(&request, socket);
}



void Client::reconnect() {
	RequestHeader* header = new RequestHeader;
	buildRequestHeader(header, RequestsCode::Reconnect, MAX_CLIENT_NAME);

	RegisterRequest request;
	errno_t err = strncpy_s(request.client_name, sizeof(request.client_name), client_name.c_str(), _TRUNCATE);
	if (err != 0) {
		// Handle the error appropriately
		throw std::runtime_error("Error copying client name.");
	}

	SocketHandler::sendBytes(header, socket);
	SocketHandler::sendBytes(&request, socket);
}



void Client::sendFile() {
	std::filesystem::path path(file_to_send_path);
	file_name = path.filename().string();

	if (file_name.length() >= MAX_FILE_NAME) {
		throw std::invalid_argument("File name is longer than allowed.");
	}

	auto file_size = std::filesystem::file_size(path);
	auto bloc_size = static_cast<int>(CryptoPP::AES::BLOCKSIZE);
	auto content_size = (std::ceil(static_cast<double>(file_size) / bloc_size) + 1) * bloc_size;

	RequestHeader* header = new RequestHeader;
	buildRequestHeader(header, RequestsCode::SendFile, CONTENT_SIZE + MAX_FILE_NAME + content_size);

	SendFileRequest request;
	request.content_size = content_size;
	auto cipher = rsaWrapper->encryptFile(file_to_send_path);
	errno_t err = strncpy_s(request.file_name, sizeof(request.file_name), file_name.c_str(), _TRUNCATE);
	if (err != 0) {
		throw std::runtime_error("Error copying file name.");
	}

	SocketHandler::sendBytes(header, socket);
	SocketHandler::sendBytes(&request, socket);

	// Send file content
	size_t bytes_sent = boost::asio::write(socket, boost::asio::buffer(cipher.c_str(), cipher.length()));

	if (bytes_sent < cipher.length()) {
		throw std::runtime_error("Failed to send the full file content to the server");
	}
}



void Client::validCRC() {
	RequestHeader* header = new RequestHeader;
	buildRequestHeader(header, RequestsCode::ValidCRCrequestCode, MAX_FILE_NAME);

	ValidCRCrequest request;
	errno_t err = strncpy_s(request.file_name, sizeof(request.file_name), file_name.c_str(), _TRUNCATE);
	if (err != 0) {
		// Handle the error appropriately
		throw std::runtime_error("Error copying file name.");
	}

	SocketHandler::sendBytes(header, socket);
	SocketHandler::sendBytes(&request, socket);
}



void Client::invalidCRCretry() {
	RequestHeader* header = new RequestHeader;
	buildRequestHeader(header, RequestsCode::InvalidCRCretry, MAX_FILE_NAME);

	InvalidCRCretryRequest request;
	errno_t err = strncpy_s(request.file_name, sizeof(request.file_name), file_name.c_str(), _TRUNCATE);
	if (err != 0) {
		// Handle the error appropriately
		throw std::runtime_error("Error copying file name.");
	}

	SocketHandler::sendBytes(header, socket);
	SocketHandler::sendBytes(&request, socket);
}

void Client::invalidCRCabort()
{
	// Build the header
	RequestHeader* header = new RequestHeader;
	buildRequestHeader(header, RequestsCode::InvalidCRCabort, MAX_FILE_NAME);

	// Build the request
	InvalidCRCabortRequest request{};
	strncpy_s(request.file_name, sizeof(request.file_name), file_name.c_str(), _TRUNCATE);

	// Send header and request
	SocketHandler::sendBytes(header, socket);
	SocketHandler::sendBytes(&request, socket);
}

void Client::runProcess() {
	try {
		establishConnection();
		transmitFile();
		std::cout << "Client process execution is complete." << std::endl;
	}
	catch (const std::exception& e) {
		handleError(e);
	}
}

void Client::establishConnection() {
	while (!connected) {
		if (registration_required) {
			handleRegistration();
		}
		else {
			handleReconnection();
		}
	}
	std::cout << "\nConnected to server." << std::endl;
}

void Client::handleRegistration() {
	std::cout << "Registering client." << std::endl;
	registration();
	if (!successfulRegistration()) {
		throw std::runtime_error("Registration failed.");
	}

	std::cout << "Generating keys." << std::endl;
	generateKeys();
	std::cout << "Sending public key." << std::endl;
	sendPublicKey();
	if (!publicKeySentSuccessfully()) {
		throw std::runtime_error("Failed to send public key.");
	}

	saveDetailsToFile();
	connected = true;
}

void Client::handleReconnection() {
	std::cout << "Trying to reconnect." << std::endl;
	reconnect();
	uint16_t reconnectResult = reconnectSuccessfully();
	if (reconnectResult == ResponseCode::ReconnectDenied) {
		std::cout << "Failed to reconnect, starting over." << std::endl;
		registration_required = true;
	}
	else if (reconnectResult == ResponseCode::ServerFailed) {
		throw std::runtime_error("Server failed during reconnection.");
	}
	else {
		connected = true;
	}
}

void Client::transmitFile() {
	std::cout << "\nSending file." << std::endl;
	int attempts = 1;
	while (attempts <= RETRY_FILE_ATTEMPTS) {
		sendFile();
		if (validCRCresponse()) {
			validCRC();
			confirmMessage();
			std::cout << "File sent successfully." << std::endl;
			break;
		}

		if (attempts != RETRY_FILE_ATTEMPTS) {
			invalidCRCretry();
		}
		else {
			invalidCRCabort();
			std::cout << "File transmission failed.\nABORTING." << std::endl;
			break;
		}
		attempts++;
	}
}

void Client::handleError(const std::exception& e) {
	socket.close();
	std::cerr << "Error: " << e.what() << std::endl;
}

void Client::saveDetailsToFile() {
	try {
		meInfo->saveDetailsToFile(client_name, client_id, private_key_str);
		std::cout << "Client details saved to file successfully." << std::endl;
	}
	catch (const std::exception& e) {
		std::cerr << "Error saving client details to file: " << e.what() << std::endl;
	}
}


void Client::confirmMessage() {
	// Get response header
	ResponseHeader header = SocketHandler::receiveStruct<ResponseHeader>(socket);

	// Check server response
	if (header.code == ResponseCode::ServerFailed) {
		serverFailed();
	}
	else if (header.code != ResponseCode::ConfirmMessage) {
		std::string err = "Unexpected response";
		throw std::exception(err.c_str());
	}

	// Receive and discard the response according to the protocol
	ConfirmMessageResponse response = SocketHandler::receiveStruct<ConfirmMessageResponse>(socket);
}


bool Client::successfulRegistration() {
	// Get response header
	ResponseHeader header = SocketHandler::receiveStruct<ResponseHeader>(socket);

	// Check server response
	if (header.code == ResponseCode::ServerFailed) {
		std::cout << "Server failed" << std::endl;
		return false;
	}
	else if (header.code == ResponseCode::RegistrationFailed) {
		std::cout << "Server denied registration" << std::endl;
		return false;
	}
	else if (header.code != ResponseCode::SuccessfulRegistration) {
		std::cout << "Unexpected response" << std::endl;
		return false;
	}

	registration_required = false;

	// Get response and copy the client ID
	SuccessfulRegistrationResponse response = SocketHandler::receiveStruct<SuccessfulRegistrationResponse>(socket);
	memcpy_s(client_id, sizeof(client_id), response.client_id, sizeof(response.client_id));

	return true;
}


bool Client::validCRCresponse() {
	// Get response header
	ResponseHeader header = SocketHandler::receiveStruct<ResponseHeader>(socket);

	// Check server response
	if (header.code == ResponseCode::ServerFailed) {
		serverFailed();
	}
	else if (header.code != ResponseCode::ValidCRCresponseCode) {
		std::cout << "Unexpected response" << std::endl;
		return false;
	}

	// Get response
	ValidCRCResponse response = SocketHandler::receiveStruct<ValidCRCResponse>(socket);
	auto file_crc = CRC32().fileCRCcalc(file_to_send_path);

	return response.checksum == file_crc;
}
#pragma pack(push, r1, 1)
uint16_t Client::reconnectSuccessfully()
{
	ResponseHeader header = SocketHandler::receiveStruct<ResponseHeader>(socket);

	// Check the server's response
	if (header.code == ResponseCode::ServerFailed)
	{
		serverFailed();        // Handle server failure
	}
	else if (header.code == ResponseCode::ApproveReconnect)
	{
		// Handle successful reconnection
		ApproveReconnectResponse response{};
		auto symetric_key_size = header.payload_size - CLIENT_ID_SIZE;
		response.client_id = new unsigned char[CLIENT_ID_SIZE];
		response.symetric_key = new unsigned char[symetric_key_size];

		// Receive response data
		SocketHandler::receiveBytes(response.client_id, CLIENT_ID_SIZE, socket);
		SocketHandler::receiveBytes(response.symetric_key, symetric_key_size, socket);

		// Decrypt the symmetric key using RSA
		public_key_str = rsaWrapper->decrypt(response.symetric_key, symetric_key_size);
		// Set the client as connected
		connected = true;
		// Clean up allocated memory
		delete[] response.client_id;
		delete[] response.symetric_key;
	}
	else
	{
		// Handle denied reconnection
		ReconnectDeniedResponse response = SocketHandler::receiveStruct<ReconnectDeniedResponse>(socket);
		registration_required = true;
	}
	// Return the response code
	return header.code;
}

void Client::serverFailed() {
	std::string error_message = "Server failed. ";
	throw std::runtime_error(error_message.c_str());
}


bool Client::publicKeySentSuccessfully()
{
	// Get response header
	ResponseHeader header = SocketHandler::receiveStruct<ResponseHeader>(socket);

	if (header.code == ResponseCode::ServerFailed) {
		serverFailed();
	}

	if (header.code != ResponseCode::KeySentGetAES) {
		std::cerr << "Unexpected response code: " << header.code << std::endl;
		return false;
	}

	// Initialize the response
	KeySentGetAESresponse response{};
	auto symetric_key_size = header.payload_size - CLIENT_ID_SIZE;

	response.client_id = new unsigned char[CLIENT_ID_SIZE];
	response.symetric_key = new unsigned char[symetric_key_size];

	// Receive the response data
	SocketHandler::receiveBytes(response.client_id, CLIENT_ID_SIZE, socket);
	SocketHandler::receiveBytes(response.symetric_key, symetric_key_size, socket);

	// Decrypt the symmetric key
	public_key_str = rsaWrapper->decrypt(response.symetric_key, symetric_key_size);

	// Clean up memory
	delete[] response.client_id;
	delete[] response.symetric_key;

	return true;

}

#pragma pack(pop, r1)

Client::~Client() {
	delete meInfo;     // Free meInfo object
	delete rsaWrapper; // Free rsaWrapper object
}



