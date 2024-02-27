#include "InfoFilesHandler.h"
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <boost/asio.hpp>
#include <base64.h>
#include "Base64Wrapper.h"
#include "Protocol.h"
#include <filesystem>
#include <sstream>
#include <iomanip>

// MeInfo definitions
MeInfo::MeInfo() {
    loadFile();
}

MeInfo::~MeInfo() {
    delete[] clientId;
}

void MeInfo::loadFile() {
    try {
        std::ifstream file;
        file.open(ME_FILE);
        if (!file) {
            std::cout << "Cannot open file: " << ME_FILE << " retry.." << std::endl;
            return;
        }

        // Try to read client name
        std::string line;
        std::getline(file, line);
        if (line.length() == 0) {
            std::cout << "Client name is missing" << ME_FILE << std::endl;
            return;
        }

        this->clientName = line;
        std::getline(file, line);
        if (line.length() == 0) {
            std::cout << "Client ID is missing" << ME_FILE << std::endl;
            return;
        }

        UUID::stringToUuid(clientId, line, UUID_SIZE);
        std::getline(file, line);
        if (line.length() == 0) {
            std::cout << "Private key is missing" << ME_FILE << std::endl;
            return;
        }

        this->private_key = Base64Wrapper::decode(line);
        this->registration_required = false;
        file.close();
    }
    catch (const std::exception&) {
        this->registration_required = true;
    }
}

void MeInfo::saveDetailsToFile(std::string client_name, unsigned char client_id[], std::string private_key_str) {
    std::ofstream file(ME_FILE);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot write to file: " + ME_FILE);
    }
    file << client_name << std::endl;
    file << UUID::uuidToString(client_id, UUID_SIZE) << std::endl;
    file << Base64Wrapper::encode(private_key_str);
    file.close();
}

bool MeInfo::getRegistrationRequired() const { return registration_required; }
std::string MeInfo::getPrivateKey() const { return private_key; }
std::string MeInfo::getClientName() const { return clientName; }
unsigned char* MeInfo::getClientId() const { return clientId; }

// TransferInfo definitions
TransferInfo::TransferInfo() {
    std::ifstream transferInfoFile(TRANSFER_FILE);
    if (!transferInfoFile.is_open()) {
        throwError("Cannot open " + TRANSFER_FILE);
    }

    std::string line;
    std::getline(transferInfoFile, line);
    auto index = line.find(':');
    if (index == std::string::npos) {
        throwError("Incorrect file format, file: " + TRANSFER_FILE);
    }
    hostIP = line.substr(0, index);
    if (!validateIpAddress(hostIP)) {
        std::cout << "Incorrect host ip, ip set to default: " << DEFAULT_HOST_IP << std::endl;
        hostIP = DEFAULT_HOST_IP;
    }

    try {
        port = std::stoi(line.substr(index + 1));
    }
    catch (...) {
        std::cout << "Incorrect port, port set to default: " << DEFAULT_PORT << std::endl;
        port = DEFAULT_PORT;
    }

    getline(transferInfoFile, clientName);
    if (clientName.size() == 0 || line.size() > MAX_CLIENT_NAME) {
        throwError("Invalid client name in " + TRANSFER_FILE);
    }

    std::string path;
    getline(transferInfoFile, path);
    if (!std::filesystem::is_regular_file(std::filesystem::path(path))) {
        throwError("File does not exist " + path);
    }
    filePath = path;
    transferInfoFile.close();
}

void TransferInfo::throwError(std::string msg) {
    throw std::runtime_error(msg);
}

bool TransferInfo::validateIpAddress(const std::string& ip) {
    try {
        auto ip_add = boost::asio::ip::make_address(ip);
        return ip_add.is_v4();
    }
    catch (...) {
        return false;
    }
}

std::string TransferInfo::getHostIP() const { return hostIP; }
uint16_t TransferInfo::getPort() const { return port; }
std::string TransferInfo::getClientName() const { return clientName; }
std::string TransferInfo::getFilePath() const { return filePath; }

// UUID definitions
std::string UUID::uuidToString(const unsigned char* uuid, size_t len)
{
    std::ostringstream converter;
    converter << std::hex << std::setfill('0');

    for (size_t i = 0; i < len; ++i) {
        converter << std::setw(2) << (static_cast<unsigned>(uuid[i]) & 0xFF);
    }
    return converter.str();
}

void UUID::stringToUuid(unsigned char* dest, const std::string& src, size_t len)
{
    if (src.length() != len * 2) {
        throw std::invalid_argument("Invalid UUID format");
    }

    for (size_t i = 0; i < len; ++i) {
        std::string byteString = src.substr(2 * i, 2);
        unsigned int byte;
        std::istringstream(byteString) >> std::hex >> byte;
        dest[i] = static_cast<unsigned char>(byte & 0xFF);
    }
}