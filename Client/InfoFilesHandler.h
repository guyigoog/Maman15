#pragma once
#include <string>
#include <boost/asio.hpp>
#include "Protocol.h"

#define DEFAULT_PORT 1357
constexpr size_t UUID_SIZE = 16;

// Class for handling UUID operations
class UUID {
public:
    /// Converts a UUID to a string representation.
    /// @param uuid Pointer to the UUID array.
    /// @param len Length of the UUID array.
    /// @return A hexadecimal string representation of the UUID.
    static std::string uuidToString(const unsigned char* uuid, size_t len);

    /// Converts a string representation to a UUID.
    /// @param dest Destination array for the UUID.
    /// @param src Source string in hexadecimal format.
    /// @param len Length of the destination array.
    static void stringToUuid(unsigned char* dest, const std::string& src, size_t len);
};

// Class for managing Me information
class MeInfo {
    const std::string ME_FILE = "me.info";

private:
    std::string clientName;
    unsigned char* clientId = new unsigned char[CLIENT_ID_SIZE] {0};
    std::string private_key;
    bool registration_required = true;

    // Reads and loads client details from file
    void loadFile();

public:
    MeInfo();
    ~MeInfo();

    // Returns registration needed state
    bool getRegistrationRequired() const;

    // Returns private key
    std::string getPrivateKey() const;

    // Returns client name
    std::string getClientName() const;

    // Saves client details to file
    void saveDetailsToFile(std::string client_name, unsigned char client_id[], std::string private_key_str);

    // Returns client ID
    unsigned char* getClientId() const;
};

// Class for managing Transfer information
class TransferInfo {
    const std::string TRANSFER_FILE = "transfer.info";
    const std::string DEFAULT_HOST_IP = "127.0.0.1";

private:
    std::string hostIP;
    uint16_t port;
    std::string clientName;
    std::string filePath;

    // Validates the IP address
    bool validateIpAddress(const std::string& ip);

    // Throws an exception in case of an uncorrectable error
    void throwError(std::string msg);

public:
    TransferInfo();

    // Retrieves various transfer details
    std::string getHostIP() const;
    uint16_t getPort() const;
    std::string getClientName() const;
    std::string getFilePath() const;
};
