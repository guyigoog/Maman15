#pragma once
#include "Protocol.h"
#include "InfoFilesHandler.h"
#include <boost/asio.hpp>
#include "InfoFilesHandler.h"
#include "RSAWrapper.h"
#include "CRC32.h"

class Client {
private:
    const int RETRY_FILE_ATTEMPTS = 4; ///< Maximum attempts to retry file transmission.
    MeInfo* meInfo; ///< Handles client's personal information.
    RSAWrapper* rsaWrapper; ///< Wrapper for RSA cryptographic 

    boost::asio::io_context io_context; ///< ASIO context for network operations.
    boost::asio::ip::tcp::socket socket; ///< Socket for TCP network communication.
    boost::asio::ip::tcp::resolver resolver; ///< Resolver for DNS queries within the ASIO context.

    bool registration_required; ///< Indicates if client registration is required.
    bool connected; ///< Indicates if the client is connected to the server.
    std::string client_name; ///< The client's name.
    unsigned char client_id[CLIENT_ID_SIZE]; ///< Unique identifier for the client.

    std::string public_key_str; ///< Public key of the client in string format.
    std::string private_key_str; ///< Private key of the client in string format.

    std::string file_to_send_path; ///< File path of the file to be sent.
    std::string file_name; ///< Name of the file to be sent.

    void establishConnection();
    void handleRegistration();
    void handleReconnection();
    void transmitFile();
    void handleError(const std::exception& e);

    /// Generates RSA private and public keys.
    void generateKeys();

    /// Saves client's details to a local file.
    void saveDetailsToFile();

    /// Checks server response for successful registration.
    /// @return True if registration was successful, false otherwise.
    bool successfulRegistration();

    /// Checks server response for successful public key transmission.
    /// @return True if public key was successfully sent, false otherwise.
    bool publicKeySentSuccessfully();

    /// Checks server response for successful file transmission.
    /// @return True if the server confirms file integrity, false otherwise.
    bool validCRCresponse();

    /// Checks server response for a successful reconnection attempt.
    /// @return Status code indicating the result of the reconnection attempt.
    uint16_t reconnectSuccessfully();

    /// Processes confirmation message from the server.
    void confirmMessage();

    /// Sends registration request to the server.
    void registration();

    /// Sends public key to the server.
    void sendPublicKey();

    /// Sends reconnection request to the server.
    void reconnect();

    /// Sends a file to the server.
    void sendFile();

    /// Sends a valid CRC request to the server.
    void validCRC();

    /// Sends an invalid CRC retry request to the server.
    void invalidCRCretry();

    /// Sends an invalid CRC abort request to the server.
    void invalidCRCabort();

    /// Builds a request header.
    /// @param header Pointer to the request header structure to be built.
    /// @param code The request code to be included in the header.
    /// @param payload_size The size of the payload in bytes.
    void buildRequestHeader(struct RequestHeader* header, uint16_t code, uint32_t payload_size);

    /// Throws an exception in case of server failure.
    void serverFailed();

public:
    /// Constructor for the Client class.
    /// @param transferInfo Transfer information for network communication.
    Client(const TransferInfo& transferInfo);

    /// Destructor for the Client class.
    ~Client();

    /// Starts the client's processing loop.
    void runProcess();
};
