#pragma once
#include <boost/asio.hpp>
#include <string>
#include <sstream>
#include <stdexcept>

class SocketHandler {
public:
    /// Receives a specified number of bytes from the server.
    /// @param buffer Pointer to the buffer where received data will be stored.
    /// @param bytes Number of bytes to receive.
    /// @param socket Reference to the TCP socket used for communication.
    /// @throws std::runtime_error if the number of received bytes is less than expected.
    static void receiveBytes(unsigned char* buffer, size_t bytes, boost::asio::ip::tcp::socket& socket) {
        size_t receivedBytes = boost::asio::read(socket, boost::asio::buffer(buffer, bytes));
        if (receivedBytes < bytes) {
            std::string err = "Receive from server error: expected " + std::to_string(bytes) + " received: " + std::to_string(receivedBytes);
            throw std::runtime_error(err);
        }
    }

    /// Receives data from the server and converts it to a struct of type T.
    /// @tparam T The type of struct to receive.
    /// @param socket Reference to the TCP socket used for communication.
    /// @return The received struct of type T.
    /// @throws std::runtime_error if the number of received bytes is less than the size of T.
    template<typename T>
    static T receiveStruct(boost::asio::ip::tcp::socket& socket) {
        T structTemp;
        auto charStruct = reinterpret_cast<unsigned char*>(&structTemp);

        size_t receivedBytes = boost::asio::read(socket, boost::asio::buffer(charStruct, sizeof(T)));
        if (receivedBytes < sizeof(T)) {
            std::string err = "Receive from server error: expected " + std::to_string(sizeof(T)) + " received: " + std::to_string(receivedBytes);
            throw std::runtime_error(err);
        }

        return structTemp;
    }

    /// Sends a struct of type T to the server.
    /// @tparam T The type of struct to send.
    /// @param data Pointer to the struct of type T to be sent.
    /// @param socket Reference to the TCP socket used for communication.
    /// @throws std::runtime_error if the number of sent bytes is less than the size of T.
    template<typename T>
    static void sendBytes(const T* data, boost::asio::ip::tcp::socket& socket) {
        const auto dataBytes = reinterpret_cast<const unsigned char*>(data);
        size_t bytesSent = boost::asio::write(socket, boost::asio::buffer(dataBytes, sizeof(T)));

        if (bytesSent < sizeof(T)) {
            std::string err = "Send to server error: expected " + std::to_string(sizeof(T)) + " sent: " + std::to_string(bytesSent);
            throw std::runtime_error(err);
        }
    }
};
