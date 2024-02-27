#ifndef RSA_WRAPPER_H
#define RSA_WRAPPER_H

#include <rsa.h>
#include <osrng.h>
#include <string>

class RSAWrapper {
    static constexpr unsigned int KEY_SIZE = 16;
    static constexpr unsigned int BITS = 1024;
public:
    /// Generates public and private RSA keys.
    void generateKeys();

    /// Returns the public key as a string.
    /// @return A string representation of the public key.
    std::string getPublicKey();

    /// Returns the private key as a string.
    /// @return A string representation of the private key.
    std::string getPrivateKey();

    /// Decrypts the given encrypted data using the private key.
    /// @param encrypted Pointer to the encrypted data.
    /// @param size Size of the encrypted data.
    /// @return A string containing the decrypted data.
    std::string decrypt(unsigned char* encrypted, size_t size);

    /// Encrypts the content of a file specified by the path using the public key.
    /// @param filePath Path to the file to be encrypted.
    /// @return A string containing the encrypted file content.
    std::string encryptFile(std::string filePath);

    /// Loads a given string key into the CryptoPP::RSA::PrivateKey object.
    /// @param key The key string to be loaded.
    void loadKey(std::string key);

private:

    CryptoPP::AutoSeededRandomPool _rng;
    CryptoPP::RSA::PrivateKey private_key;
    std::string public_key_str;
    std::string private_key_str;
};

#endif // RSA_WRAPPER_H
