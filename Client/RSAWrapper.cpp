#include "RSAWrapper.h"
#include <iostream>
#include <filesystem>
#include <boost/asio.hpp>
#include <modes.h>
#include <aes.h>
#include <filters.h>
#include <files.h>

#pragma pack(push, r1, 1)
void RSAWrapper::generateKeys()
{
	private_key.Initialize(_rng, BITS);
}

std::string RSAWrapper::getPublicKey()
{
	CryptoPP::RSAFunction publicKey(this->private_key);
	std::string key;
	CryptoPP::StringSink ss(key);
	publicKey.Save(ss);
	public_key_str = key;
	return public_key_str;
}

std::string RSAWrapper::getPrivateKey()
{
	std::string key;
	CryptoPP::StringSink ss(key);
	private_key.Save(ss);
	private_key_str = key;
	return private_key_str;
}

void RSAWrapper::loadKey(std::string key)
{
	CryptoPP::StringSource ss(key, true);
	private_key.Load(ss);
}


std::string RSAWrapper::decrypt(unsigned char* encrypted, size_t size)
{
	std::string decrypted;
	std::string cipher;
	cipher.assign(reinterpret_cast<char*>(encrypted), size);

	CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(private_key);

	// Assert in case of decryption error (zero plaintext length)
	size_t dpl = decryptor.MaxPlaintextLength(size);
	assert(0 != dpl);

	// Perform decryption
	CryptoPP::StringSource ss(cipher, true,
		new CryptoPP::PK_DecryptorFilter(_rng, decryptor,
			new CryptoPP::StringSink(decrypted)));

	// Update and return the public key string
	public_key_str = decrypted;
	return public_key_str;
}


std::string RSAWrapper::encryptFile(std::string file_path)
{
	// Initialize key and IV
	CryptoPP::SecByteBlock key(KEY_SIZE), iv(CryptoPP::AES::BLOCKSIZE);
	std::memset(iv, 0, iv.size()); // Initialize IV with zeros

	// Load file
	auto path = std::filesystem::path(file_path);
	std::ifstream file(path, std::ios::binary);

	// Copy public key into key block
	memcpy_s(key, key.size(), public_key_str.c_str(), public_key_str.length());

	std::string cipher;

	// Encrypt using AES in CBC mode
	CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryptor{ key, key.size(), iv };
	auto stream_filter = new CryptoPP::StreamTransformationFilter(encryptor,
		new CryptoPP::StringSink(cipher));
	CryptoPP::FileSource file_Source(file, true, stream_filter);

	// Close file if open
	if (file.is_open())
		file.close();

	return cipher;
}
#pragma pack(pop, r1)