#include "Base64Wrapper.h"

std::string Base64Wrapper::encode(const std::string& ciphertext)
{
	std::string encoded;
	CryptoPP::StringSource ss(ciphertext, true,
		new CryptoPP::Base64Encoder(
			new CryptoPP::StringSink(encoded), false
		));

	return encoded;
}

std::string Base64Wrapper::decode(const std::string& ciphertext)
{
	std::string decoded;
	CryptoPP::StringSource ss(ciphertext, true,
		new CryptoPP::Base64Decoder(
			new CryptoPP::StringSink(decoded)
		));
	return decoded;
}