#include "TrapdoorHash.hpp"

std::vector<uint8_t> TrapdoorHash::hash(const uint8_t in[], size_t length,
								const Botan::BigInt& r)
{
	if (m_hash_key == nullptr)
	{
		throw std::runtime_error("Error. Key is not set properly");
	}

	Botan::BigInt hash = m_hash_key->hash(Botan::BigInt(in, length), r);
	const uint8_t* temp_hash_ptr = reinterpret_cast<const uint8_t*>(hash.data());
	return std::vector<uint8_t>(temp_hash_ptr, temp_hash_ptr + hash.bytes());
}