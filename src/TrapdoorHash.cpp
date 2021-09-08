#include "TrapdoorHash.hpp"

std::vector<uint8_t> TrapdoorHash::hash(const uint8_t in[], size_t length,
								const Botan::BigInt& r)
{
	Botan::BigInt msg(in, length);
	Botan::BigInt hash = m_key->hash(msg, r); 
	const uint8_t* temp_hash_ptr = reinterpret_cast<const uint8_t*>(hash.data());
	return std::vector<uint8_t>(temp_hash_ptr, temp_hash_ptr + hash.bytes());
}