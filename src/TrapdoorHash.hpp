#include <botan/bigint.h>
#include "Key.hpp"
#include <botan/secmem.h>
#include <botan/rng.h>
#include <botan/buf_comp.h>
#include <botan/numthry.h>
#include <iostream>

/**
 * The Trapdoor hash family
 */
class TrapdoorHash
{
private: 
	ITH_HashKey* m_hash_key = nullptr;
	ITH_PrivateKey* m_private_key = nullptr;
public:
	TrapdoorHash() {};

	TrapdoorHash(ITH_HashKey* hash_key)
	{
		PRINT_DEBUG("Init with Hash Key");
		if (hash_key == nullptr)
		{
			throw std::runtime_error("Error. Pointer is null"); 
		}
		m_hash_key = hash_key;
	}

	TrapdoorHash(ITH_PrivateKey* private_key)
	{
		PRINT_DEBUG("Init with Private Key");
		if (private_key == nullptr)
		{
			throw std::runtime_error("Error. Pointer is null"); 
		}
		m_private_key = private_key;
		m_hash_key = private_key->hash_key();
	}

	~TrapdoorHash()=default; 
	TrapdoorHash(const TrapdoorHash&) = delete;
	TrapdoorHash& operator= (const TrapdoorHash&) = delete;

	/**
	 * Hash a message all in one go
	 * @param in the message to hash as a byte array
	 * @param length the length of the above byte array
	 * @param r random element
	 * @return hash value
	 */
	std::vector<uint8_t> hash(const uint8_t in[], size_t length,
								const Botan::BigInt& r);

	/**
	 * Hash a message.
	 * @param in the message to hash
	 * @param rng the hash to use
	 * @return hash value
	*/
	template<typename Alloc>
	std::vector<uint8_t> hash(const std::vector<uint8_t, Alloc>& in,
								const Botan::BigInt& r)
	{
		return hash(in.data(), in.size(), r);
	}

	/**
	 * Find a collision with use of trapdoor
	 */
	Botan::BigInt collision(const std::vector<uint8_t> msg1, const Botan::BigInt& r1, 
							const std::vector<uint8_t> msg2)
	{
		if (m_private_key == nullptr)
		{
			throw std::runtime_error("Error. Private key isn\'t set");
		}
		return m_private_key->collision(msg1, r1, msg2);
	}

	size_t get_random_element_size()
	{
		return m_hash_key->get_random_element_size();
	}
};