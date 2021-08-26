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
	ITH_HashKey* m_key;
public:
	TrapdoorHash() {};

	TrapdoorHash(const ITH_HashKey& private_key)
	{
		m_key = private_key;
	};

	~TrapdoorHash(); 
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
	Botan::BigInt collision(ITH_PrivateKey& private_key, const std::vector<uint8_t> msg1, 
							const Botan::BigInt& r1, const std::vector<uint8_t> msg2)
	{
		return private_key.collision(msg1, r1, msg2);
	}

	size_t get_random_element_size()
	{
		return m_key.get_random_element_size();
	}
};