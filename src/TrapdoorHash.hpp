#include <botan/bigint.h>
#include <botan/secmem.h>
#include <botan/dl_group.h>
#include <botan/rng.h>
#include <botan/buf_comp.h>
#include <botan/numthry.h>
#include <iostream>

class ITH_HashKey 
{
public:
	ITH_HashKey() =default;
	ITH_HashKey(const ITH_HashKey& other) = default;
	ITH_HashKey& operator=(const ITH_HashKey& other) = default;
	virtual ~ITH_HashKey() = default;
};

class ITH_PrivateKey : public ITH_HashKey
{
public:
	ITH_PrivateKey() = default;
	ITH_PrivateKey(const ITH_PrivateKey& other) = default;
	ITH_PrivateKey& operator=(const ITH_PrivateKey& other) = default;
	virtual ~ITH_PrivateKey() = default;

	//virtual ITH_HashKey get_hash_key();
	//virtual bool check();
};

/**
 * The public hash key for trapdoor hash family
 */
class TH_HashKey : public ITH_HashKey
{
protected:
	Botan::DL_Group m_key_dl_group;
	Botan::BigInt m_key_y; 
public:
	TH_HashKey() {};
	/**
	 * Construct a hash key from the specified parameters
	 */
	TH_HashKey(const Botan::BigInt& p, const Botan::BigInt& g, const Botan::BigInt& y);

	/**
	  * Calculate hash value
	  * @param msg vector which contain data to calculate hash from
	  * @param r random integer from Zq
	*/
	void hash(const std::vector<uint8_t> msg, const Botan::BigInt& r);

	void print();
};

/**
 * The private key for rapdoor hash family 
 */
class TH_PrivateKey: public ITH_PrivateKey, public TH_HashKey
{
private:
	Botan::BigInt m_key_alpha;
public:
	TH_PrivateKey() {};
	/**
	 * Construct a private key from the specified parameters
	 */
	TH_PrivateKey(const Botan::BigInt& p, const Botan::BigInt& g, 
				const Botan::BigInt& y, const Botan::BigInt& alpha);
	
	/**
	 * Generate a new private key with the specified bit length
	 */
	TH_PrivateKey(Botan::RandomNumberGenerator &rng, 
					size_t bits); 
	
	/** 
	 * Find collision using tradoor key [r2]
	 * Such as hash(msg1, r1) = hash(msg2, r2)
	 */
	Botan::BigInt collision(const std::vector<uint8_t> msg1, const Botan::BigInt& r1, const std::vector<uint8_t> msg2);
	
	void print();
}; 

/**
 * The Trapdoor hash family
 */
class TrapdoorHash
{
private:
	TH_PrivateKey m_key;
	std::vector<uint8_t> m_data;
public:
	TrapdoorHash() {};

	TrapdoorHash(const TH_PrivateKey& private_key)
	{
		m_key = private_key;
	};

	//TrapdoorHash(const TH_HashKey& hash_key);

	~TrapdoorHash(); 

	TrapdoorHash(const TrapdoorHash&) = delete;
	TrapdoorHash& operator= (const TrapdoorHash&) = delete;

	/**
	 * Add a message part (single byte).
	 * @param in byte to add 
	 */
	void update(const uint8_t in) { update(&in, 1); }

	/**
	 * Add a message part.
	 * @param in the message part to add as a byte array
	 * @param length the length of the above byte array
	*/
	void update(const uint8_t in[], size_t length)
	{
		std::vector<uint8_t> vec(in, in + length);
		m_data.insert( m_data.end(), vec.begin(), vec.end() );
	}

	/**
	 * Add a message part.
	 * @param in the message part to add
	 */
	template<typename Alloc>
	void update(const std::vector<uint8_t, Alloc>& in)
	{
		m_data += in;
	}

	/**
	 * Add a message part.
	 * @param in the message part to add
	 */
	void update(const std::string& in)
	{
		update(Botan::cast_char_ptr_to_uint8(in.data()), in.size());
	}
};