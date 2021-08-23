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
	ITH_HashKey() = default;
	ITH_HashKey(const ITH_HashKey& other) = default;
	ITH_HashKey& operator=(const ITH_HashKey& other) = default;
	virtual ~ITH_HashKey() = default;

	virtual Botan::BigInt hash(Botan::BigInt msg, Botan::BigInt r);
};

class ITH_PrivateKey : public ITH_HashKey
{
public:
	ITH_PrivateKey() = default;
	ITH_PrivateKey(const ITH_PrivateKey& other) = default;
	ITH_PrivateKey& operator=(const ITH_PrivateKey& other) = default;
	virtual ~ITH_PrivateKey() = default;

	virtual Botan::BigInt collision(const std::vector<uint8_t> msg1, const Botan::BigInt& r1, const std::vector<uint8_t> msg2);
};

/**
 * The public hash key for trapdoor hash family 
 * based on the Discrete Log Assumption
 */
class TH_DLA_HashKey : public virtual ITH_HashKey
{
protected:
	Botan::DL_Group m_key_dl_group;
	Botan::BigInt m_key_y; 
public:
	TH_DLA_HashKey() {};
	/**
	 * Construct a hash key from the specified parameters
	 */
	TH_DLA_HashKey(const Botan::BigInt& p, const Botan::BigInt& g, const Botan::BigInt& y);

	/**
	  * Calculate hash value
	  * @param msg BigInt which contain msg in form of integer
	  * @param r random BigInt from Zq
	*/
	Botan::BigInt hash(const Botan::BigInt& msg, const Botan::BigInt& r) override; 

	std::string name() const
	{
		return "A trapdoor hash family based on the Discrete Log Assumption";
	}

	void print();

	/**
	 * @return size in bits of random element from finite field wchich used in hash function
	 */
	size_t get_random_element_size() const 
	{ 
		return m_key_dl_group.q_bits(); 
	}

	/**
	 * @return random safe prime p
	 */
	const Botan::BigInt& get_p() const { return m_key_dl_group.get_p(); }

	/**
	 * @return second prime q
	 */
	const Botan::BigInt& get_q() const { return m_key_dl_group.get_q(); }

	/**
	 * Get g with g ^ q = 1 (mod p)
	 * @return g
	 */
	const Botan::BigInt& get_g() const { return m_key_dl_group.get_g(); } 

	/** 
	 * Get y with y = g ^ alpha (mod p)
	 * @return y
	 */
	const Botan::BigInt& get_y() const; 
};

/**
 * The private key for trapdoor hash family 
 */
class TH_DLA_PrivateKey final: public TH_DLA_HashKey, public ITH_PrivateKey
{
private:
	Botan::BigInt m_key_alpha;
public:
	TH_DLA_PrivateKey() {};
	/**
	 * Construct a private key from the specified parameters
	 */
	TH_DLA_PrivateKey(const Botan::BigInt& p, const Botan::BigInt& g, 
				const Botan::BigInt& y, const Botan::BigInt& alpha);
	
	/**
	 * Generate a new private key with the specified bit length
	 */
	TH_DLA_PrivateKey(Botan::RandomNumberGenerator &rng, 
					size_t bits); 

	/**
	 * Get private key alpha
	 * @return alpha
	 */
	const Botan::BigInt& get_alpha() const { return m_key_alpha; }
	
	/** 
	 * Find collision using tradoor key [r2]
	 * Such as hash(msg1, r1) = hash(msg2, r2)
	 * @return r2
	 */
	Botan::BigInt collision(const std::vector<uint8_t> msg1, const Botan::BigInt& r1, 
							const std::vector<uint8_t> msg2) override;
	
	void print();
}; 

/**
 * The Trapdoor hash family
 */
class TrapdoorHash
{
private:
	ITH_PrivateKey m_key;
	std::vector<uint8_t> m_data;
public:
	TrapdoorHash() {};

	TrapdoorHash(const TH_DLA_PrivateKey& private_key)
	{
		m_key = private_key;
	};

	~TrapdoorHash(); 
	TrapdoorHash(const TrapdoorHash&) = delete;
	TrapdoorHash& operator= (const TrapdoorHash&) = delete;

	/**
	 * Sign a message all in one go
	 * @param in the message to sign as a byte array
	 * @param length the length of the above byte array
	 * @param rng the rng to use
	 * @return signature
	 */
	Botan::BigInt sign_message(const uint8_t in[], size_t length,
									Botan::RandomNumberGenerator& rng)
	{
		this->update(in, length);
		return this->signature(rng);
	}

	/**
	 * Sign a message.
	 * @param in the message to sign
	 * @param rng the rng to use
	 * @return signature
	*/
	template<typename Alloc>
	Botan::BigInt sign_message(const std::vector<uint8_t, Alloc>& in,
										Botan::RandomNumberGenerator& rng)
	{
		return sign_message(in.data(), in.size(), rng);
	}

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

	/**
	 * Get the signature of the so far processed message (provided by the
	 * calls to update()).
	 * @param rng the rng to use
	 * @return signature of the total message
	 */
	Botan::BigInt signature(const Botan::BigInt& r);

};