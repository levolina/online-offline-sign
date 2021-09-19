#include <iostream>
#include <botan/bigint.h>
#include <botan/dl_group.h>

class ITH_HashKey 
{
public:
	ITH_HashKey() {};
	ITH_HashKey(Botan::RandomNumberGenerator& rng, size_t bits);
	ITH_HashKey(const ITH_HashKey &obj);
	virtual ~ITH_HashKey() {};

	virtual size_t get_random_element_size() const = 0; 
	virtual Botan::BigInt hash(const Botan::BigInt& msg,
		const Botan::BigInt& r) = 0;
};

class ITH_PrivateKey : public ITH_HashKey
{
public:
	ITH_PrivateKey() {}; 
	ITH_PrivateKey(Botan::RandomNumberGenerator& rng, size_t bits);
	ITH_PrivateKey(const ITH_PrivateKey &obj);

	virtual ITH_HashKey* hash_key() = 0;
	virtual ~ITH_PrivateKey() {};

	virtual Botan::BigInt collision(const std::vector<uint8_t> msg1, const Botan::BigInt& r1, 
		const std::vector<uint8_t> msg2) = 0;
};

/**
 * The public hash key for trapdoor hash family 
 * based on the Discrete Log Assumption
 */
class TH_DLA_HashKey : public ITH_HashKey
{
protected:
	Botan::DL_Group m_key_dl_group;
	Botan::BigInt m_key_y; 
public:
	TH_DLA_HashKey()=default;

	TH_DLA_HashKey(const TH_DLA_HashKey &other) : ITH_HashKey(other)
	{
		m_key_dl_group = other.m_key_dl_group;
		m_key_y = other.m_key_y;
	}

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
	const Botan::BigInt& get_y() const { return m_key_y; }; 
};

/**
 * The private key for trapdoor hash family 
 * based on the Discrete Log Assumption
 */
class TH_DLA_PrivateKey final: public TH_DLA_HashKey, public ITH_PrivateKey
{
private:
	Botan::BigInt m_key_alpha;
public:
	TH_DLA_PrivateKey()=default;
	
	TH_DLA_PrivateKey(const TH_DLA_PrivateKey &other): TH_DLA_HashKey(other), ITH_PrivateKey(other)
	{
		m_key_alpha = other.m_key_alpha;
	}
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

	Botan::BigInt hash(const Botan::BigInt& msg, const Botan::BigInt& r) 
	{
		return TH_DLA_HashKey::hash(msg, r);
	}

	size_t get_random_element_size() const 
	{ 
		return TH_DLA_HashKey::get_random_element_size();
	}

	TH_DLA_HashKey* hash_key()
	{
		return dynamic_cast<TH_DLA_HashKey*> (this);
	}

}; 
