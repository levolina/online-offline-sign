#include <botan/bigint.h>
#include <botan/secmem.h>
#include <botan/dl_group.h>

enum TrapdoorAlgo 
{
	TRAPDOOR_DLA
};
/**
* Trapdoor Hash Family Interface. 
*/
class ITrapdoorHash
{
public:
	/**
	 * Probabilistic polynomial-time key generation algorithm 
	 * that generates a pair hash key (HK) + trapdoor key (TK)
	 * @param key_len key size in bytes 
	*/
	virtual void generate_key(size_t key_len) = 0;

	/**
	 * Randomized hash function. Hash function is associated with a hash key HK
	 * and is applied to a message and a random element from a finite space
	 * The output of the hash function does not depend on TK
	 * @param msg the message
	 * @param msg_len the length of msg in bytes
	 * @param random_element random element from a finite field
	 */
	virtual Botan::secure_vector<uint8_t> hash(const uint8_t msg[], size_t msg_len, const uint8_t random_element[], size_t random_size) = 0;
	
	virtual ~ITrapdoorHash() = default;
};

/**
 * The Trapdoor hash family based on the Discrete Log Assumtion
 */
class TrapdoorHash_DLA: public virtual ITrapdoorHash
{
private:
	// Public hash key
	Botan::DL_Group m_key_dl_group; 
	Botan::BigInt m_key_y = 0; 
	// Private trapdoor key
	Botan::BigInt m_key_alpha = 0; 

	size_t m_key_len = 0;

public:
	/**
	  * Generates pair of key HK and TK
	  * @param key_len key size in bytes
	  */
	void generate_key(size_t key_len);

	/**
	  * Calculate hash value
	  * @param msg the message
	  * @param msg_len the length of msg in bytes
	  * @param random_element random integer from Zq
	  * @param random_size size of random element
	  * TODO: maybe change type of return value (unnnecessary move from BigInt to vector and vice-versa
	  * also think about type of random element)
	  */
	Botan::secure_vector<uint8_t> hash(const uint8_t msg[], size_t msg_len, const uint8_t random_element[], size_t random_size);

	/**
	 * Just for debug purposes to print private member values
	 */
	void debug_print(); 
};