#include <botan/bigint.h>
#include <botan/dl_group.h>

class TrapdoorHash 
{
private:
	// Trapdoor Key
	// Public hash key: (p, g, y)
	// Private trapdoor key : (alpha)
	Botan::DL_Group m_keyDlGroup; 
	Botan::BigInt m_keyAlpha = Botan::BigInt::zero(); 
	Botan::BigInt m_keyY = Botan::BigInt::zero(); 

	size_t m_keyLen = 0;

	/**
      * Create a DSA group with a given seed.
      * @param keyLen size in bytes
      */
	void generateKey(size_t keyLen);

public:
	/**
      * Create TrapdoorHash
      * @param keySize size of key to be used in algorithm
	  */
	TrapdoorHash(size_t keySize = 128);

	/**
      * Calculate hash value
      * @param r random integer from Zq
	  * @param data data to calculate hash from
	  * @param dataLen lenght of data (in bytes)
      */
	Botan::BigInt hash(Botan::BigInt r, const uint8_t* data, size_t dataLen);
};