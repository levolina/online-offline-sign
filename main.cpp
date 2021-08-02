#include <botan/auto_rng.h>
#include <botan/ec_group.h>
#include <botan/pubkey.h>
#include <botan/hex.h>

#include <botan/rsa.h>

#include <botan/bigint.h>
#include <botan/dl_group.h>
#include <botan/numthry.h>

#include <iostream>
#include <string.h>

#define DEBUG_BITS 1024

// Trapdoor hash function
// Based on the Discrete Log Assumption (2)
class THF 
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
	void generateKey(size_t keyLen)
	{
		Botan::AutoSeeded_RNG rng;
		m_keyDlGroup = Botan::DL_Group(rng, Botan::DL_Group::PrimeType::Strong,
               keyLen * 8, 0);
		m_keyAlpha = Botan::BigInt::random_integer(rng, 0, m_keyDlGroup.get_q());
		m_keyY = m_keyDlGroup.power_g_p(m_keyAlpha);

		std::cout << "p = " << m_keyDlGroup.get_p() << std::endl; 
		std::cout << "q = " << m_keyDlGroup.get_q() << std::endl; 
		std::cout << "g = " << m_keyDlGroup.get_g() << std::endl; 
		std::cout << "Alpha = " << m_keyAlpha << std::endl;
		std::cout << "Y = " << m_keyY << std::endl;
	}

public:
	/**
      * Create THF
      * @param keySize size of key to be used in algorithm
	  */
	THF(size_t keySize = 128)
	{
		// Initialization
		m_keyLen=keySize; 
		generateKey(keySize);
	}

	/**
      * Calculate hash value
      * @param r random integer from Zq
	  * @param data data to calculate hash from
	  * @param dataLen lenght of data (in bytes)
      */
	Botan::BigInt hash(Botan::BigInt r, const uint8_t* data, size_t dataLen)
	{
		Botan::BigInt msg(data, dataLen);
		Botan::BigInt hashValue = Botan::BigInt::zero(); 
		msg = m_keyDlGroup.mod_q(msg); 
		hashValue = m_keyDlGroup.multi_exponentiate(msg, m_keyY, r);
		std::cout << "HASH:" << hashValue << std::endl; 
		return hashValue;
	}
};

class Signer {
	
}; 

int create_sign()
{
	Botan::AutoSeeded_RNG rng;
  	// Generate keypair
	Botan::RSA_PrivateKey key(rng, DEBUG_BITS);

  	std::string text("This is a tasty burger!");
  	std::vector<uint8_t> data(text.data(),text.data()+text.length());
	// sign data
	Botan::PK_Signer signer(key, rng, "EMSA1(SHA-256)");
	signer.update(data);
	std::vector<uint8_t> signature = signer.signature(rng);
	std::cout << "Signature:" << std::endl << Botan::hex_encode(signature);
	// verify signature
	Botan::PK_Verifier verifier(key, "EMSA1(SHA-256)");
	verifier.update(data);
	std::cout << std::endl << "is " << (verifier.check_signature(signature)? "valid" : "invalid");
	return 0;
  }
/*

int main()
{
	genRandNum();
	Botan::AutoSeeded_RNG rng;
	// Generate ECDSA keypair
	Botan::ECDSA_PrivateKey key(rng, Botan::EC_Group("secp521r1"));

	std::string text("This is a tasty burger!");
	std::vector<uint8_t> data(text.data(),text.data()+text.length());
	// sign data
	Botan::PK_Signer signer(key, rng, "EMSA1(SHA-256)");
	signer.update(data);
	std::vector<uint8_t> signature = signer.signature(rng);
	std::cout << "Signature:" << std::endl << Botan::hex_encode(signature);
	// verify signature
	Botan::PK_Verifier verifier(key, "EMSA1(SHA-256)");
	verifier.update(data);
	std::cout << std::endl << "is " << (verifier.check_signature(signature)? "valid" : "invalid") << std::endl;
	return 0;
}*/

int main()
{
	THF test; 
	const char teststr[] = "Hello";

	test.hash(34, reinterpret_cast<const uint8_t*>(teststr), strlen(teststr));
	//test.calculate_r();
	return 0;
}

