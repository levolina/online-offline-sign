#include <botan/auto_rng.h>
#include <botan/ecdsa.h>
#include <botan/ec_group.h>
#include <botan/pubkey.h>
#include <botan/hex.h>

#include <botan/bigint.h>
#include <botan/dl_group.h>
#include <botan/numthry.h>

#include <iostream>
#include <string.h>


/* 
  Idea is to make smth like this
class Signer
{
	Botan::PK_Signer signer(key, rng, "EMSA1(SHA-256)", "THF");
}
*/

// Trapdoor hash function
// first based on the Discrete Log Assumption
class THF 
{
private:
	// Private Trapdoor Key
	Botan::BigInt m_keyP = Botan::BigInt::zero(); 
	Botan::BigInt m_keyQ = Botan::BigInt::zero(); 
	// Public Hash Key
	Botan::BigInt m_keyN = Botan::BigInt::zero(); 

	size_t m_keyLen = 0;

	/**
      * Create a DSA group with a given seed.
      * @param keyLen size in bytes
      */
	void generateKey(size_t keyLen)
	{
		Botan::AutoSeeded_RNG rng;
		Botan::DL_Group dl_group(rng, Botan::DL_Group::PrimeType::Strong,
               keyLen * 8, 0);
		std::cout << "p = " << dl_group.get_p() << std::endl; 
		std::cout << "q = " << dl_group.get_q() << std::endl; 
		std::cout << "g = " << dl_group.get_g() << std::endl; 
	}

	/*
	void generateKey_1(size_t keyLen)
	{
		Botan::AutoSeeded_RNG rng;
		m_keyP = Botan::BigInt::zero();
		m_keyQ = Botan::BigInt::zero();
		
		while (m_keyP % 8 != 3)
		{
			m_keyP.randomize(rng, keyLen / 2, false); 
		} 

		while (m_keyQ % 8 != 7)
		{
			m_keyQ.randomize(rng, keyLen / 2, false); 
		}
		m_keyN = m_keyP * m_keyQ;
		// DEBUG
		std::cout << "p = " << m_keyP << std::endl; 
		std::cout << "q = " << m_keyQ << std::endl;
		std::cout << "n = " << m_keyN << std::endl;
	}*/

public:
	THF(size_t keySize = 32)
	{
		// Initialization
		m_keyLen=keySize; 
		generateKey(keySize);
	}

	/*
	Botan::BigInt calculate_r()
	{
		static Botan::AutoSeeded_RNG rng;
		Botan::BigInt r(rng, m_keyLen, false);
		r = r % m_keyN; 

		while(Botan::jacobi(r, m_keyP) != 1 || Botan::jacobi(r, m_keyQ) != 1)
		{
			r.random_integer(rng, 0, m_keyN);
		}
		// DEBUG
		std::cout << "Generated r = " << r << std::endl; 
		return r; 
	}

	Botan::BigInt hash(Botan::BigInt r, char* data)
	{
		Botan::BigInt hashValue = Botan::BigInt::zero();
		Botan::BigInt message(reinterpret_cast<const uint8_t*>(data), strlen(data)); // TODO: change strlen 
		Botan::Power_Mod pwme(m_keyN, EXP_IS_LARGE); // TODO: see hints as second parameter
		pwme.set_base(4);
		pwme.set_exponent(message);
		hashValue = pwme.execute();

		pwme.set_base(r);

		Botan::BigInt exponent;
		pwme.set_exponent(exponent.power_of_2(strlen(message)*8));
		hashValue *= pwme.execute();
		hashValue %= m_keyN; 

		std::cout << "Result:" << hashValue << std::endl; 
		return hashValue; 
	}*/

};


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
	//test.calculate_r();
	return 0;
}
