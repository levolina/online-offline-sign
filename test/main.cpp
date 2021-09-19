#include <iostream>
#include "../src/Sign.hpp"
#include <botan/rsa.h>
#include <botan/auto_rng.h>

// Some tests for functionality 

// Test with predefine hash key
void ut_trapdoor_hash()
{
	Botan::AutoSeeded_RNG rng;
	Botan::RSA_PrivateKey rsa_key(rng, 1024); 
	TH_DLA_PrivateKey private_key(251387, 62849, 36711, 31862); 
	TH_DLA_HashKey* hash_key = private_key.hash_key();
	private_key.print(); 

	char buffer[] = "msg";
	uint8_t* buffer_ptr = reinterpret_cast<uint8_t*>(buffer);
	std::vector<uint8_t> test_vector(buffer_ptr, buffer_ptr + sizeof(buffer));

	Signer sig(&rsa_key, &private_key, rng);
	sig.offline_phase(rng);
	std::pair<std::vector<uint8_t>, Botan::BigInt> signature = sig.sign_message(test_vector, rng); 

	Verifier ver(&rsa_key, hash_key);
	ver.verify_message(test_vector, signature.first, signature.second);
}

// Test with random generated key 
void ut_random_generated_key()
{
	Botan::AutoSeeded_RNG rng;
	Botan::RSA_PrivateKey rsa_key(rng, 1024); 
	TH_DLA_PrivateKey private_key(rng, 1024); 
	TH_DLA_HashKey* hash_key = private_key.hash_key();
	private_key.print(); 

	char buffer[] = "msg";
	uint8_t* buffer_ptr = reinterpret_cast<uint8_t*>(buffer);
	std::vector<uint8_t> test_vector(buffer_ptr, buffer_ptr + sizeof(buffer));

	Signer sig(&rsa_key, &private_key, rng);
	sig.offline_phase(rng);
	
	std::pair<std::vector<uint8_t>, Botan::BigInt> signature = sig.sign_message(test_vector, rng); 

	Verifier ver(&rsa_key, hash_key);
	ver.verify_message(test_vector, signature.first, signature.second);
}

// Just a simple file with functionality of future library
int main()
{
	std::cout << "THF template started" << std::endl; 
	ut_trapdoor_hash();
	std::cout << "THF template finished" << std::endl; 

	std::cout << "THF template started" << std::endl; 
	ut_random_generated_key();
	std::cout << "THF template finished" << std::endl; 
}