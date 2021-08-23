#include <iostream>
#include "Sign.hpp"
#include <botan/rsa.h>
#include <botan/auto_rng.h>

#define TEST_SIZE 128

void ut_trapdoor_hash()
{
	Botan::AutoSeeded_RNG rng;
	Botan::RSA_PrivateKey rsa_key(rng, 1024); 
	TH_DLA_PrivateKey private_key(251387, 62849, 36711, 31862); 
	private_key.print(); 

	int test = 64; 
	uint8_t* test_ptr = reinterpret_cast<uint8_t*>(&test);
	std::vector<uint8_t> test_vector(test_ptr, test_ptr + sizeof(int));
	char buffer[] = "msg";
	uint8_t* buffer_ptr = reinterpret_cast<uint8_t*>(buffer);
	std::vector<uint8_t> test2(buffer_ptr, buffer_ptr + sizeof(buffer));

	Signer sig(rsa_key, private_key, rng);
	sig.offline_phase(rng);
	std::pair<std::vector<uint8_t>, Botan::BigInt> signature = sig.sign_message(test2, rng); 

	Verifier ver(rsa_key, private_key);
	ver.verify_message(test2, signature.first, signature.second);
}

// Just a simple file with functionality of future library
int main()
{
	std::cout << "THF template started" << std::endl; 
	ut_trapdoor_hash();
	std::cout << "THF template finished" << std::endl; 
}