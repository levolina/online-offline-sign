#include <benchmark/benchmark.h>
// Botan
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <botan/dsa.h>
#include <botan/ecdsa.h>
#include <botan/ec_group.h>

#include <botan/gost_3410.h>
#include <botan/auto_rng.h>

//Oosign 
#include "Sign.hpp"

#define EMSA "EMSA1(SHA-256)"

const uint8_t TEST_STR[] = "This is test string";

// Botan RSA signature
void botan_rsa_test_str_sign()
{
	Botan::AutoSeeded_RNG rng;
	Botan::RSA_PrivateKey private_key(rng, 1024); 
	Botan::RSA_PublicKey public_key(private_key);
	Botan::PK_Signer signer(private_key, rng, EMSA); 
	Botan::PK_Verifier verifier(public_key, EMSA);
	std::vector<uint8_t> signature; 
	bool result; 
	
	// Sign data
	signature = signer.sign_message(TEST_STR,sizeof(TEST_STR), rng);
	// Verify signature
	verifier.update(TEST_STR, sizeof(TEST_STR));
	result = verifier.verify_message(TEST_STR, sizeof(TEST_STR), signature.data(), signature.size());
}

void botan_dsa_test_str_sign()
{
	Botan::AutoSeeded_RNG rng;
	Botan::DSA_PrivateKey private_key(rng, Botan::DL_Group(rng, Botan::DL_Group::Strong, 1024));
	Botan::DSA_PublicKey public_key(private_key);
	Botan::PK_Signer signer(private_key, rng, EMSA); 
	Botan::PK_Verifier verifier(public_key, EMSA);
	std::vector<uint8_t> signature; 
	bool result; 
	
	// Sign data
	signature = signer.sign_message(TEST_STR,sizeof(TEST_STR), rng);
	// Verify signature
	verifier.update(TEST_STR, sizeof(TEST_STR));
	result = verifier.verify_message(TEST_STR, sizeof(TEST_STR), signature.data(), signature.size());
}

void botan_ecdsa_test_str_sign()
{
	Botan::AutoSeeded_RNG rng;
	// Generate ECDSA keypair
	Botan::ECDSA_PrivateKey private_key(rng, Botan::EC_Group("secp521r1"));
	Botan::ECDSA_PublicKey public_key(private_key);
	Botan::PK_Signer signer(private_key, rng, EMSA); 
	Botan::PK_Verifier verifier(public_key, EMSA);
	std::vector<uint8_t> signature; 
	bool result; 
	
	// Sign data
	signature = signer.sign_message(TEST_STR,sizeof(TEST_STR), rng);
	// Verify signature
	verifier.update(TEST_STR, sizeof(TEST_STR));
	result = verifier.verify_message(TEST_STR, sizeof(TEST_STR), signature.data(), signature.size());
}

void botan_gost_test_str_sign() 
{
	Botan::AutoSeeded_RNG rng;
	Botan::GOST_3410_PrivateKey private_key(rng, Botan::EC_Group("secp521r1"));
	Botan::GOST_3410_PublicKey public_key(private_key);
	Botan::PK_Signer signer(private_key, rng, EMSA); 
	Botan::PK_Verifier verifier(public_key, EMSA);
	std::vector<uint8_t> signature; 
	bool result; 
	
	// Sign data
	signature = signer.sign_message(TEST_STR,sizeof(TEST_STR), rng);
	// Verify signature
	verifier.update(TEST_STR, sizeof(TEST_STR));
	result = verifier.verify_message(TEST_STR, sizeof(TEST_STR), signature.data(), signature.size());
}

// OOSIGN Implementation
void oosign_rsa_test_str_sign()
{
	Botan::AutoSeeded_RNG rng;
	Botan::RSA_PrivateKey rsa_key(rng, 1024); 
	TH_DLA_PrivateKey private_key(rng, 1024); 
	TH_DLA_HashKey* hash_key = private_key.hash_key();
	Signer sig(&rsa_key, &private_key, rng);

	sig.offline_phase(rng);
	std::pair<std::vector<uint8_t>, Botan::BigInt> signature = sig.sign_message(TEST_STR, sizeof(TEST_STR)); 

	Verifier ver(&rsa_key, hash_key);
	ver.verify_message(TEST_STR, sizeof(TEST_STR), signature.first.data(), signature.first.size(), signature.second);
}

void signBotanRSA(benchmark::State& state) 
{
	while (state.KeepRunning()) 
	{
		botan_rsa_test_str_sign();
	}
}

void signBotanDSA(benchmark::State& state) 
{
	while (state.KeepRunning()) 
	{
		botan_dsa_test_str_sign();
	}
}

void signBotanECDSA(benchmark::State& state) 
{
	while (state.KeepRunning()) 
	{
		botan_ecdsa_test_str_sign();
	}
}

void signBotanGOST(benchmark::State& state)
{
	while (state.KeepRunning()) 
	{
		botan_gost_test_str_sign();
	}
}

void OosignRSA(benchmark::State& state) 
{
	while (state.KeepRunning()) 
	{
		oosign_rsa_test_str_sign();
	}
}

// Register the function as a benchmark
BENCHMARK(signBotanRSA);
BENCHMARK(signBotanDSA);
BENCHMARK(signBotanECDSA);
BENCHMARK(OosignRSA);

BENCHMARK_MAIN();

// RSA Signature generation
/*void rsa_sign()
{
	std::cout << "- RSA Signature" << std::endl;
	Botan::AutoSeeded_RNG rng;
	Botan::RSA_PrivateKey rsa_key(rng, 1024); 

	std::string text("This is a tasty burger!");
	std::vector<uint8_t> data(text.data(),text.data()+text.length());
	// sign data
	Botan::PK_Signer signer(rsa_key, rng, "EMSA1(SHA-256)");
	signer.update(data);
	std::vector<uint8_t> signature = signer.signature(rng);
	std::cout << "Signature:" << std::endl << Botan::hex_encode(signature);
	// verify signature
	Botan::PK_Verifier verifier(rsa_key, "EMSA1(SHA-256)");
	verifier.update(data);
	std::cout << std::endl << "is " << (verifier.check_signature(signature)? "valid" : "invalid") << std::endl;
}

void dsa_sign()
{
	std::cout << "- DSA Signature" << std::endl;
	Botan::AutoSeeded_RNG rng;
	Botan::DSA_PrivateKey dsa_key(rng, Botan::DL_Group(rng, Botan::DL_Group::PrimeType::Strong, 1024)); 

	std::string text("This is a tasty burger!");
	std::vector<uint8_t> data(text.data(),text.data()+text.length());
	// sign data
	Botan::PK_Signer signer(dsa_key, rng, "EMSA1(SHA-256)");
	signer.update(data);
	std::vector<uint8_t> signature = signer.signature(rng);
	std::cout << "Signature:" << std::endl << Botan::hex_encode(signature);
	// verify signature
	Botan::PK_Verifier verifier(dsa_key, "EMSA1(SHA-256)");
	verifier.update(data);
	std::cout << std::endl << "is " << (verifier.check_signature(signature)? "valid" : "invalid") << std::endl;
}

void ecdsa_sign() 
{
	std::cout << "- ECDSA Signature" << std::endl;
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
}

void gost_sign() 
{
	std::cout << "- GOST2001_SIGN Signature" << std::endl;
	Botan::AutoSeeded_RNG rng;
	// Generate ECDSA keypair
	Botan::GOST_3410_PrivateKey key(rng, Botan::EC_Group("secp521r1"));

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
}

int main()
{
	rsa_sign();
	dsa_sign();
	ecdsa_sign();
	gost_sign();
	return 0;
}*/


// Test with predefine hash key
/*void ut_trapdoor_hash()
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
	std::pair<std::vector<uint8_t>, Botan::BigInt> signature = sig.sign_message(test_vector); 

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
	
	std::pair<std::vector<uint8_t>, Botan::BigInt> signature = sig.sign_message(test_vector); 

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
}*/