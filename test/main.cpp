#include <benchmark/benchmark.h>
// Botan
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <botan/dsa.h>
#include <botan/ecdsa.h>
#include <botan/ec_group.h>
#include <botan/auto_rng.h>

//Oosign 
#include "Sign.hpp"

#define EMSA "EMSA1(SHA-256)"
#define RSA_KEYLEN 2048
#define TH_DLA_KEYLEN 1024 

const uint8_t TEST_STR[] = "This is test string";

// --------------- RSA --------------------
static void signBotanRSA(benchmark::State& state) 
{
	Botan::AutoSeeded_RNG rng;
	Botan::RSA_PrivateKey private_key(rng, RSA_KEYLEN); 
	Botan::PK_Signer signer(private_key, rng, EMSA); 
	std::vector<uint8_t> signature; 
	bool result; 

	for (auto _ : state)
	{
		signature = signer.sign_message(TEST_STR,sizeof(TEST_STR), rng);
	}
}

static void verifyBotanRSA(benchmark::State& state) 
{
	Botan::AutoSeeded_RNG rng;
	Botan::RSA_PrivateKey private_key(rng, RSA_KEYLEN); 
	Botan::RSA_PublicKey public_key(private_key);
	Botan::PK_Signer signer(private_key, rng, EMSA); 
	std::vector<uint8_t> signature = signer.sign_message(TEST_STR,sizeof(TEST_STR), rng);
	Botan::PK_Verifier verifier(public_key, EMSA);
	bool result; 

	for (auto _ : state)
	{
		result = verifier.verify_message(TEST_STR, sizeof(TEST_STR), signature.data(), signature.size());
	}
}

// OOSIGN Implementation
static void signOosignRSA(benchmark::State& state)
{
	Botan::AutoSeeded_RNG rng;
	Botan::RSA_PrivateKey rsa_key(rng, RSA_KEYLEN); 
	TH_DLA_PrivateKey private_key(rng, TH_DLA_KEYLEN); 
	Signer sig(&rsa_key, &private_key, rng);
	std::pair<std::vector<uint8_t>, Botan::BigInt> signature;

	sig.offline_phase(rng);
	for (auto _ : state)
	{
		signature = sig.sign_message(TEST_STR, sizeof(TEST_STR)); 
	}
}

static void offlineOosignRSA(benchmark::State& state)
{
	Botan::AutoSeeded_RNG rng;
	Botan::RSA_PrivateKey rsa_key(rng, RSA_KEYLEN); 
	TH_DLA_PrivateKey private_key(rng, TH_DLA_KEYLEN); 
	Signer sig(&rsa_key, &private_key, rng);

	for (auto _ : state)
	{
		sig.offline_phase(rng);
	}
}

static void verifyOosignRSA(benchmark::State& state)
{
	Botan::AutoSeeded_RNG rng;
	Botan::RSA_PrivateKey rsa_key(rng, RSA_KEYLEN); 
	TH_DLA_PrivateKey private_key(rng, TH_DLA_KEYLEN); 
	TH_DLA_HashKey* hash_key = private_key.hash_key();
	Signer sig(&rsa_key, &private_key, rng);
	bool result;

	sig.offline_phase(rng);
	std::pair<std::vector<uint8_t>, Botan::BigInt> signature = sig.sign_message(TEST_STR, sizeof(TEST_STR)); 

	Verifier ver(&rsa_key, hash_key);
	for (auto _ : state)
	{
		result = ver.verify_message(TEST_STR, sizeof(TEST_STR), signature.first.data(), signature.first.size(), signature.second);
	}
}

// --------------- DSA --------------------
static void signBotanDSA(benchmark::State& state)
{
	Botan::AutoSeeded_RNG rng;
	Botan::DSA_PrivateKey private_key(rng, Botan::DL_Group(rng, Botan::DL_Group::Strong, 1024));
	Botan::DSA_PublicKey public_key(private_key);
	Botan::PK_Signer signer(private_key, rng, EMSA); 
	std::vector<uint8_t> signature; 
	bool result; 
	
	for (auto _ : state)
	{
		signature = signer.sign_message(TEST_STR,sizeof(TEST_STR), rng);
	}
}

static void verifyBotanDSA(benchmark::State& state) 
{
	Botan::AutoSeeded_RNG rng;
	Botan::DSA_PrivateKey private_key(rng, Botan::DL_Group(rng, Botan::DL_Group::Strong, 1024));
	Botan::DSA_PublicKey public_key(private_key);
	Botan::PK_Signer signer(private_key, rng, EMSA); 
	std::vector<uint8_t> signature = signer.sign_message(TEST_STR,sizeof(TEST_STR), rng);
	Botan::PK_Verifier verifier(public_key, EMSA);
	bool result; 

	for (auto _ : state)
	{
		result = verifier.verify_message(TEST_STR, sizeof(TEST_STR), signature.data(), signature.size());
	}
}

// OOSIGN Implementation
static void signOosignDSA(benchmark::State& state)
{
	Botan::AutoSeeded_RNG rng;
	Botan::DSA_PrivateKey dsa_key(rng, Botan::DL_Group(rng, Botan::DL_Group::Strong, 1024)); 
	TH_DLA_PrivateKey private_key(rng, 1024); 
	Signer sig(&dsa_key, &private_key, rng);
	std::pair<std::vector<uint8_t>, Botan::BigInt> signature;

	sig.offline_phase(rng);
	for (auto _ : state)
	{
		signature = sig.sign_message(TEST_STR, sizeof(TEST_STR)); 
	}
}

static void offlineOosignDSA(benchmark::State& state)
{
	Botan::AutoSeeded_RNG rng;
	Botan::DSA_PrivateKey dsa_key(rng, Botan::DL_Group(rng, Botan::DL_Group::Strong, 1024)); 
	TH_DLA_PrivateKey private_key(rng, 1024); 
	Signer sig(&dsa_key, &private_key, rng);
	std::pair<std::vector<uint8_t>, Botan::BigInt> signature;

	for (auto _ : state)
	{
		sig.offline_phase(rng);
	}
}

static void verifyOosignDSA(benchmark::State& state)
{
	Botan::AutoSeeded_RNG rng;
	Botan::DSA_PrivateKey dsa_key(rng, Botan::DL_Group(rng, Botan::DL_Group::Strong, 1024)); 
	TH_DLA_PrivateKey private_key(rng, 1024); 
	TH_DLA_HashKey* hash_key = private_key.hash_key();
	Signer sig(&dsa_key, &private_key, rng);

	sig.offline_phase(rng);
	std::pair<std::vector<uint8_t>, Botan::BigInt> signature = sig.sign_message(TEST_STR, sizeof(TEST_STR)); 

	Verifier ver(&dsa_key, hash_key);
	for (auto _ : state)
	{
		ver.verify_message(TEST_STR, sizeof(TEST_STR), signature.first.data(), signature.first.size(), signature.second);
	}
}

// --------------- ECDSA --------------------
static void signBotanECDSA(benchmark::State& state)
{
	Botan::AutoSeeded_RNG rng;
	Botan::ECDSA_PrivateKey private_key(rng, Botan::EC_Group("secp521r1"));
	Botan::PK_Signer signer(private_key, rng, EMSA); 
	std::vector<uint8_t> signature; 
	bool result; 
	
	for (auto _ : state)
	{
		signature = signer.sign_message(TEST_STR,sizeof(TEST_STR), rng);
	}
}

static void verifyBotanECDSA(benchmark::State& state) 
{
	Botan::AutoSeeded_RNG rng;
	Botan::ECDSA_PrivateKey private_key(rng, Botan::EC_Group("secp521r1"));
	Botan::ECDSA_PublicKey public_key(private_key);
	Botan::PK_Signer signer(private_key, rng, EMSA); 
	std::vector<uint8_t> signature = signer.sign_message(TEST_STR,sizeof(TEST_STR), rng);
	Botan::PK_Verifier verifier(public_key, EMSA);
	bool result; 

	for (auto _ : state)
	{
		result = verifier.verify_message(TEST_STR, sizeof(TEST_STR), signature.data(), signature.size());
	}
}

// OOSIGN Implementation
static void offlineOosignECDSA(benchmark::State& state)
{
	Botan::AutoSeeded_RNG rng;
	Botan::ECDSA_PrivateKey ecdsa_key(rng, Botan::EC_Group("secp521r1"));
	TH_DLA_PrivateKey private_key(rng, 1024); 
	Signer sig(&ecdsa_key, &private_key, rng);
	std::pair<std::vector<uint8_t>, Botan::BigInt> signature;

	for (auto _ : state)
	{
		sig.offline_phase(rng);
	}
}

static void signOosignECDSA(benchmark::State& state)
{
	Botan::AutoSeeded_RNG rng;
	Botan::ECDSA_PrivateKey ecdsa_key(rng, Botan::EC_Group("secp521r1"));
	TH_DLA_PrivateKey private_key(rng, 1024); 
	Signer sig(&ecdsa_key, &private_key, rng);
	std::pair<std::vector<uint8_t>, Botan::BigInt> signature;

	sig.offline_phase(rng);
	for (auto _ : state)
	{
		signature = sig.sign_message(TEST_STR, sizeof(TEST_STR)); 
	}
}

static void verifyOosignECDSA(benchmark::State& state)
{
	Botan::AutoSeeded_RNG rng;
	Botan::ECDSA_PrivateKey ecdsa_key(rng, Botan::EC_Group("secp521r1"));
	Botan::ECDSA_PublicKey public_key(ecdsa_key);
	TH_DLA_PrivateKey private_key(rng, 1024); 
	TH_DLA_HashKey* hash_key = private_key.hash_key();
	Signer sig(&ecdsa_key, &private_key, rng);
	bool result;

	sig.offline_phase(rng);
	std::pair<std::vector<uint8_t>, Botan::BigInt> signature = sig.sign_message(TEST_STR, sizeof(TEST_STR)); 

	Verifier ver(&public_key, hash_key);
	for (auto _ : state)
	{
		result = ver.verify_message(TEST_STR, sizeof(TEST_STR), signature.first.data(), signature.first.size(), signature.second);
	}
}

BENCHMARK(signBotanRSA);
BENCHMARK(verifyBotanRSA);
BENCHMARK(offlineOosignRSA);
BENCHMARK(signOosignRSA);
BENCHMARK(verifyOosignRSA);
BENCHMARK(signBotanDSA);
BENCHMARK(verifyBotanDSA);
BENCHMARK(offlineOosignDSA);
BENCHMARK(signOosignDSA);
BENCHMARK(verifyOosignDSA);
BENCHMARK(signBotanECDSA);
BENCHMARK(verifyBotanECDSA);
BENCHMARK(offlineOosignECDSA);
BENCHMARK(signOosignECDSA);
BENCHMARK(verifyOosignECDSA);

BENCHMARK_MAIN();