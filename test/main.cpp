#define CATCH_CONFIG_MAIN
#define CATCH_CONFIG_ENABLE_BENCHMARKING

#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <botan/dsa.h>
#include <botan/ecdsa.h>
#include <botan/ec_group.h>
#include <botan/auto_rng.h>
#include <catch2/catch.hpp>

#include "Sign.hpp"

#define EMSA "EMSA1(SHA-256)"
#define RSA_KEYLEN 2048
#define TH_DLA_KEYLEN 1024 

const uint8_t TEST_STR[] = "This is test string";

TEST_CASE("botan3: RSA")
{
	Botan::AutoSeeded_RNG rng;
	Botan::RSA_PrivateKey private_key(rng, RSA_KEYLEN);
	Botan::RSA_PublicKey public_key(private_key);
	Botan::PK_Signer signer(private_key, rng, EMSA);
	Botan::PK_Verifier verifier(public_key, EMSA);
	std::vector<uint8_t> signature; 
	bool result; 

	BENCHMARK("sign") 
	{
		return signer.sign_message(TEST_STR, sizeof(TEST_STR), rng);
	};

	signature = signer.sign_message(TEST_STR,sizeof(TEST_STR), rng);

	BENCHMARK("verify")
	{
		return verifier.verify_message(TEST_STR, sizeof(TEST_STR), signature.data(), signature.size());
	};

	result = verifier.verify_message(TEST_STR, sizeof(TEST_STR), signature.data(), signature.size());
	REQUIRE(result);
}

TEST_CASE("oosign: RSA")
{
	Botan::AutoSeeded_RNG rng;
	Botan::RSA_PrivateKey rsa_key(rng, RSA_KEYLEN); 
	TH_DLA_PrivateKey private_key(rng, TH_DLA_KEYLEN);
	TH_DLA_HashKey* hash_key = private_key.hash_key();
	Signer sig(&rsa_key, &private_key, rng);
	Verifier ver(&rsa_key, hash_key);
	std::pair<std::vector<uint8_t>, Botan::BigInt> signature;
	bool result;

	BENCHMARK("offline phase")
	{
		return sig.offline_phase(rng);
	};

	BENCHMARK("online phase")
	{
		return sig.sign_message(TEST_STR, sizeof(TEST_STR));
	};

	signature = sig.sign_message(TEST_STR, sizeof(TEST_STR));

	BENCHMARK("verify")
	{
		return ver.verify_message(TEST_STR, sizeof(TEST_STR), signature.first.data(), signature.first.size(), signature.second);
	};
	result = ver.verify_message(TEST_STR, sizeof(TEST_STR), signature.first.data(), signature.first.size(), signature.second);
	REQUIRE(result);
}

TEST_CASE("botan3: DSA")
{
	Botan::AutoSeeded_RNG rng;
	Botan::DSA_PrivateKey private_key(rng, Botan::DL_Group(rng, Botan::DL_Group::Strong, 1024));
	Botan::DSA_PublicKey public_key(private_key);
	Botan::PK_Signer signer(private_key, rng, EMSA);
	Botan::PK_Verifier verifier(public_key, EMSA);
	std::vector<uint8_t> signature; 
	bool result; 

	BENCHMARK("sign") 
	{
		return signer.sign_message(TEST_STR, sizeof(TEST_STR), rng);
	};

	signature = signer.sign_message(TEST_STR,sizeof(TEST_STR), rng);

	BENCHMARK("verify")
	{
		return verifier.verify_message(TEST_STR, sizeof(TEST_STR), signature.data(), signature.size());
	};

	result = verifier.verify_message(TEST_STR, sizeof(TEST_STR), signature.data(), signature.size());
	REQUIRE(result);
}

TEST_CASE("oosign: DSA")
{
	Botan::AutoSeeded_RNG rng;
	Botan::DSA_PrivateKey dsa_key(rng, Botan::DL_Group(rng, Botan::DL_Group::Strong, 1024)); 
	TH_DLA_PrivateKey private_key(rng, TH_DLA_KEYLEN); 
	TH_DLA_HashKey* hash_key = private_key.hash_key();
	Signer sig(&dsa_key, &private_key, rng);
	Verifier ver(&dsa_key, hash_key);
	std::pair<std::vector<uint8_t>, Botan::BigInt> signature;
	bool result;

	BENCHMARK("offline phase")
	{
		return sig.offline_phase(rng);
	};

	BENCHMARK("online phase")
	{
		return sig.sign_message(TEST_STR, sizeof(TEST_STR));
	};

	signature = sig.sign_message(TEST_STR, sizeof(TEST_STR));

	BENCHMARK("verify")
	{
		return ver.verify_message(TEST_STR, sizeof(TEST_STR), signature.first.data(), signature.first.size(), signature.second);
	};
	result = ver.verify_message(TEST_STR, sizeof(TEST_STR), signature.first.data(), signature.first.size(), signature.second);
	REQUIRE(result);
}

TEST_CASE("botan3: ECDSA")
{
	Botan::AutoSeeded_RNG rng;
	Botan::ECDSA_PrivateKey private_key(rng, Botan::EC_Group("secp521r1"));
	Botan::ECDSA_PublicKey public_key(private_key);
	Botan::PK_Signer signer(private_key, rng, EMSA);
	Botan::PK_Verifier verifier(public_key, EMSA);
	std::vector<uint8_t> signature; 
	bool result; 

	BENCHMARK("sign") 
	{
		return signer.sign_message(TEST_STR, sizeof(TEST_STR), rng);
	};

	signature = signer.sign_message(TEST_STR,sizeof(TEST_STR), rng);

	BENCHMARK("verify")
	{
		return verifier.verify_message(TEST_STR, sizeof(TEST_STR), signature.data(), signature.size());
	};

	result = verifier.verify_message(TEST_STR, sizeof(TEST_STR), signature.data(), signature.size());
	REQUIRE(result);
}

TEST_CASE("oosign: ECDSA")
{
	Botan::AutoSeeded_RNG rng;
	Botan::ECDSA_PrivateKey ecdsa_key(rng, Botan::EC_Group("secp521r1"));
	TH_DLA_PrivateKey private_key(rng, TH_DLA_KEYLEN); 
	TH_DLA_HashKey* hash_key = private_key.hash_key();
	Signer sig(&ecdsa_key, &private_key, rng);
	Verifier ver(&ecdsa_key, hash_key);
	std::pair<std::vector<uint8_t>, Botan::BigInt> signature;
	bool result;

	BENCHMARK("offline phase")
	{
		return sig.offline_phase(rng);
	};

	BENCHMARK("online phase")
	{
		return sig.sign_message(TEST_STR, sizeof(TEST_STR));
	};

	signature = sig.sign_message(TEST_STR, sizeof(TEST_STR));

	BENCHMARK("verify")
	{
		return ver.verify_message(TEST_STR, sizeof(TEST_STR), signature.first.data(), signature.first.size(), signature.second);
	};
	result = ver.verify_message(TEST_STR, sizeof(TEST_STR), signature.first.data(), signature.first.size(), signature.second);
	REQUIRE(result);
}