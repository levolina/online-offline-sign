#include <botan/auto_rng.h>
#include <botan/rsa.h>
#include <botan/dsa.h>
#include <botan/ecdsa.h>
#include <botan/gost_3410.h>

#include <botan/ec_group.h>
#include <botan/pubkey.h>
#include <botan/hex.h>
#include <iostream>

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