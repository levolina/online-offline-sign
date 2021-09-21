#include "Sign.hpp"
#include <iostream>

#ifdef DEBUG
#define PRINT_DEBUG(msg) { std::cout << msg << std::endl; } 
#else
#define PRINT_DEBUG(msg)
#endif

Signer::Signer(const Botan::Private_Key* key,
			ITH_PrivateKey* hash_key,
			Botan::RandomNumberGenerator& rng)
{
	m_signer = new Botan::PK_Signer(*key, rng, "EMSA1(SHA-224)");
	m_hash_key = hash_key;
}

Signer::~Signer()
{
	delete m_signer;
}

void Signer::offline_phase(Botan::RandomNumberGenerator& rng)
{
	#define RAND_MSG_LEN 256
	// Choose a random (m', r') and compute hash(m', r')
	std::vector<uint8_t> rand_msg(RAND_MSG_LEN); 
	rng.random_vec(rand_msg, RAND_MSG_LEN);
	TrapdoorHash hash_function(m_hash_key);
	
	m_offline_data.msg = rand_msg;
	m_offline_data.r.randomize(rng, hash_function.get_random_element_size(), false);
	m_offline_data.hash = hash_function.hash(m_offline_data.msg, m_offline_data.r);

	PRINT_DEBUG("Precomputed values:");
	PRINT_DEBUG("m = " << Botan::BigInt(rand_msg));
	PRINT_DEBUG("r = " << m_offline_data.r );

	// Run the signature algorithm with the signing key
	m_offline_data.signature = m_signer->sign_message(m_offline_data.hash, rng);
}

std::pair<std::vector<uint8_t>, Botan::BigInt> Signer::sign_message(const uint8_t in[], size_t length)
{
	if (m_hash_key == nullptr)
	{
		throw std::runtime_error("Hash Key pointer is null");
	}

	std::vector<uint8_t> in_vector(in, in + length);
	TrapdoorHash hash_function(m_hash_key);

	Botan::BigInt r = hash_function.collision( m_offline_data.msg, m_offline_data.r, in_vector);

	if(m_offline_data.hash != hash_function.hash(in_vector, r))
	{
		throw std::runtime_error("Incorrect collision"); 
	}
	return std::make_pair(m_offline_data.signature, r);
}

/* ----------------------------------------------------------------------------*/ 

Verifier::Verifier(const Botan::Public_Key* pub_key,
				ITH_HashKey* hash_key)
{
	m_verifier = new Botan::PK_Verifier(*pub_key, "EMSA1(SHA-224)");
	m_hash_key = hash_key;
}

Verifier::~Verifier()
{
	delete m_verifier; 
}

bool Verifier::verify_message(const uint8_t msg[], size_t msg_length,
						const uint8_t sig[], size_t sig_length, 
						const Botan::BigInt& r)
{
	TrapdoorHash hash_function(m_hash_key);
	std::vector<uint8_t> hash_value = hash_function.hash(msg, msg_length, r); 
	bool b_correct = m_verifier->verify_message(hash_value.data(), hash_value.size(), sig, sig_length);

	PRINT_DEBUG(b_correct);

	return b_correct;
}
