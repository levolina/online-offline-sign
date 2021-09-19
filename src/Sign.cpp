#include "Sign.hpp"
#include <iostream>

Signer::Signer(const Botan::Private_Key* key,
			ITH_PrivateKey* hash_key,
			Botan::RandomNumberGenerator& rng)
{
	m_signer = new Botan::PK_Signer(*key, rng, "EMSA1(SHA-224)");
	m_hash_key = hash_key;

	/*
	#define BOTAN_RSA_USE_ASYNC

 #if defined(BOTAN_RSA_USE_ASYNC)
 
          auto future_j1 = Thread_Pool::global_instance().run([this, &m, &d1_mask]() {
 #endif
             const BigInt masked_d1 = m_private->get_d1() + (d1_mask * (m_private->get_p() - 1));
             auto powm_d1_p = monty_precompute(m_private->m_monty_p, m_private->m_mod_p.reduce(m), powm_window);
             BigInt j1 = monty_execute(*powm_d1_p, masked_d1, m_max_d1_bits);
 
 #if defined(BOTAN_RSA_USE_ASYNC)
          return j1;
          });
 #endif
 
          const BigInt d2_mask(m_blinder.rng(), m_blinding_bits);
          const BigInt masked_d2 = m_private->get_d2() + (d2_mask * (m_private->get_q() - 1));
          auto powm_d2_q = monty_precompute(m_private->m_monty_q, m_private->m_mod_q.reduce(m), powm_window);
          const BigInt j2 = monty_execute(*powm_d2_q, masked_d2, m_max_d2_bits);
 
 #if defined(BOTAN_RSA_USE_ASYNC)
          BigInt j1 = future_j1.get();
 #endif*/
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

	// DEBUG
	std::cout << "Precomputed values: " << std::endl; 
	std::cout << "m = " << Botan::BigInt(rand_msg) << std::endl;
	std::cout << "r = " << m_offline_data.r << std::endl; 

	// Run the signature algorithm with the signing key
	m_offline_data.signature = m_signer->sign_message(m_offline_data.hash, rng);
}

std::pair<std::vector<uint8_t>, Botan::BigInt> Signer::sign_message(const uint8_t in[], size_t length,
									Botan::RandomNumberGenerator& rng)
{
	if (m_hash_key == nullptr)
	{
		throw std::runtime_error("Hash Key pointer is null");
	}

	std::vector<uint8_t> in_vector(in, in + length);
	TrapdoorHash hash_function(m_hash_key);

	Botan::BigInt r = hash_function.collision( m_offline_data.msg, m_offline_data.r, in_vector);

	if(hash_function.hash(m_offline_data.msg, m_offline_data.r) == hash_function.hash(in_vector, r))
	{
		std::cout << "Correct collision find by trapdoor" << std::endl;
	}
	else
	{
		std::cout << "Incorrect collision" <<std::endl;
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
	std::vector<uint8_t> msg_vector(msg, msg + msg_length);
	TrapdoorHash hash_function(m_hash_key);

	std::vector<uint8_t> hash_value = hash_function.hash(msg_vector, r); 

	bool b_correct = m_verifier->verify_message(hash_value.data(), hash_value.size(), sig, sig_length);

	// DEBUG
	if(b_correct)
	{
		std::cout << "True" << std::endl;
	}
	else
	{
		std::cout << "False" << std::endl;
	}
	return b_correct;
}
