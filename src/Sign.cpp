#include "Sign.hpp"
#include <iostream>



Signer::Signer(const Botan::Private_Key& key,
			const TH_PrivateKey& hash_key,
			Botan::RandomNumberGenerator& rng)
{
	m_signer = new Botan::PK_Signer(key, rng, "EMSA1(SHA-224)");
	m_hash_key = hash_key;
}

void Signer::offline_phase(Botan::RandomNumberGenerator& rng)
{
	size_t random_value_size = m_hash_key.get_random_element_size();
	Botan::BigInt random_msg(rng, 2048, false);
	const uint8_t* random_msg_ptr = reinterpret_cast<const uint8_t*>(random_msg.data());
	
	std::vector<uint8_t> V(random_msg_ptr, random_msg_ptr + random_msg.bytes());
	
	m_offline_data.msg = V;
	m_offline_data.r.randomize(rng, random_value_size, false);

	std::cout << "Precomputed values: " << std::endl; 
	std::cout << "m = " << random_msg << std::endl;
	std::cout << "r = " << m_offline_data.r << std::endl; 

	m_offline_data.hash = m_hash_key.hash(V, m_offline_data.r);

	const uint8_t* temp_hash_ptr = reinterpret_cast<const uint8_t*>(m_offline_data.hash.data());
	m_signer->update(temp_hash_ptr, m_offline_data.hash.bytes()); 

	m_offline_data.signature = m_signer->signature(rng);
}

std::pair<std::vector<uint8_t>, Botan::BigInt> Signer::sign_message(const uint8_t in[], size_t length,
									Botan::RandomNumberGenerator& rng)
{
	std::vector<uint8_t> in_vector(in, in + length);
	Botan::BigInt r = m_hash_key.collision(m_offline_data.msg, m_offline_data.r, in_vector);

	if(m_hash_key.hash(m_offline_data.msg, m_offline_data.r) == m_hash_key.hash(in_vector, r))
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

Verifier::Verifier(const Botan::Public_Key& pub_key,
				const TH_HashKey& hash_key)
{
	m_verifier = new Botan::PK_Verifier(pub_key, "EMSA1(SHA-224)");
	m_hash_key = hash_key;
}

bool Verifier::verify_message(const uint8_t msg[], size_t msg_length,
						const uint8_t sig[], size_t sig_length, 
						const Botan::BigInt& r)
{
	std::vector<uint8_t> msg_vector(msg, msg + msg_length);
	Botan::BigInt hash_value = m_hash_key.hash(msg_vector, r); 

	const uint8_t* temp_hash_ptr = reinterpret_cast<const uint8_t*>(hash_value.data());
	bool b_correct = m_verifier->verify_message(temp_hash_ptr, hash_value.bytes(), 
								sig, sig_length);

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
