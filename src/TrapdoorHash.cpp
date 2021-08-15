#include <botan/auto_rng.h>
#include <iostream>
#include "TrapdoorHash.hpp"

Botan::secure_vector<uint8_t> hash(const uint8_t msg[], size_t msg_len, const uint8_t random_element[]);

void TrapdoorHash_DLA::generate_key(size_t key_len)
{
	Botan::AutoSeeded_RNG rng;
	m_key_dl_group = Botan::DL_Group(rng, Botan::DL_Group::PrimeType::Strong,
		key_len * 8, 0);
	m_key_alpha = Botan::BigInt::random_integer(rng, 0, m_key_dl_group.get_q());
	m_key_y = m_key_dl_group.power_g_p(m_key_alpha);
}

void TrapdoorHash_DLA::debug_print()
{
	std::cout << "p = " << m_key_dl_group.get_p() << std::endl; 
	std::cout << "q = " << m_key_dl_group.get_q() << std::endl; 
	std::cout << "g = " << m_key_dl_group.get_g() << std::endl; 
	std::cout << "Alpha = " << m_key_alpha << std::endl;
	std::cout << "Y = " << m_key_y << std::endl;
}

Botan::secure_vector<uint8_t> TrapdoorHash_DLA::hash(const uint8_t msg[], size_t msg_len, const uint8_t random_element[], size_t random_size)
{
	Botan::BigInt msg_int(msg, msg_len);
	Botan::BigInt random_int(random_element, random_size);
	Botan::BigInt hash_value = 0;
	Botan::secure_vector<uint8_t> hash_vector;

	msg_int = m_key_dl_group.mod_q(msg_int); // As g is of order q
	hash_value = m_key_dl_group.multi_exponentiate(msg_int, m_key_y, random_int);
	hash_vector = Botan::BigInt::encode_locked(hash_value);
	return hash_vector; 
}
