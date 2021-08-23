#include <botan/auto_rng.h>
#include <iostream>
#include "TrapdoorHash.hpp"

TH_DLA_HashKey::TH_DLA_HashKey(const Botan::BigInt& p, const Botan::BigInt& g, const Botan::BigInt& y)
{
	m_key_dl_group = Botan::DL_Group(p, (p-1) / 2, g);
	m_key_y = y; 
}

void TH_DLA_HashKey::print()
{
	std::cout << "Trapdoor Hash Key" << std::endl;
	std::cout << "p = " << m_key_dl_group.get_p() << std::endl;
	std::cout << "q = " << m_key_dl_group.get_q() << std::endl;
	std::cout << "g = " << m_key_dl_group.get_g() << std::endl;
	std::cout << "y = " << m_key_y << std::endl;
	std::cout << std::endl;
}

TH_DLA_PrivateKey::TH_DLA_PrivateKey(const Botan::BigInt& p,const Botan::BigInt& g, 
					const Botan::BigInt& y, const Botan::BigInt& alpha)
					: TH_DLA_HashKey(p, g, y)
{
	m_key_alpha = alpha;
}

TH_DLA_PrivateKey::TH_DLA_PrivateKey(Botan::RandomNumberGenerator& rng, 
				size_t bits)
{
	m_key_dl_group = Botan::DL_Group(rng, Botan::DL_Group::PrimeType::Strong, bits, 0);
	m_key_alpha = Botan::BigInt::random_integer(rng, 0, m_key_dl_group.get_q());
	m_key_y = m_key_dl_group.power_g_p(m_key_alpha);
}

void TH_DLA_PrivateKey::print()
{
	TH_DLA_HashKey::print();
	std::cout << "Trapdoor Private Key" << std::endl;
	std::cout << "alpha = " << m_key_alpha << std::endl;
	std::cout << std::endl;
}

/* -------------------------------- END OF KEY CODE AREA ---------------------*/

Botan::BigInt TH_DLA_HashKey::hash(const Botan::BigInt& msg, const Botan::BigInt& r)
{
	std::cout << "Msg in int" << std::endl;
	std::cout << msg << std::endl;

	// As g is of order q
	Botan::BigInt cropped_msg = m_key_dl_group.mod_q(msg);

	Botan::BigInt hash_value = m_key_dl_group.multi_exponentiate(cropped_msg, m_key_y, r);

	std::cout << "Calculated hash value: " << std::endl;
	std::cout << hash_value << std::endl; 
	std::cout << std::endl;

	return hash_value;
}

Botan::BigInt TH_DLA_PrivateKey::collision(const std::vector<uint8_t> msg1, 
	const Botan::BigInt& r1, const std::vector<uint8_t> msg2)
{
	Botan::BigInt i_msg1(msg1.data(), msg1.size());
	Botan::BigInt i_msg2(msg2.data(), msg2.size());
	Botan::BigInt r2 = 0;

	// As g is of order q
	i_msg1 = m_key_dl_group.mod_q(i_msg1);
	i_msg2 = m_key_dl_group.mod_q(i_msg2);

	std::cout << "Msg1: " << i_msg1 << std::endl;
	std::cout << "Msg2: " << i_msg2 << std::endl;

	r2 = m_key_dl_group.mod_q( (i_msg1 - i_msg2) * m_key_dl_group.inverse_mod_q(m_key_alpha) + r1 );
	
	std::cout << "r2 = " << r2 << std::endl;
	return r2; 
}

Botan::BigInt TrapdoorHash::signature(const Botan::BigInt& r)
{
	Botan::BigInt msg(m_data);
	return m_key.hash(msg, r);
}