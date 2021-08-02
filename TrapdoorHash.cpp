#include <botan/auto_rng.h>
#include <iostream>
#include "TrapdoorHash.hpp"

void TrapdoorHash::generateKey(size_t keyLen)
{
	Botan::AutoSeeded_RNG rng;
	m_keyDlGroup = Botan::DL_Group(rng, Botan::DL_Group::PrimeType::Strong,
           keyLen * 8, 0);
	m_keyAlpha = Botan::BigInt::random_integer(rng, 0, m_keyDlGroup.get_q());
	m_keyY = m_keyDlGroup.power_g_p(m_keyAlpha);

	std::cout << "p = " << m_keyDlGroup.get_p() << std::endl; 
	std::cout << "q = " << m_keyDlGroup.get_q() << std::endl; 
	std::cout << "g = " << m_keyDlGroup.get_g() << std::endl; 
	std::cout << "Alpha = " << m_keyAlpha << std::endl;
	std::cout << "Y = " << m_keyY << std::endl;
}

TrapdoorHash::TrapdoorHash(size_t keySize = 128)
{
	m_keyLen=keySize; 
	generateKey(keySize);
}

Botan::BigInt TrapdoorHash::hash(Botan::BigInt r, const uint8_t* data, size_t dataLen)
{
	Botan::BigInt msg(data, dataLen);
	Botan::BigInt hashValue = Botan::BigInt::zero(); 
	msg = m_keyDlGroup.mod_q(msg); 
	hashValue = m_keyDlGroup.multi_exponentiate(msg, m_keyY, r);
	std::cout << "HASH:" << hashValue << std::endl; 
	return hashValue;
}
