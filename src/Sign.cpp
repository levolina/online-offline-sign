#include "Sign.hpp"
#include <iostream>

// TODO: move parameters of type to constructor
// Cannot be changed after class creation

/*
void Signer::generate_key(size_t key_len, SignAlgo sign_type, TrapdoorAlgo hash_type)
{
	switch(hash_type)
	{
	case RSA_SIGN:
	case DSA_SIGN:
	case ECDSA_SIGN:
	case GOST2001_SIGN:
		std::cout << "Not yet implemented" << std::endl; 
		break; 
	default:
		throw Botan::Invalid_Argument("Unknown signature algorithm");
	}

	// Clear memory if was allocated previouslly
	if(m_hash != nullptr)
	{
		delete m_hash;
	}

	switch(hash_type)
	{
	case TRAPDOOR_DLA:
		m_hash = new TrapdoorHash_DLA;
		break;
	default:
		throw Botan::Invalid_Argument("Unknown trapdoor hash type");
	}
}

Signer::Signer(const std::string& emsa,
					 const std::string& provider)
{
    // Initialize/create key for trapdoor hash function and original signature scheme
    // Probably can save them im selfmade privateKey class
    // Add private field in this class
	m_op = key.create_signature_op(rng, emsa, provider);
	if(!m_op)
    {
		throw Botan::Invalid_Argument("Key type " + key.algo_name() + " does not support signature generation");
    }
	m_parts = key.message_parts();
	m_part_size = key.message_part_size();
}

Signer::~Signer() = default;

void Signer::update(const uint8_t in[], size_t length)
{
	m_op->update(in, length);
}

size_t Signer::signature_length() const
{
	return m_op->signature_length();
}

std::vector<uint8_t> Signer::signature()
{
	const std::vector<uint8_t> sig = unlock(m_op->sign(rng));
    return sig;
}

Verifier::Verifier(const Botan::Public_Key& key,
								 const std::string& emsa,
								 const std::string& provider)
{
	m_op = key.create_verification_op(emsa, provider);
	if(!m_op)
	{
		throw Botan::Invalid_Argument("Key type " + key.algo_name() + " does not support signature verification");
	}
	m_parts = key.message_parts();
	m_part_size = key.message_part_size();
}

Verifier::~Verifier() = default;

bool Verifier::verify_message(const uint8_t msg[], size_t msg_length,
											const uint8_t sig[], size_t sig_length)
{
	update(msg, msg_length);
	return check_signature(sig, sig_length);
}

void Verifier::update(const uint8_t in[], size_t length)
{
	m_op->update(in, length);
}

bool Verifier::check_signature(const uint8_t sig[], size_t length)
{
	try {
		return m_op->is_valid_signature(sig, length);
	}
	catch(Botan::Invalid_Argument&) { return false; }
	catch(Botan::Decoding_Error&) { return false; }
	catch(Botan::Encoding_Error&) { return false; }
}

*/