// Signer and verifier class
#include <botan/pk_keys.h>
#include <botan/mem_ops.h>
#include <botan/pubkey.h>
#include <vector>
#include "TrapdoorHash.hpp"


struct OfflinePhaseData
{
	std::vector<uint8_t> msg; 
	Botan::BigInt r; 
	Botan::BigInt hash;
	std::vector<uint8_t> signature; 
}; 
/**
 * Class Signer. 
 * General method for combining any trapdoor hash family and any signature scheme 
 * to get an online/offline signature scheme
 */
class Signer 
{
private:
	Botan::PK_Signer* m_signer;
	ITH_PrivateKey m_hash_key; 
	OfflinePhaseData m_offline_data; 

public:
	/**
	 * Construct a Signer.
	 * @param key the key to use inside this signer
	 * @param hash_key the key of hash
	 * @param rng the random generator to use
	*/
	Signer(const Botan::Private_Key& key,
			const ITH_PrivateKey& hash_key,
			Botan::RandomNumberGenerator& rng);
	
	~Signer() { delete m_signer; };

	Signer(const Signer&) = delete;
	Signer& operator=(const Signer&) = delete;

	/**
	 * Offline phase
	 */
	void offline_phase(Botan::RandomNumberGenerator& rng);

	/**
	 * Sign a message all in one go
	 * @param in the message to sign as a byte array
	 * @param length the length of the above byte array
	 * @param rng the rng to use
	 * @return signature
	 */
	std::pair<std::vector<uint8_t>, Botan::BigInt> sign_message(const uint8_t in[], size_t length,
									Botan::RandomNumberGenerator& rng);

	/**
	 * Sign a message.
	 * @param in the message to sign
	 * @param rng the rng to use
	 * @return signature
	 */
	template<typename Alloc>
	std::pair<std::vector<uint8_t>, Botan::BigInt> sign_message(const std::vector<uint8_t, Alloc>& in,
									Botan::RandomNumberGenerator& rng)
	{
		return sign_message(in.data(), in.size(), rng);
	}
};

/**
* Public Key Verifier. Use the verify_message() functions for small
* messages. Use multiple calls update() to process large messages and
* verify the signature by finally calling check_signature().
*/
class Verifier
{
private:
	Botan::PK_Verifier* m_verifier; 
	ITH_HashKey m_hash_key;
public:
	/**
	 * Construct a Verifier.
	 * @param pub_key the public key to verify against
	 */
	Verifier(const Botan::Public_Key& pub_key,
				const ITH_HashKey& hash_key);

	~Verifier() { delete m_verifier; };

	Verifier& operator=(const Verifier&) = delete; 
	Verifier(const Verifier&) = delete;

	/**
	 * Verify a signature.
	 * @param msg the message that the signature belongs to, as a byte array
	 * @param msg_length the length of the above byte array msg
	 * @param sig the signature as a byte array
	 * @param sig_length the length of the above byte array sig
	 * @return true if the signature is valid
	 */
	bool verify_message(const uint8_t msg[], size_t msg_length,
						const uint8_t sig[], size_t sig_length, 
						const Botan::BigInt& r);

	/**
	 * Verify a signature.
	 * @param msg the message that the signature belongs to
	 * @param sig the signature
	 * @return true if the signature is valid
	 */
	template<typename Alloc, typename Alloc2>
	bool verify_message(const std::vector<uint8_t, Alloc>& msg,
						const std::vector<uint8_t, Alloc2>& sig,
						const Botan::BigInt& r)
	{
		return verify_message(msg.data(), msg.size(), 
						sig.data(), sig.size(), 
						r);
	}
	
};