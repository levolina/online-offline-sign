// Signer and verifier class
#include <botan/pk_keys.h>
#include <botan/mem_ops.h>
#include <vector>
#include "TrapdoorHash.hpp"


enum SignAlgo 
{
	RSA_SIGN, 
	DSA_SIGN, 
	ECDSA_SIGN, 
	GOST2001_SIGN
};

/**
* Hash-Sign-Switch Paradigm. 
* General method for combining any trapdoor hash family and any signature scheme 
* to get an online/offline signature scheme
*/

class ISigner
{
protected:
	TrapdoorHash *m_hash = nullptr;
	Botan::Private_Key *m_key = nullptr; 
public:
	/**
	 * The Key Generation Algorithm
	 * 1) Generate a pair of signing and verification key (SK, VK)
	 * 2) Generate a pair of hash key and trapdoor key (HK, TK)
	*/
	virtual void generate_key(size_t key_len, SignAlgo sign_type) = 0;

	/** 
	 * The Signing Algorithm
	 * Signing key: (SK, HK, TK)
	*/
	virtual void offline_phase() = 0;
	virtual Botan::secure_vector<uint8_t> online_phase(const uint8_t msg[], size_t msg_len) = 0;
	
	virtual ~ISigner() = default;
};

/**
 * Class Signer. 
 * Produce signature in IEEE1363 format
 * General method for combining any trapdoor hash family and any signature scheme 
 * to get an online/offline signature scheme
 */
class Signer : public ISigner {
	public:

		/**
		* Construct a Signer.
		* @param emsa the EMSA to use
		* An example would be "EMSA1(SHA-224)".
		* @param provider the provider to use
		*/
		Signer(const std::string& emsa,
				const std::string& provider = "");

		~Signer();

		Signer(const Signer&) = delete;
		Signer(Signer&&) = delete;
		Signer& operator=(const Signer&) = delete;
		Signer& operator=(Signer&&) = delete;

		void generate_key(size_t key_len, SignAlgo sign_type);

		/**
		* Sign a message all in one go
		* @param in the message to sign as a byte array
		* @param length the length of the above byte array
		* @return signature
		*/
		std::vector<uint8_t> sign_message(const uint8_t in[], size_t length)
		{
			this->update(in, length);
			return this->signature();
		}
	
		/**
		* Sign a message.
		* @param in the message to sign
		* @return signature
		*/
		template<typename Alloc>
			std::vector<uint8_t> sign_message(const std::vector<uint8_t, Alloc>& in)
		{
			return sign_message(in.data(), in.size());
		}

		/**
		* Add a message part (single byte).
		* @param in the byte to add
		*/
		void update(uint8_t in) { update(&in, 1); }

		/**
		* Add a message part.
		* @param in the message part to add as a byte array
		* @param length the length of the above byte array
		*/
		void update(const uint8_t in[], size_t length);

		/**
		* Add a message part.
		* @param in the message part to add
		*/
		template<typename Alloc>
		void update(const std::vector<uint8_t, Alloc>& in)
		{
			update(in.data(), in.size());
		}

		/**
		* Add a message part.
		* @param in the message part to add
		*/
		void update(const std::string& in)
		{
			update(Botan::cast_char_ptr_to_uint8(in.data()), in.size());
		}

		/**
		* Get the signature of the so far processed message (provided by the
		* calls to update()).
		* @return signature of the total message
		*/
		std::vector<uint8_t> signature();

		/**
		* Return an upper bound on the length of the signatures this
		* Signer will produce
		*/
		size_t signature_length() const;

	private:
		std::unique_ptr<Botan::PK_Ops::Signature> m_op;
		size_t m_parts, m_part_size;
};

/**
* Public Key Verifier. Use the verify_message() functions for small
* messages. Use multiple calls update() to process large messages and
* verify the signature by finally calling check_signature().
*/
class Verifier
{
	public:
		/**
		* Construct a PK Verifier.
		* @param pub_key the public key to verify against
		* @param emsa the EMSA to use (eg "EMSA3(SHA-1)")
		* @param provider the provider to use
		*/
		Verifier(const Botan::Public_Key& pub_key,
						const std::string& emsa,
						const std::string& provider = "");

		~Verifier();

		Verifier(const Verifier&) = delete;
		Verifier(Verifier&&) = delete;
		Verifier& operator=(const Verifier&) = delete;
		Verifier& operator=(Verifier&&) = delete;

		/**
		* Verify a signature.
		* @param msg the message that the signature belongs to, as a byte array
		* @param msg_length the length of the above byte array msg
		* @param sig the signature as a byte array
		* @param sig_length the length of the above byte array sig
		* @return true if the signature is valid
		*/
		bool verify_message(const uint8_t msg[], size_t msg_length,
								  const uint8_t sig[], size_t sig_length);
		/**
		* Verify a signature.
		* @param msg the message that the signature belongs to
		* @param sig the signature
		* @return true if the signature is valid
		*/
		template<typename Alloc, typename Alloc2>
		bool verify_message(const std::vector<uint8_t, Alloc>& msg,
								  const std::vector<uint8_t, Alloc2>& sig)
		{
			return verify_message(msg.data(), msg.size(),
										 sig.data(), sig.size());
		}

		/**
		* Add a message part (single byte) of the message corresponding to the
		* signature to be verified.
		* @param in the byte to add
		*/
		void update(uint8_t in) { update(&in, 1); }

		/**
		* Add a message part of the message corresponding to the
		* signature to be verified.
		* @param msg_part the new message part as a byte array
		* @param length the length of the above byte array
		*/
		void update(const uint8_t msg_part[], size_t length);

		/**
		* Add a message part of the message corresponding to the
		* signature to be verified.
		* @param in the new message part
		*/
		template<typename Alloc>
			void update(const std::vector<uint8_t, Alloc>& in)
		{
			update(in.data(), in.size());
		}

		/**
		* Add a message part of the message corresponding to the
		* signature to be verified.
		*/
		void update(const std::string& in)
		{
			update(Botan::cast_char_ptr_to_uint8(in.data()), in.size());
		}

		/**
		* Check the signature of the buffered message, i.e. the one build
		* by successive calls to update.
		* @param sig the signature to be verified as a byte array
		* @param length the length of the above byte array
		* @return true if the signature is valid, false otherwise
		*/
		bool check_signature(const uint8_t sig[], size_t length);

		/**
		* Check the signature of the buffered message, i.e. the one build
		* by successive calls to update.
		* @param sig the signature to be verified
		* @return true if the signature is valid, false otherwise
		*/
		template<typename Alloc>
		bool check_signature(const std::vector<uint8_t, Alloc>& sig)
		{
			return check_signature(sig.data(), sig.size());
		}

	private:
		std::unique_ptr<Botan::PK_Ops::Verification> m_op;
		size_t m_parts, m_part_size;
};