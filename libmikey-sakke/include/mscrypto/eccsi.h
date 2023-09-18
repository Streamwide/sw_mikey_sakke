#ifndef MSCRYPTO_ECCSI_H
#define MSCRYPTO_ECCSI_H

#include <mscrypto/random.h>
#include <mskms/client-fwd.h>

struct OctetString;

namespace MikeySakkeCrypto {

/**
 * Validate the message signing \a keys delivered to the user given by
 * \a identifier in the specified \a community.  Note that the \a keys
 * passed are mutable.  Should the validation fail, ALL keys
 * accessible through \a identifier will be revoked and the function
 * will return false.  If successful, the value of "HS" calculated
 * during the validation algorithm is cached as a public key of \a
 * identifier for later use within Sign() below and true is returned.
 */
bool ValidateSigningKeysAndCacheHS(const OctetString& identifier, std::string const& community, MikeySakkeKMS::KeyStoragePtr const& keys);

/**
 * Sign the message given by the range [ \a msg, \a msg + \a msg_len )
 * using the key material for the given \a identifier in the given \a
 * community from the key store \a keys and the random number
 * generator \a random.  The sign output is stored in the range [ \a
 * sign_out, \a sign_out + \a sign_len ).
 *
 * \return true if signing was successful, false otherwise.
 */
bool Sign(uint8_t const* msg, size_t msg_len, uint8_t* sign_out, size_t sign_len, OctetString const& identifier,
          RandomGenerator const& random, MikeySakkeKMS::KeyAccessPtr const& keys);

/**
 * As per in-place Sign() above but returns the signature via the
 * function result.
 */
OctetString Sign(uint8_t const* msg, size_t msg_len, OctetString const& identifier, RandomGenerator const& random,
                 MikeySakkeKMS::KeyAccessPtr const& keys);

/**
 * Verify the signature given by the range [ \a sign, \a sign + \a
 * sign_len ) against the message given by the range [ \a msg, \a msg
 * + \a msg_len ) using the key material for the given \a identifier
 * in the given \a community from the key store \a keys.
 *
 * \return true if the message is verified by the signature, false
 * otherwise.
 */
bool Verify(uint8_t const* msg, size_t msg_len, uint8_t const* sign, size_t sign_len, const OctetString& identifier,
            std::string const& community, MikeySakkeKMS::KeyAccessPtr const& keys);

} // namespace MikeySakkeCrypto

#endif // MSCRYPTO_ECCSI_H
