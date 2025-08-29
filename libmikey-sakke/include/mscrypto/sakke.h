#ifndef MSCRYPTO_SAKKE_H
#define MSCRYPTO_SAKKE_H

#include <mscrypto/random.h>
#include <mskms/client-fwd.h>

struct OctetString;

namespace MikeySakkeCrypto {

/**
 * Validate the message decryption key in \a keys delivered to the
 * user given by \a identifier in the specified \a community.  Note
 * that the \a keys passed are mutable.  Should the validation fail,
 * ALL keys accessible through \a identifier will be revoked.
 * \return true on successful validate, false otherwise.
 */
bool ValidateReceiverSecretKey(const OctetString& identifier, std::string const& community, MikeySakkeKMS::KeyStoragePtr const& keys);

/**
 * Using the random number generator \a random, generate a Shared
 * Secret Value (SSV) and corresponding SAKKE Encapsulated Data (\a
 * SED) for the given \a identifier from the community \a community
 * using the key material from the key store \a keys.
 *
 * \param [out] SED The SAKKE Encapsulated Data used to transmit the
 *                  SSV securely to the user identified by \a identifier
 *                  in community \a community.
 * \return the Shared Secret Value, a cryptographically strong random number.
 * \return empty string on failure.
 */
OctetString GenerateSharedSecretAndSED(OctetString& SED, OctetString const& identifier, std::string const& community,
                                       MikeySakkeKMS::KeyAccessPtr const& keys, const OctetString& SSV);

/**
 * Extract the Shared Secret Value (SSV) intended for the user given
 * by \a identifier in the community \a community from the provided
 * SAKKE Encapsulated Data (\a SED) using the key material from the
 * key store \a keys.
 *
 * \return the Shared Secret Value, a cryptographically strong random value.
 * \return empty string on failure.
 */
OctetString ExtractSharedSecret(OctetString const& SED, const OctetString& identifier, std::string const& community,
                                MikeySakkeKMS::KeyAccessPtr const& keys, int SSVSize);

std::vector<uint8_t> GenerateGukIdSalt(OctetString peerUri, OctetString const& GMK);

std::vector<uint8_t> GenerateGukId(OctetString peerUri, const OctetString& gmk, const OctetString& gmkId);

OctetString ExtractGmkId(OctetString gukId, OctetString peerUri, OctetString const& key);

std::vector<uint8_t> GenericKdf(const uint8_t FC, OctetString const& P0, OctetString const& key);
std::vector<uint8_t> DerivateDppkToDpck(OctetString const& dppkId, OctetString const& DPPK);

} // namespace MikeySakkeCrypto

#endif // MSCRYPTO_SAKKE_H
