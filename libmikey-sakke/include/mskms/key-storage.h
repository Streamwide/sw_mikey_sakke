#ifndef MSKMS_KEY_STORAGE_H
#define MSKMS_KEY_STORAGE_H

#include <memory>
#include <string>
#include <vector>

struct OctetString;

namespace MikeySakkeKMS {

/**
 * Provides access to and update of a set of identity-based keys.
 * XXX: consider dropping the tier of this by removing the identifier
 * XXX: parameter from all functions.  An application would then map
 * XXX: and identity-specific object via this interface to that
 * XXX: identities keys.  See mskms/key-storage.alternate.h
 */
class KeyStorage {
  public:
    virtual OctetString GetPrivateKey(std::string const& identifier, std::string const& key) const                              = 0;
    virtual OctetString GetPublicKey(std::string const& identifier, std::string const& key) const                               = 0;
    virtual std::string GetPublicParameter(std::string const& identifier, std::string const& param) const                       = 0;
    virtual void        StorePrivateKey(std::string const& identifier, std::string const& key, OctetString const& value)        = 0;
    virtual void        StorePublicKey(std::string const& identifier, std::string const& key, OctetString const& value)         = 0;
    virtual void        StorePublicParameter(std::string const& identifier, std::string const& param, std::string const& value) = 0;

    /**
     * Add a user community.  Key material for these are accessed in
     * the same way as user key material.  This provides a means to
     * accumulate known communities and support enumeration of them via
     * GetCommunityIdentifiers().
     */
    virtual void                     AddCommunity(std::string const&) = 0;
    virtual std::vector<std::string> GetCommunityIdentifiers() const  = 0;

    virtual void RevokeKeys(std::string const& identifier) = 0;
    virtual void Purge()                                   = 0;

    virtual ~KeyStorage() = default;
};
typedef std::shared_ptr<KeyStorage>       KeyStoragePtr;
typedef std::shared_ptr<const KeyStorage> KeyAccessPtr;

} // namespace MikeySakkeKMS

#endif // MSKMS_KEY_STORAGE_H
