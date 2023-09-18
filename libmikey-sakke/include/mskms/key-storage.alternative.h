#ifndef MSKMS_KEY_STORAGE_H
#define MSKMS_KEY_STORAGE_H

#include <map>
#include <util/std.h>

struct OctetString;

namespace MikeySakkeKMS {

/**
 * Provides access to and update of a set key material.
 */
class KeyStorage {
  public:
    virtual OctetString GetPrivateKey(std::string const& key) const                              = 0;
    virtual OctetString GetPublicKey(std::string const& key) const                               = 0;
    virtual std::string GetPublicParameter(std::string const& param) const                       = 0;
    virtual void        StorePrivateKey(std::string const& key, OctetString const& value)        = 0;
    virtual void        StorePublicKey(std::string const& key, OctetString const& value)         = 0;
    virtual void        StorePublicParameter(std::string const& param, std::string const& value) = 0;
    virtual ~KeyStorage() {}
};
typedef std::shared_ptr<KeyStorage>       KeyStoragePtr;
typedef std::shared_ptr<const KeyStorage> KeyAccessPtr;

/**
 * Provides access to and update of identity-based key material.
 */
class KeyRing {
  public:
    KeyRing(std::function<KeyStoragePtr(std::string const& identifier)> const& factory): factory(factory) {}
    virtual ~KeyRing() {}

  public:
    KeyStoragePtr GetUserKeys(std::string const& identifier) {
        return GetKeys(userKeys, identifier);
    }
    KeyAccessPtr GetUserKeys(std::string const& identifier) const {
        return GetKeys(userKeys, identifier);
    }

    KeyStoragePtr GetCommunityKeys(std::string const& identifier) {
        return GetKeys(communityKeys, identifier);
    }
    KeyAccessPtr GetCommunityKeys(std::string const& identifier) const {
        return GetKeys(communityKeys, identifier);
    }

    void RevokeKeys(std::string const& identifier);

  private:
    std::map<std::string, KeyStoragePtr> userKeys;
    std::map<std::string, KeyStoragePtr> communityKeys;

    template <class Map> KeyStoragePtr GetKeys(Map& map std::string const& identifier) {
        Map::const_iterator it = map.find(identifier);
        if (it != end)
            return it->second;
        return map[factory(identifier)];
    }
    template <class Map> static KeyAccessPtr GetKeys(Map const& map, std::string const& identifier) {
        Map::const_iterator it = map.find(identifier);
        if (it != end)
            return it->second;
        return KeyAccessPtr();
    }
};

} // namespace MikeySakkeKMS

#endif // MSKMS_KEY_STORAGE_H
