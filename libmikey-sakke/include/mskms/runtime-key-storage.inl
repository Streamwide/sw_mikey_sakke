#ifndef MSKMS_RUNTIME_KEY_STORAGE_INL
#define MSKMS_RUNTIME_KEY_STORAGE_INL

#include <mskms/key-storage.h>
#include <util/octet-string.h>
#include <map>
#include <set>

namespace MikeySakkeKMS {

/**
 * Development implementation for key storage in memory.  Key data is
 * not persisted across runs causing a fetch on each initial access
 * for each run.
 */
class RuntimeKeyStorage : public KeyStorage
{
public:

   OctetString GetPrivateKey(std::string const& identifier, std::string const& key) const override
   {
      return FetchOrDefault(privateKeys, identifier, key);
   }
   OctetString GetPublicKey(std::string const& identifier, std::string const& key) const override
   {
      return FetchOrDefault(publicKeys, identifier, key);
   }
   std::string GetPublicParameter(std::string const& identifier, std::string const& key) const override
   {
      return FetchOrDefault(publicParameters, identifier, key);
   }
   void StorePrivateKey(std::string const& identifier, std::string const& key, OctetString const& value) override
   {
      privateKeys[identifier][key] = value;
   }
   void StorePublicKey(std::string const& identifier, std::string const& key, OctetString const& value) override
   {
      publicKeys[identifier][key] = value;
   }
   void StorePublicParameter(std::string const& identifier, std::string const& key, std::string const& value) override
   {
      publicParameters[identifier][key] = value;
   }
   void AddCommunity(std::string const& community) override
   {
      communities.insert(community);
   }
   std::vector<std::string> GetCommunityIdentifiers() const override
   {
      return std::vector<std::string>(communities.begin(), communities.end());
   }
   void RevokeKeys(std::string const& identifier) override
   {
      privateKeys.erase(identifier);
      publicKeys.erase(identifier);
      publicParameters.erase(identifier);
      communities.erase(identifier);
   }
   void Purge() override
   {
      privateKeys.clear();
      publicKeys.clear();
      publicParameters.clear();
      communities.clear();
   }

private:


   template <class Map>
   static typename Map::mapped_type::mapped_type
   FetchOrDefault(Map const& map, std::string const& identifier, std::string const& key)
   {
      auto it = map.find(identifier);
      if (it != map.end())
      {
         auto keys = it->second;
         auto kit = keys.find(key);
         if (kit != keys.end())
            return kit->second;
      }
      return typename Map::mapped_type::mapped_type();
   }

   std::map<std::string, std::map<std::string, std::string> > publicParameters;
   std::map<std::string, std::map<std::string, OctetString> > publicKeys;
   std::map<std::string, std::map<std::string, OctetString> > privateKeys;
   std::set<std::string> communities;
};

} // MikeySakkeKMS

#endif//MSKMS_RUNTIME_KEY_STORAGE_INL

