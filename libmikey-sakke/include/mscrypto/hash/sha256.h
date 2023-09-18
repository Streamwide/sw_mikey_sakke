#ifndef MSCRYPTO_HASH_SHA256_H
#define MSCRYPTO_HASH_SHA256_H

#include <cassert>
#include <openssl/opensslv.h>
#include <util/octet-string.h>
#if OPENSSL_VERSION_MAJOR >= 3 // For openssl > 3.0.0
#include <openssl/evp.h>
#elif OPENSSL_VERSION_NUMBER >= 0x1010100fL // For  1.1.1 <= openssl < 3.0.0
#include <openssl/sha.h>
#endif

namespace MikeySakkeCrypto {

class InplaceSHA256Digest {
  public:
    InplaceSHA256Digest(OctetString& result);
    InplaceSHA256Digest(uint8_t result[32]);
    ~InplaceSHA256Digest();

  public:
    InplaceSHA256Digest& digest(uint8_t const* octets, size_t N);
    InplaceSHA256Digest& digest(OctetString const& octets);
    InplaceSHA256Digest& digest(std::string const& s);
    InplaceSHA256Digest& sync();
    void                 complete();
    bool                 is_synchronized() const;
    bool                 is_complete() const;

  private:
#if OPENSSL_VERSION_MAJOR == 3
    EVP_MD_CTX* ctx;
    EVP_MD*     md;
#elif OPENSSL_VERSION_NUMBER > 0x1010100fL
    SHA256_CTX ctx;
#endif
    uint8_t* result;
    bool     insync;
};

struct OctetStringHolder {
    OctetString octets;
    OctetStringHolder(size_t octets): octets(octets) {}
};

class SHA256Digest : private OctetStringHolder, public InplaceSHA256Digest {
  public:
    SHA256Digest();
    ~SHA256Digest();

    OctetString const& str() const;

    operator OctetString const&() {
        return str();
    }
};

} // namespace MikeySakkeCrypto

#endif // MSCRYPTO_HASH_SHA256_H
