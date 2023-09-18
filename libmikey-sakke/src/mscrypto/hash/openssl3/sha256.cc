#include <cassert>
#include <mscrypto/hash/sha256.h>
#include <openssl/evp.h>
#include <util/octet-string.h>

namespace MikeySakkeCrypto {

InplaceSHA256Digest::InplaceSHA256Digest(OctetString& result): result(result.raw()), insync(true) {
    assert(result.size() >= 32);
    ctx = EVP_MD_CTX_new();
    md  = EVP_MD_fetch(nullptr, "SHA256", nullptr);
    EVP_DigestInit_ex(ctx, md, nullptr);
}
InplaceSHA256Digest::InplaceSHA256Digest(uint8_t result[32]): result(result), insync(true) {
    ctx = EVP_MD_CTX_new();
    md  = EVP_MD_fetch(nullptr, "SHA256", nullptr);
    EVP_DigestInit_ex(ctx, md, nullptr);
}
InplaceSHA256Digest::~InplaceSHA256Digest() {
    if (!is_complete())
        complete();
}

InplaceSHA256Digest& InplaceSHA256Digest::digest(uint8_t const* octets, size_t N) {
    assert(!is_complete());
    insync = false;
    EVP_DigestUpdate(ctx, octets, N);
    return *this;
}
InplaceSHA256Digest& InplaceSHA256Digest::digest(OctetString const& octets) {
    assert(!is_complete());
    insync = false;
    EVP_DigestUpdate(ctx, octets.raw(), octets.size());
    return *this;
}
InplaceSHA256Digest& InplaceSHA256Digest::digest(std::string const& s) {
    assert(!is_complete());
    insync = false;
    EVP_DigestUpdate(ctx, s.c_str(), s.size());
    return *this;
}
InplaceSHA256Digest& InplaceSHA256Digest::sync() {
    assert(!is_complete());
    if (!insync) {
        EVP_DigestFinal_ex(ctx, result, nullptr);
        EVP_DigestInit_ex(ctx, md, nullptr);
        insync = true;
    }
    return *this;
}
void InplaceSHA256Digest::complete() {
    assert(!is_complete());
    if (!insync) {
        EVP_DigestFinal_ex(ctx, result, nullptr);
        insync = true;
    }
    EVP_MD_CTX_free(ctx);
    EVP_MD_free(md);
    result = nullptr;
}
bool InplaceSHA256Digest::is_synchronized() const {
    return insync;
}
bool InplaceSHA256Digest::is_complete() const {
    return result == nullptr;
}

SHA256Digest::SHA256Digest(): OctetStringHolder(32), InplaceSHA256Digest(octets.raw()) {}
SHA256Digest::~SHA256Digest() {
    assert(is_complete());
}

OctetString const& SHA256Digest::str() const {
    assert(is_synchronized());
    return octets;
}

} // namespace MikeySakkeCrypto