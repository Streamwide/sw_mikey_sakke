#include "libmutil/Logger.h"
#include "gtest/gtest.h"
#include <array>
#include <libmikey/KeyAgreement.h>
#include <mikeysakkelog4c.h>
#include <mikeysakke4c.h>
#include <util/octet-string.h>
#include <mscrypto/sakke.h>

TEST(test_key_deriv, encr_and_salt) {
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    static constexpr uint8_t       cs_id04 = 0x04;
    static constexpr std::array<uint8_t, 16> ssv     = {0xA2, 0x7B, 0x7D, 0x57, 0x8E, 0xEB, 0x9B, 0x1E, 0xE7, 0x70, 0x5E, 0x38, 0x59, 0x96, 0xD3, 0x00};
    static constexpr std::array<uint8_t, 16> rand    = {0x43, 0x39, 0xF6, 0x2F, 0x55, 0xAA, 0xC8, 0x63, 0x48, 0x84, 0x6A, 0x48, 0x2C, 0x89, 0x38, 0x02};
    static constexpr std::array<uint8_t, 4>  csbId   = {0x05, 0xA8, 0x5C, 0x16};

    static constexpr size_t tek_len  = 16;           // key len
    static constexpr size_t salt_len = 12;           // key salt len
    uint8_t          key[tek_len + salt_len]; // max srtp key len + salt
    KeyAgreement::keyDeriv2(cs_id04, csbId.data(), ssv.data(), ssv.size(), key, tek_len, KEY_DERIV_ENCR, rand.data(), rand.size());
    KeyAgreement::keyDeriv2(cs_id04, csbId.data(), ssv.data(), ssv.size(), key + tek_len, salt_len, KEY_DERIV_SALT, rand.data(), rand.size());

    static constexpr uint8_t expected_key_salt1[] = {0x39, 0x24, 0x93, 0x59, 0x40, 0xc1, 0x54, 0xcc, 0xbc, 0x3c, 0x2a, 0xd0, 0x5c, 0x8f,
                                              0x51, 0x81, 0x17, 0x25, 0x86, 0x9b, 0x80, 0xf3, 0x70, 0xcc, 0x9f, 0x24, 0xe1, 0x3b};
    ASSERT_FALSE(!!memcmp(key, expected_key_salt1, tek_len + salt_len));

    static constexpr uint8_t cs_id00 = 0x00;
    memset(key, 0, tek_len + salt_len);
    KeyAgreement::keyDeriv2(cs_id00, csbId.data(), ssv.data(), ssv.size(), key, tek_len, KEY_DERIV_ENCR, rand.data(), rand.size());
    KeyAgreement::keyDeriv2(cs_id00, csbId.data(), ssv.data(), ssv.size(), key + tek_len, salt_len, KEY_DERIV_SALT, rand.data(), rand.size());
    static constexpr uint8_t expected_key_salt2[] = {0xf1, 0x7c, 0x80, 0xa8, 0xd2, 0xf9, 0xbe, 0xfa, 0x47, 0xcf, 0x71, 0x26, 0x03, 0xd7,
                                              0x22, 0x9a, 0xc3, 0xb7, 0xb5, 0x61, 0xa2, 0x91, 0xa1, 0xd3, 0xab, 0xef, 0x48, 0x2b};
    ASSERT_FALSE(!!memcmp(key, expected_key_salt2, tek_len + salt_len));
}

TEST(test_key_deriv, tek_and_salt) {
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    static constexpr uint8_t       cs_id04 = 0x04;
    static constexpr std::array<uint8_t, 16> ssv     = {0xA2, 0x7B, 0x7D, 0x57, 0x8E, 0xEB, 0x9B, 0x1E, 0xE7, 0x70, 0x5E, 0x38, 0x59, 0x96, 0xD3, 0x00};
    static constexpr std::array<uint8_t, 16> rand    = {0x43, 0x39, 0xF6, 0x2F, 0x55, 0xAA, 0xC8, 0x63, 0x48, 0x84, 0x6A, 0x48, 0x2C, 0x89, 0x38, 0x02};
    static constexpr std::array<uint8_t, 4>  csbId   = {0x06, 0x33, 0xF4, 0x57};

    static constexpr size_t tek_len  = 16;           // key len
    static constexpr size_t salt_len = 12;           // key salt len
    uint8_t          key[tek_len + salt_len]; // max srtp key len + salt
    KeyAgreement::keyDeriv2(cs_id04, csbId.data(), ssv.data(), ssv.size(), key, tek_len, KEY_DERIV_TEK, rand.data(), rand.size());
    KeyAgreement::keyDeriv2(cs_id04, csbId.data(), ssv.data(), ssv.size(), key + tek_len, salt_len, KEY_DERIV_SALT, rand.data(), rand.size());

    static constexpr uint8_t expected_key_salt[] = {0x59, 0xAA, 0xA4, 0x9E, 0xBB, 0x54, 0x81, 0x36, 0x02, 0xB7, 0xCC, 0x16, 0x59, 0x61,
                                             0xB4, 0xE8, 0x74, 0x5E, 0xB4, 0xDF, 0x7D, 0x15, 0x5C, 0x47, 0x31, 0x14, 0xA7, 0x99};
    ASSERT_FALSE(!!memcmp(key, expected_key_salt, tek_len + salt_len));
}

void test_id(uint32_t key_type) {
    uint8_t* keyId = mikey_sakke_gen_key_id(key_type);
    uint32_t test;
    std::memcpy(&test, keyId, sizeof(test));
    uint32_t ret = (keyId[0] & 0xF0) >> 4;//KeyAgreement::extractPurposeTag(test);

    ASSERT_EQ(key_type, ret);

    auto keyId_os = OctetString {4, keyId};
    uint8_t key_raw[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
    auto key_os = OctetString {16, key_raw};
    auto peerUri = OctetString {5, (uint8_t*) "myuri"};
    std::vector<uint8_t> ret_v = MikeySakkeCrypto::GenerateGukId(peerUri, key_os, keyId_os);
    std::memcpy(&test, ret_v.data(), sizeof(test));
    ret = (ret_v.data()[0] & 0xF0) >> 4;//KeyAgreement::extractPurposeTag(test);
    ASSERT_EQ(key_type, ret);
    free(keyId);
};

TEST(test_key_deriv, key_type_gmk) {
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    test_id(GMK);
}

TEST(test_key_deriv, key_type_pck) {
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    test_id(PCK);
}

TEST(test_key_deriv, key_type_csk) {
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    test_id(CSK);
}
