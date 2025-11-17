#include "keymaterials.h"
#include "mikeysakke4c.h"
#include "gtest/gtest.h"
#include <libmcrypto/rand.h>
#include <libmutil/Logger.h>
#include <mscrypto/eccsi.h>
#include <mscrypto/parameter-set.h>
#include <test_data.h>
#include <util/octet-string.h>

void stw_log(int log_level, const char* filename, unsigned line, const char* function, char* thread_name, long thread_id, const char* log) {
    fprintf(stderr, "[%s:%d][%s] %s\n", filename, line, function, log);
}

TEST(test_eccsi, testsign_verify) {
    mikey_sakke_set_log_func(stw_log);
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    OctetString id   = OctetString::skipws("7bff17ef68f63d62f20b1380254b2078aa5c606151225682eae8a49937e3bb59");
    auto        keys = std::make_shared<MikeySakkeKMS::RuntimeKeyStorage>();
    keys->AddCommunity("streamwide.com");
    std::vector<std::string> communities = keys->GetCommunityIdentifiers();

    keys->StorePublicKey(communities[0], "Z", OctetString::skipws(STW_KEYMAT_Z));
    keys->StorePublicKey(communities[0], "KPAK", OctetString::skipws(STW_KEYMAT_KPAK));
    keys->StorePrivateKey(id.translate(), "RSK", OctetString::skipws(STW_KEYMAT_RSK_GMS));
    keys->StorePrivateKey(id.translate(), "SSK", OctetString::skipws(STW_KEYMAT_SSK_GMS));
    keys->StorePublicKey(id.translate(), "PVT", OctetString::skipws(STW_KEYMAT_PVT_GMS));
    keys->StorePublicParameter(communities[0], "SakkeSet", "1");

    bool success = MikeySakkeCrypto::ValidateSigningKeysAndCacheHS(id, communities[0], keys);
    ASSERT_TRUE(success);

    // Generate random message to sign it
    size_t   msg_len = 256;
    auto* msg     = new uint8_t[msg_len];

    Rand::randomize(msg, msg_len);

    const size_t sig_len = 1 + 4 * MikeySakkeCrypto::eccsi_6509_param_set().hash_len;
    auto*     sig     = new uint8_t[sig_len];

    success = MikeySakkeCrypto::Sign(msg, msg_len, sig, sig_len, id, (bool (*)(void*, size_t))Rand::randomize, keys);
    ASSERT_TRUE(success);

    success = MikeySakkeCrypto::Verify(msg, msg_len, sig, sig_len, id, communities[0], keys);
    ASSERT_TRUE(success);
    delete[](msg);
    delete[](sig);
}

TEST(test_eccsi, testsign_verify_softil) {
    mikey_sakke_set_log_func(stw_log);
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    OctetString id   = OctetString::skipws("9edf69d4006a12fd4dbc3ac7c7e99839bc4c7e6cd2a79a8de72e6b3015f59a3a");
    auto        keys = std::make_shared<MikeySakkeKMS::RuntimeKeyStorage>();
    keys->AddCommunity("streamwide.com");
    std::vector<std::string> communities = keys->GetCommunityIdentifiers();

    keys->StorePublicKey(communities[0], "Z", OctetString::skipws("04753963fbf2b8e8fa35e79b9789a4d46ee4506f26b67f82cd87d6cc73e584a3f0a4150da59a992174087449a4359db7efe8bbd80bbf2d1178ad11251f57ac624b9f9d477696c330f6ddc291625b6072f126649ad520c11b7fa3dff9227e0c5d9d9ec4f5d2911983f8a3d2ad2601ec16c7e395dab28c8afce84aacf5b533875ed42fdf80bb1fc9bea57da1bb3bbcab3dc16a9151f1127ee5fa54e692a31fd617faa36d4851dff57c115c685805ef778f383d1e20589a7a08dde5a97cbb1381b080f76a20e2853f8b178950079f8772ae3957c8bc2d38fae8b9fa12ce3cc92d8aaa11fe21dcf62dfd3c982c9cd811dba02e3bde32b89b937ed3c93721bbced9167d"));
    keys->StorePublicKey(communities[0], "KPAK", OctetString::skipws("04627dbb3e53b1fed07b2105565c62cc9f9179789cdda9a849293adf75613c7c8585fa1afce0c38ed5b12c921f65f1736c5314fb7d516b7157ed10e540b4a8834d"));
    keys->StorePrivateKey(id.translate(), "RSK", OctetString::skipws("046ae3c1fedae2dd1c57f81e9410b45518a78734398d4206cd90d7a2fdde8a06365515e3c3652da5704c92d8482666d50d9436cca9d1a99fc4d87379c6a13b75d98061e1cdc866a8f192c6054835d7195e3d60421d62b4f8607fecfd4c863ca7818fb64555c2f6faa832161dd4a5d57eb5003504c47f550b7374e4de787af8716e73267da1faa9e0112741bd6bce0275a800cfda3ea6da7227da340243f9f7d73fcf2eb1028c95f4d7a85843e8e60d4b3a6cd64776cfe86fd01fa73fa1d4f13e3e77d727a26acae7377a2d087fb96d57a07bbcfe65816ab090779458ee8bb7b15716d372f945a8d751139538bf61c3619f9ef1e1bbbe4d7f96a654979ca5bd89d1"));
    keys->StorePrivateKey(id.translate(), "SSK", OctetString::skipws("0d00a72e73b489bd59f0651992bc678a03f318c1f030fd8debc9458d78c5efe7"));
    keys->StorePublicKey(id.translate(), "PVT", OctetString::skipws("04f7b66e1df9ce9275c37aa998f73b596bb015a6572bb16b98f17641c1899779fed23ed85d427db6e2992c6c15003046e837833c1bc32f8237b604aeb831999934"));
    keys->StorePublicParameter(communities[0], "SakkeSet", "1");

    bool success = MikeySakkeCrypto::ValidateSigningKeysAndCacheHS(id, communities[0], keys);
    ASSERT_TRUE(success);

    // Generate random message to sign it
    size_t   msg_len = 256;
    auto* msg     = new uint8_t[msg_len];

    Rand::randomize(msg, msg_len);

    const size_t sig_len = 1 + 4 * MikeySakkeCrypto::eccsi_6509_param_set().hash_len;
    auto*     sig     = new uint8_t[sig_len];

    success = MikeySakkeCrypto::Sign(msg, msg_len, sig, sig_len, id, (bool (*)(void*, size_t))Rand::randomize, keys);
    ASSERT_TRUE(success);

    success = MikeySakkeCrypto::Verify(msg, msg_len, sig, sig_len, id, communities[0], keys);
    ASSERT_TRUE(success);
    delete[](msg);
    delete[](sig);
}