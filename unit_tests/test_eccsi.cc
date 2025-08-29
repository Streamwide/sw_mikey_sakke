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