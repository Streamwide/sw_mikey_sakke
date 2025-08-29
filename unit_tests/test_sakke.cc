#include "keymaterials.h"
#include "mikeysakke4c.h"
#include "gtest/gtest.h"
#include <libmcrypto/rand.h>
#include <libmutil/Logger.h>
#include <mscrypto/parameter-set.h>
#include <mscrypto/sakke.h>
#include <test_data.h>
#include <util/octet-string.h>

void stw_log(int log_level, const char* filename, unsigned line, const char* function, char* thread_name, long thread_id, const char* log) {
    fprintf(stderr, "[%s:%d][%s] %s\n", filename, line, function, log);
}

TEST(test_sakke, test_workaround) {
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");
    //static constexpr size_t MIKEY_SAKKE_DEFAULT_KEY_SIZE = 16;
    OctetString      id                           = OctetString::skipws("7bff17ef68f63d62f20b1380254b2078aa5c606151225682eae8a49937e3bb59");
    auto             keys                         = std::make_shared<MikeySakkeKMS::RuntimeKeyStorage>();
    keys->AddCommunity("streamwide.com");
    std::vector<std::string> communities = keys->GetCommunityIdentifiers();

    keys->StorePublicKey(communities[0], "Z", OctetString::skipws(STW_KEYMAT_Z));
    keys->StorePublicKey(communities[0], "KPAK", OctetString::skipws(STW_KEYMAT_KPAK));
    keys->StorePrivateKey(id.translate(), "RSK", OctetString::skipws(STW_KEYMAT_RSK_GMS));
    keys->StorePrivateKey(id.translate(), "SSK", OctetString::skipws(STW_KEYMAT_SSK_GMS));
    keys->StorePublicKey(id.translate(), "PVT", OctetString::skipws(STW_KEYMAT_PVT_GMS));
    keys->StorePublicParameter(communities[0], "SakkeSet", "1");

    // FIXME Doesn't work with OPENSSL_ONLY
    // bool success = MikeySakkeCrypto::ValidateReceiverSecretKey(id.translate(), communities[0], keys);
    // ASSERT_TRUE(success);

    OctetString SED;
    OctetString key_bytes(MIKEY_SAKKE_DEFAULT_KEY_SIZE);
    Rand::randomize(key_bytes.raw(), MIKEY_SAKKE_DEFAULT_KEY_SIZE);

    MIKEY_SAKKE_LOGD("Generated GMK : %s", key_bytes.translate().c_str());

    auto SSV = MikeySakkeCrypto::GenerateSharedSecretAndSED(SED, id, communities[0], keys, key_bytes);

    ASSERT_FALSE(SSV.empty());
    // SED should always start with 0x04 to indicate uncompressed data
    ASSERT_EQ(*SED.raw(), 0x04);
    MIKEY_SAKKE_LOGD("Shared Secret Value : %s", SSV.translate().c_str());
    MIKEY_SAKKE_LOGD("SAKKE Encapsulated Data : %s", SED.translate().c_str());

    auto decrypted_secret = MikeySakkeCrypto::ExtractSharedSecret(SED, id, communities[0], keys, 16);
    MIKEY_SAKKE_LOGD("Decrypted secret : %s", decrypted_secret.translate().c_str());

    ASSERT_FALSE(decrypted_secret.empty());
    ASSERT_TRUE(SSV.translate() == decrypted_secret.translate());
}