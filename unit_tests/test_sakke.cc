#include "keymaterials.h"
#include "mikeysakke4c.h"
#include "gtest/gtest.h"
#include <libmcrypto/rand.h>
#include <libmutil/Logger.h>
#include <mscrypto/parameter-set.h>
#include <mscrypto/sakke.h>
#include <test_data.h>
#include <util/octet-string.h>

#define STW_KEYMAT_RSK_GMS_1529 "047f97e3fe5f387004057e864ea1ecc1269be194f1ba676ad0f45c590bd3816a076e0ae4dda49ff88a40cf09ce85dc0a507f0c77ae1803654ff9a22be7838e14e43ce00fe8fc3e74ecbeb85e32211891375566351a3262787ac0f8ca7dbb280a28c71b55428742f211894a82ff7562db4e28dea72bdfda8a59254d9f11874b60d7991e2f7de3418b3b89fd5cc328b2502ba39020b642d16b9925753d68b05a5a20f62a4380fcac98f1417a023087fb4ff6938a1ed4bec5b8fc94fe05ff2da66beb1fdcadbde27713e7dab0613263d236c08f31751b19fcee0ac557f92e5771c4532695cab5a5f2e85aebfb1bccb74f7ed8d0e50e63136582fd148c1e9878a44f11"
#define STW_KEYMAT_SSK_GMS_1529 "af5c4672503c1c1725725cfd70d18f7b6dc1b45fda5a5e2e1b38d634eae83627"
#define STW_KEYMAT_PVT_GMS_1529 "0408fcce1b78e519f39adbaa1c501f26bfcb0711acf9d32b5d4881297b2cb574c20653e6418379c8d29408943dbc1b6cb100d4aadb285d74dd5f378bd144045992"

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

TEST(test_sakke, test_softil_no_identity_hidding) {
    mikey_sakke_set_log_func(stw_log);
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");
    //static constexpr size_t MIKEY_SAKKE_DEFAULT_KEY_SIZE = 16;
    //OctetString      id                           = OctetString("gms@streamwide.com", OctetString::Untranslated);
    OctetString id = OctetString::skipws("2c1ef02fffa063388ee934b1c7d0af085c5b027c0d84f5fca40385e8a763e8c0");
    auto             keys                         = std::make_shared<MikeySakkeKMS::RuntimeKeyStorage>();
    keys->AddCommunity("streamwide.com");
    std::vector<std::string> communities = keys->GetCommunityIdentifiers();

    keys->StorePublicKey(communities[0], "Z", OctetString::skipws(STW_KEYMAT_Z));
    keys->StorePublicKey(communities[0], "KPAK", OctetString::skipws(STW_KEYMAT_KPAK));
    keys->StorePrivateKey(id.translate(), "RSK", OctetString::skipws(STW_KEYMAT_RSK_GMS_1529));
    keys->StorePrivateKey(id.translate(), "SSK", OctetString::skipws(STW_KEYMAT_SSK_GMS_1529));
    keys->StorePublicKey(id.translate(), "PVT", OctetString::skipws(STW_KEYMAT_PVT_GMS_1529));
    keys->StorePublicParameter(communities[0], "SakkeSet", "1");

    // FIXME Doesn't work with OPENSSL_ONLY
    //bool success = MikeySakkeCrypto::ValidateReceiverSecretKey(id.translate(), communities[0], keys);
    //ASSERT_TRUE(success);

    OctetString SED = OctetString::skipws("043ad082971fa5d2d3b579df9def89c621bb3748ef46769da48ecfc2224d55c62db11d662c2b6257450d5116a0ad1257adeccc7cc16980ee6de72e24e9e1ecf42f93cf4155ccdeb86bd2b71a56ce51017717617ec48125abcf91acfc3a15a14535e4a7ab4a03ba736360cfba217b7d77242fa2b4baa93363c355ecc20a2eac983602e50c31ec0b0fe38f79aca614a8d1845e5c843ad6cda607f3b314145499060bd49d966a2ee25d7d0963f1181fbe999f1de933b71604446061b65160b492268998127ae5d6c895b3cd27e3a88db6b826ecdb9195ac5a4feb29d208dc66eccd7a718e5c93fec22ec24f453826a9d8d46ef73b31fa06ebb516263672503e10221b9f5afa40c5eea3d0225671790721d9f9");

    MIKEY_SAKKE_LOGD("SAKKE Encapsulated Data : %s", SED.translate().c_str());

    auto decrypted_secret = MikeySakkeCrypto::ExtractSharedSecret(SED, id, communities[0], keys, 16);
    MIKEY_SAKKE_LOGD("Decrypted secret : %s", decrypted_secret.translate().c_str());

    ASSERT_FALSE(decrypted_secret.empty());
    //ASSERT_TRUE(SSV.translate() == decrypted_secret.translate())
}