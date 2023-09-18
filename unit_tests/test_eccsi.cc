#include "gtest/gtest.h"
#include <libmcrypto/rand.h>
#include <libmutil/Logger.h>
#include <mscrypto/eccsi.h>
#include <mscrypto/parameter-set.h>
#include <test_data.h>
#include <util/octet-string.h>

TEST(test_eccsi, testsign_verify) {
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    OctetString id   = OctetString::skipws("2eca7b7c5dd4170274d5d9894b5eca14e222cb798e6c9621e03189e65606fa55");
    auto        keys = std::make_shared<MikeySakkeKMS::RuntimeKeyStorage>();
    keys->AddCommunity("streamwide.com");
    std::vector<std::string> communities = keys->GetCommunityIdentifiers();
    keys->StorePublicKey(
        communities[0], "Z",
        OctetString::skipws("045958EF1B1679BF099B3A030DF255AA6A23C1D8F143D4D23F753E69BD27A832F38CB4AD53DDEF4260B0FE8BB45C4C1FF510EFFE300367"
                            "A37B61F701D914AEF09724825FA0707D61A6DFF4FBD7273566CDDE352A0B04B7C16A78309BE640697DE747613A5FC195E8B9F328852A57"
                            "9DB8F99B1D0034479EA9C5595F47C4B2F54FF21508D37514DCF7A8E143A6058C09A6BF2C9858CA37C258065AE6BF7532BC8B5B63383866"
                            "E0753C5AC0E72709F8445F2E6178E065857E0EDA10F68206B63505ED87E534FB2831FF957FB7DC619DAE61301EEACC2FDA3680EA499925"
                            "8A833CEA8FC67C6D19487FB449059F26CC8AAB655AB58B7CC796E24E9A394095754F5F8BAE"));

    keys->StorePublicKey(communities[0], "KPAK",
                         OctetString::skipws("0450D4670BDE75244F28D2838A0D25558A7A72686D4522D4C8273FB6442AEBFA93DBDD37551AFD263B5DFD617F396"
                                             "0C65A8C298850FF99F20366DCE7D4367217F4"));

    keys->StorePrivateKey(
        id.translate(), "RSK",
        OctetString::skipws("045C1ED9EEE83503DF7AECB8FCEB53595BAF2C4DD038C064398DDF07448A609BAB528E89BF6D9099D15AAA60C7B1243DB23A05DA597B5E"
                            "58E891587BFCED4073AFC95A9B8F081C109A74FCEC39A089B49494D2D2F9605A5BB8418BF2471D4BF63D0D0C5854D3E864B2A4B2E46177"
                            "060098F0CBC0C4C2E77AC2EB7904FF28CA570622196E352BD2CD83F7414B94068A85B983BC06C160E1B2D8B89177B7B130AA2FD4D844D9"
                            "2E86DE6B034ED2B0A30BEDD9100C67FBA2800223C372ED0F4A6E9F186B06EA2FA5F4E8618A0C6EA594B4B0035C90E6C4E8EFCF4FD24DA8"
                            "3A92957E56AC47F24A918BFDB5AF83E4A9CBDC59AC91C56700E7F10AA2C6D70270C3358FCB"));

    keys->StorePrivateKey(id.translate(), "SSK", OctetString::skipws("EE4C82095BC87BA21EF231860550C8DA9C0E5CACCF5BC78C520989E6379F93DA"));

    keys->StorePublicKey(id.translate(), "PVT",
                         OctetString::skipws("04FB8B8D7CB065096F77822677AFBC2E6667292037947724CC5E93840A44565BCBE6D3EC047A13CF695B1B476757"
                                             "8A6082714340997F7E7AC8A6150543932DA75A"));

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