#include "test_data.h"
#include <libmikey/KeyAgreementSAKKE.h>
#include <libmutil/Logger.h>
#include <map>
namespace test_data {
void set_user1_community_params(MikeySakkeKMS::KeyStorage* keys) {
    std::string community                        = "streamwide.com";
    OctetString communityPublicAuthenticationKey = OctetString::skipws("0450d4670bde75244f28d2838a0d25558a7a72686d4522d4c8273fb6442aebfa93d"
                                                                       "bdd37551afd263b5dfd617f3960c65a8c298850ff99f20366dce7d4367217f4");

    keys->AddCommunity(community);
    keys->StorePublicKey(community, "KPAK", communityPublicAuthenticationKey);

    OctetString communityPublicKey = OctetString::skipws(
        "045958ef1b1679bf099b3a030df255aa6a23c1d8f143d4d23f753e69bd27a832f38cb4ad53ddef4260b0fe8bb45c4c1ff510effe300367a37b61f701d914aef097"
        "24825fa0707d61a6dff4fbd7273566cdde352a0b04b7c16a78309be640697de747613a5fc195e8b9f328852a579db8f99b1d0034479ea9c5595f47c4b2f54ff215"
        "08d37514dcf7a8e143a6058c09a6bf2c9858ca37c258065ae6bf7532bc8b5b63383866e0753c5ac0e72709f8445f2e6178e065857e0eda10f68206b63505ed87e5"
        "34fb2831ff957fb7dc619dae61301eeacc2fda3680ea4999258a833cea8fc67c6d19487fb449059f26cc8aab655ab58b7cc796e24e9a394095754f5f8bae");
    keys->StorePublicKey(community, "Z", communityPublicKey);
    keys->StorePublicParameter(community, "SakkeSet", "1");
}

void set_alice_and_bob_community_params(MikeySakkeKMS::KeyStorage* keys, std::string community) {
    OctetString communityPublicAuthenticationKey = OctetString::skipws("04                                 "
                                                                       "50D4670B DE75244F 28D2838A 0D25558A"
                                                                       "7A72686D 4522D4C8 273FB644 2AEBFA93"
                                                                       "DBDD3755 1AFD263B 5DFD617F 3960C65A"
                                                                       "8C298850 FF99F203 66DCE7D4 367217F4");

    OctetString communityPublicKey = OctetString::skipws("04                                 "
                                                         "5958EF1B 1679BF09 9B3A030D F255AA6A"
                                                         "23C1D8F1 43D4D23F 753E69BD 27A832F3"
                                                         "8CB4AD53 DDEF4260 B0FE8BB4 5C4C1FF5"
                                                         "10EFFE30 0367A37B 61F701D9 14AEF097"
                                                         "24825FA0 707D61A6 DFF4FBD7 273566CD"
                                                         "DE352A0B 04B7C16A 78309BE6 40697DE7"
                                                         "47613A5F C195E8B9 F328852A 579DB8F9"
                                                         "9B1D0034 479EA9C5 595F47C4 B2F54FF2"
                                                         "                                   "
                                                         "1508D375 14DCF7A8 E143A605 8C09A6BF"
                                                         "2C9858CA 37C25806 5AE6BF75 32BC8B5B"
                                                         "63383866 E0753C5A C0E72709 F8445F2E"
                                                         "6178E065 857E0EDA 10F68206 B63505ED"
                                                         "87E534FB 2831FF95 7FB7DC61 9DAE6130"
                                                         "1EEACC2F DA3680EA 4999258A 833CEA8F"
                                                         "C67C6D19 487FB449 059F26CC 8AAB655A"
                                                         "B58B7CC7 96E24E9A 39409575 4F5F8BAE");

    keys->AddCommunity(community);
    /*
     * KMS Public Authentication Key(KPAK in IETF RFC 6507)
     * "In advance, the KMS chooses its KMS Secret Authentication Key (KSAK),
     * which is the root of trust for all other key material in the scheme.
     * From this, the KMS derives the KMS Public Authentication Key (KPAK),
     * which all devices will require in order to verify signatures.  This
     * will be the root of trust for verification."
     */

    keys->StorePublicKey(community, "KPAK", communityPublicAuthenticationKey);
    // KMS Public Encryption Key ("Z" in IETF RFC 6508)
    keys->StorePublicKey(community, "Z", communityPublicKey);
    keys->StorePublicParameter(community, "SakkeSet", "1");
    keys->StorePublicParameter(community, "UserKeyPeriod", "2592000");
    keys->StorePublicParameter(community, "UserKeyOffset", "0");
    keys->StorePublicParameter(community, "KmsUri", "example.streamwide.com");
}

MikeySakkeKMS::KeyStorage* make_alice_key_store(const std::string& user_uri, const std::string& user_community) {
    MikeySakkeKMS::KeyStorage* keys = new MikeySakkeKMS::RuntimeKeyStorage;

    std::string alice_uri = user_uri;
    std::string community = user_community;
    set_alice_and_bob_community_params(keys, community);

    uint32_t    userKeyPeriod = std::stoi(keys->GetPublicParameter(community, "UserKeyPeriod"));
    uint32_t    userKeyOffset = std::stoi(keys->GetPublicParameter(community, "UserKeyOffset"));
    std::string kmsUri        = keys->GetPublicParameter(community, "KmsUri");
    OctetString alice_id      = genMikeySakkeUid(alice_uri, kmsUri, userKeyPeriod, userKeyOffset);

    // https://tools.ietf.org/html/rfc6507#section-5.1

    // user signing key for each UID for the current time period (SSK and PVT in IETF RFC 6507).
    // SSK : Secret Signing Key
    //    : A private key given by the KMS to sign messages
    keys->StorePrivateKey(alice_id.translate(), "SSK",
                          OctetString::skipws("23F374AE 1F4033F3 E9DBDDAA EF20F4CF"
                                              "0B86BBD5 A138A5AE 9E7E006B 34489A0D"));

    // PVT : Public Verification Token
    //    : Together with the KPAK, enables us to verify messages signed with SSK
    keys->StorePublicKey(alice_id.translate(), "PVT",
                         OctetString::skipws("04                                 "
                                             "758A1427 79BE89E8 29E71984 CB40EF75"
                                             "8CC4AD77 5FC5B9A3 E1C8ED52 F6FA36D9"
                                             "A79D2476 92F4EDA3 A6BDAB77 D6AA6474"
                                             "A464AE49 34663C52 65BA7018 BA091F79"));

    return keys;
}

MikeySakkeKMS::KeyStorage* make_bob_key_store(const std::string& user_uri, const std::string& user_community) {
    MikeySakkeKMS::KeyStorage* keys = new MikeySakkeKMS::RuntimeKeyStorage;

    std::string bob_uri   = user_uri;
    std::string community = user_community;
    set_alice_and_bob_community_params(keys, community);

    uint32_t    userKeyPeriod = std::stoi(keys->GetPublicParameter(community, "UserKeyPeriod"));
    uint32_t    userKeyOffset = std::stoi(keys->GetPublicParameter(community, "UserKeyOffset"));
    std::string kmsUri        = keys->GetPublicParameter(community, "KmsUri");
    OctetString bob_id        = genMikeySakkeUid(bob_uri, kmsUri, userKeyPeriod, userKeyOffset);

    // RSK : Receiver Secret Key
    //    : Key provided by the KMS
    //    : Each user's RSK protects the SAKKE communications it receives.  This
    //    : key MUST NOT be revealed to any entity other than the trusted KMS and
    //    : the authorized user.
    //    : https://tools.ietf.org/html/rfc6508
    keys->StorePrivateKey(bob_id.translate(), "RSK",
                          OctetString::skipws("04                                 "
                                              "93AF67E5 007BA6E6 A80DA793 DA300FA4"
                                              "B52D0A74 E25E6E7B 2B3D6EE9 D18A9B5C"
                                              "5023597B D82D8062 D3401956 3BA1D25C"
                                              "0DC56B7B 979D74AA 50F29FBF 11CC2C93"
                                              "F5DFCA61 5E609279 F6175CEA DB00B58C"
                                              "6BEE1E7A 2A47C4F0 C456F052 59A6FA94"
                                              "A634A40D AE1DF593 D4FECF68 8D5FC678"
                                              "BE7EFC6D F3D68353 25B83B2C 6E69036B"
                                              "                                   "
                                              "155F0A27 241094B0 4BFB0BDF AC6C670A"
                                              "65C325D3 9A069F03 659D44CA 27D3BE8D"
                                              "F311172B 55416018 1CBE94A2 A783320C"
                                              "ED590BC4 2644702C F371271E 496BF20F"
                                              "588B78A1 BC01ECBB 6559934B DD2FB65D"
                                              "2884318A 33D1A42A DF5E33CC 5800280B"
                                              "28356497 F87135BA B9612A17 26042440"
                                              "9AC15FEE 996B744C 33215123 5DECB0F5"));

    return keys;
}

MikeySakkeKMS::KeyStorage* make_user1_key_store() {
    /* Mai */
    MikeySakkeKMS::KeyStorage* keys = new MikeySakkeKMS::RuntimeKeyStorage;

    OctetString id = OctetString::skipws("017dd1e4d90067c619569e4b9ee5904812e66c973004ad7bcebb21fa7df8e5cb");

    keys->StorePrivateKey(
        id.translate(), "RSK",
        OctetString::skipws("045e2c398196c0443c4860fe5e39965ce7bb41f4591727662d67c785550150c6dc3e0c407982806102ef9f6c6e13ba641ae3dcb8d440f1"
                            "72e02af7f77c2e2a7ea55038a40e3678a130ee5351edf32db562bc3f921985c4d969b1a14dbfbae716007fa2eff44a9cc0a63c0e27accd"
                            "a444822f11e9d2a6137db1eaf7c0419ff175574691208dbcddbd22098d12fd9d461487f1304bf3a2557a2f798b1083a57113c999250e8e"
                            "b918bc930f83402421a0530c3506aeab6c5c834b742700f8ee86ef55e951b0f93628dbd9b1a0ffbdb5b0a85aa5c8301ba4a4d7a03e4355"
                            "f9a957d3ab4eaf9cd9e6268d04c934fa6d34010718f5739a4cf489f0e0bdbfe448e934f339"));

    keys->StorePrivateKey(id.translate(), "SSK", OctetString::skipws("463d4c31527a811b1a982b39f92fc50972214a247f6d40be03f8063805c0215d"));

    keys->StorePublicKey(id.translate(), "PVT",
                         OctetString::skipws("04758a142779be89e829e71984cb40ef758cc4ad775fc5b9a3e1c8ed52f6fa36d9a79d247692f4eda3a6bdab77d6a"
                                             "a6474a464ae4934663c5265ba7018ba091f79"));

    set_user1_community_params(keys);

    return keys;
}

MikeySakkeKMS::KeyStorage* make_user2_key_store() {
    MikeySakkeKMS::KeyStorage* keys = new MikeySakkeKMS::RuntimeKeyStorage;

    std::string community = "streamwide.com";
    OctetString id        = OctetString::skipws("1377385F F4CB7BCF"
                                                       "396AD56C 4E9EDCA6"
                                                       "386D7B0C 731D4BC7"
                                                       "3196D2B9 840B69B9");

    keys->StorePrivateKey(
        id.translate(), "RSK",
        OctetString::skipws("041CC539C22536AF3C25DFBDFEE87D10D5B61DBB3A8F38A7A7AA02FD87591A0AEED6733FF5B11AAE0A6A139D3AF5B266AD23CAE4D46FAC"
                            "0EB8EFE3B6CCB457908DE4A6F6A8F606FEADF8A5F6138E4C4CF3B23AAC8486694303E737C01DB171C6762EE30D4F103C6DB9D92687230B"
                            "A34B62DC3CBF872C0B1D7F7AFB9F11320841E50502030CA465BA9E7133B93D3BDC97DE11741FAE7AAAA5A18E22609AB26CD71ABE6F0C17"
                            "06DD093571AD122ADB4D077B2EC02866064616E4D591F19E58E0560E5AAF99E9DFA095FA5537BF567FB8D75432899CA5B19F9F879A63C1"
                            "57E89022D7DA475D0267E890E911AB349D0F03DCF960DB64904A0B284CED193AFAADFE03B8"));

    keys->StorePrivateKey(id.translate(), "SSK", OctetString::skipws("C6F69C499E61773D400DE92AB726F38CCB5B01BA66B1B8FBDA27034C82947715"));

    keys->StorePublicKey(id.translate(), "PVT",
                         OctetString::skipws("04"
                                             "00000000B2BAFED7D364E5309DCDA9C4662E4BCB5D89CAB8867E78B8C15FE57B000000008680167AC14EED89C1A23"
                                             "4ED78C76269F694CC47E6185F0135D0656E"));

    set_alice_and_bob_community_params(keys, community);

    return keys;
}

std::string get_i_msg_for_user1() {
    /*Mai*/
    return "mikey "
           "ARoFAQcZnTkAAQsAAAAAAOQ9FMAOEM4YZW2qipAlMPmctrg7TKkOAQEAE0dNU0B0aGFsZXNncm91cC5jb20OAgEAFHVzZXIxQHN0cmVhbXdpZGUuY29tDgYBABNLTVN"
           "AdGhhbGVzZ3JvdXAuY29tGgcBABJLTVNAc3RyZWFtd2lkZS5jb20VAQIBEQRIit0KhOgMUMrMB6XAEVDrrkEDzrUfcaXw19a+"
           "1BFd8yiKmMLZKNeOhhnOc6bjVNG7QfiFMxm8bBM8mpUhq5qcKU0rdYOGJqHCxcGg8SAiOaDzn1K54cdmlIfbXqGQH1J45UzIfiyS95AmQiDUJ2iwYMQ6lGX3Dp+"
           "LjLsKu37jaDEFHG0t104w6Ifil3KtdAxLg8hVfk7/Ij+eZr1DgKaMF6TRUpTrJotWjTU7b+lW/n68oehmLcwEGBC2iTIatfXADXIxsNRb7/"
           "ahkig5Ce6I2JlJzM8Jqd1oWeGwGjKRze5CPmMtqi4QoBFOO4RPTYJdXHUzBIFVyphdFeecWOCMmM48MWcq7J0PNDgUA5RLGAQHAA4AAQAAAAAAAAAAAAAB/"
           "yCBJp1Mj962anTk74wNXcxZfd/mApwq/8STYAjNLMEEXYFAPdL3BIoSBjdg168n/95Ny2lLW+wcAMCA7BBuqVMLiwR1ihQneb6J6CnnGYTLQO91jMStd1/"
           "FuaPhyO1S9vo22aedJHaS9O2jpr2rd9aqZHSkZK5JNGY8UmW6cBi6CR95";
}
} // namespace test_data
