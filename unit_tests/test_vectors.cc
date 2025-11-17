#include "libmutil/Logger.h"
#include "mikeysakke4c.h"

#include "gtest/gtest.h"
#include <sstream>
#include <util/octet-string.h>

#include <mscrypto/hash/sha256.h>
#include <mscrypto/parameter-set.h>
#include "mscrypto/sakke.h"

// Tests vectors, which may then, be published to 3GPP (support only 128bit key for now)

const char community[]     = "streamwide.com";
uint8_t   gmk[]             = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
uint8_t   gmk_id[]          = {0xca, 0xfe, 0xba, 0xbe};
const char kms_uri[]       = "0.0.0.0:8080";
uint32_t   user_key_period = 2592000;
uint32_t   user_key_offset = 0;
// DO NOT CHANGE THE KEY PERIOD NO : KEYS WILL VALIDATE ONLY FOR THIS PERIOD
const uint32_t key_period_no = 1490;

TEST(test_vectors, derivation_dpck) {
    mikey_sakke_set_log_level("debug");
    uint8_t     dppkid[]          = {0xde, 0xad, 0xba, 0xad};
    uint8_t    dpck_expected[]    = {0xd8, 0x53, 0xd0, 0xbd, 0x69, 0x16, 0xff, 0xc9, 0x83, 0x7e, 0x2a, 0x20, 0x12, 0xa3, 0x94, 0x91};
    
    auto o_dppkid = OctetString {4, dppkid};
    auto o_gmk = OctetString {16, gmk};

    std::vector<uint8_t> dpck = MikeySakkeCrypto::DerivateDppkToDpck(o_dppkid, o_gmk);
    for (uint i=0; i<dpck.size(); i++)
        ASSERT_EQ(dpck[i], dpck_expected[i]);
}

TEST(test_vectors, from_alea_v3) {
    mikey_sakke_set_log_func(stw_log);
    mikey_sakke_set_log_level("info");

    const char community[]     = "alea.com";
    OctetString   gmk_expected     = OctetString::skipws("B1C9D5B7483511820CCFD06B58EF139B");
    OctetString   gmk_id_expected  = OctetString::skipws("6dbc5e2");
    OctetString   gmk_rand_expected    = OctetString::skipws("B97600F1EE9B6CAA2D1FCA9B66F66E47");
    OctetString   gmk_guk_id_expected  = OctetString::skipws("c340888");
    OctetString   csk_expected     = OctetString::skipws("2F19A7E4F466E7BBAC1E977F47BA552B");
    OctetString   csk_id_expected  = OctetString::skipws("26147a4e");
    OctetString   csk_rand_expected    = OctetString::skipws("ACFBD9718CFFDC27DAC30F4A57BC993D");
    /*OctetString   pck_expected     = OctetString::skipws("DCBEA680510F6858E742F6CFC2ACD7D0");
    OctetString   pck_id_expected  = OctetString::skipws("1f2974e5");
    OctetString   pck_rand_expected    = OctetString::skipws("F16C57D1103E350D91BA9E27D1025188");*/
    const char kms_uri[]       = "sip:common_kms.test.org";
    uint32_t   user_key_period = 914544000;
    uint32_t   user_key_offset = 0;
    const uint32_t key_period_no = 4;
    int init_format = 2;
    const char alice_uri[] = "sip:u1alea@veronica-cluster";
    const char bob_uri[] = "sip:u2alea@veronica-cluster";
    const char gms_uri[] = "sip:gms.test.org";
    const char gms2_uri[] = "sip:mcptt-participant.test.org";
    std::string imsg_gmk = "mikey ARoFAQw0CIgAAQsA7IUj1QAAAAAOELl2APHum2yqLR/Km2b2bkcOCAEAIMTr1KEFobeIpW5JWS29vl+ARA1rE13R+u1opiVgzNPMDgkBACBMNs4cNXp7mRBXBdcRvA/C0STFePeSOQX9Da6zpQSv5w4GAQAXc2lwOmNvbW1vbl9rbXMudGVzdC5vcmcKBwEAF3NpcDpjb21tb25fa21zLnRlc3Qub3JnFQEAAB4AAQYBARACAQQEAQwFAQAGAQANAQESAQQTAQAUARAaBwBmQABo2qVVAAAAAAABiCh/xsrYCM8FunElmXEoAgw0CIgAAENMWs1VitS8i5o1o9FLi4XPfMTJmCpt5SEBurW4KbfGsKbMIrVJtaSRCDzdJIexE0wfMKoaVVDOuap6yMpZ8YvtU4SpBAECAREEWvlHE823nyyJ5u7OxtSNpwFUZRTdG9LBwd4fNdwTYe+yELCsp8ou45yfp/VtN0pHB2mHv9guRyLZNUia7prEJaSNknE/mUnKinSBMvHm9ooH3MqdKLFEtuA1SqrBfhXX9nfDcc2LCOSIRyL8wbhez1x852XGmtwnrHpEXVYqQ8IYPjLJuWlKTCKVog02nNdDrTrv2o/m4EWh2SGDE/7rRevhG0tBUN8MCVPN5CeGJJ/w/j9K6slAAdPo1R+LNjxKPEX5Y8YLywok3CECD2BRHNfAnV/Qs4ZQxE/D9bNfFnZwkn3C0qHq2TaJFhapiw9jn8u1N2m3wBSmPz/LpWIy7TosmyzFJx6us4SaN6kDvZkggQtL9DeXTr1ln0ekTMRFCKC34XxSJyksndGBpnulq7kTqzdfplqZ76EHIdTGU9FLJe6ULOjLhfUQNosN/xxURRUEYYR0bqcEKTpuRIxvyyfsZ+X+HX7Xa+2OP4E5lLfJt/Xsc6itFaxjZQCuKoBC26vlXQ2yhsD9D8wQXMGiFlPPew==";
    std::string imsg_csk = "mikey ARoFASYUek4AAQsA7IUUaQAAAAAOEKz72XGM/9wn2sMPSle8mT0OCAEAIEw2zhw1enuZEFcF1xG8D8LRJMV495I5Bf0NrrOlBK/nDgkBACDa5AhlQJe/RXZHRF1wAGuVDTwioHCwT+Hm+Fc7b+ApvQ4GAQAXc2lwOmNvbW1vbl9rbXMudGVzdC5vcmcKBwEAF3NpcDpjb21tb25fa21zLnRlc3Qub3JnGgEAABIAAQYBARAEAQwFAQAGAQAUARAEAQIBEQQj9ElMoNE32SzEbDxjQts8aurQLzoHUrfB1F2+pmFC8iofViF/qnHb+42YciAfGOcrsiCm4fmoLr1FlUVpzjpXB9/+JUuAECUTvneXoBs9O+iZrBBdxMvCPY1EZOY4H3uxyurLoS4ZiIHPsarcpuFcQ/RnGnInf91wc310yvceWF9/X0NvlqmC5zYoxEWJxwbP9JvoXeV5O/Budm4DhkcwZj6jP3fQFfwChmrCarToTgmTNsUdwBkFwyG/GIu+2cYaX0W7c9Dcc/MrxKUjLy5S6V7Mv7MCr2wO5mTYD1AUnx58wB8c7aQpKrz9PWLDfGutxaoe19t6LnWN5UxggUG8Tk59gD/YV+Vnaz5uMdFfSyCBaRKOrolV45m7jQoEa3+OyGIvAbdLv5sDmN5/ZhSdnFtgfGMLPQ2Sfi3ExHjGiE5NtchVL5mXivz8DS2ouILyKwT1Hxo6FO6tAFOa0NEWwyPzZjwPfIuY0HYdzYYdcI5Iu/d1DTu41KZh7B1XUc7XMGh8NouZGe6eLTVWeTNRdRiK";
    //std::string imsg_pck = "mikey ARoFAR8pdOUAAgsA7H+n+gAAAAAOEPFsV9EQPjUNkbqeJ9ECUYgOCAEAIEw2zhw1enuZEFcF1xG8D8LRJMV495I5Bf0NrrOlBK/nDgkBACDsJZDK022McbZ1yD6E9Kbjoc8QW/ZBqJK8rNgq1HqIPQ4GAQAXc2lwOmNvbW1vbl9rbXMudGVzdC5vcmcKBwEAF3NpcDpjb21tb25fa21zLnRlc3Qub3JnGgEAABIAAQYBARAEAQwFAQAGAQAUARAEAQIBEQSIvoAG5jNNn6sqZUBN0XoLGPaMBWX4Wy37rEZyUyrurL3167XYzZtwzVz2ibwIlvkJbLgyn2S8whP1guYWp/+0XTDJay0cKmz4Q4jS1sUoZgZTBcGFVjWGjs7OAu6tpwwBrwYIwCsJpPJAgDkROnh19PRNLcSN1ql4SklK9y1pRX87pXai/IFn0n+VB7ygh02aN3usD8icd5jgJlNmFirk228u5va88QBwVSqjDKPhf3ee8v1aj8fhn7S3J7FXeqfKptnGz1CsUPja4QMZ7iALaHf8CvXT9JT857atY015DB546skWBjmhgT3SJW/NV6PGwFbXL/ae/wmGNGLDW4F8x0LI90kq7JkIBVC7cUsAQCCBY8MEvDg4CZ3e/bO2u8bDXtmNoJG7D18rsd3cfnFlScUJRtavqpACGr/3pO5CV6BXAFXQ5K4cKVS/sUD55odEPQQDIZstkDt4g2FP1nNpGS0hf4ZCc3nonG+1ngu0NduqOE8ib7F1eROOwkkHArgbMdwjFcneU5jIbVX2bceh0NdK";
    mikey_key_mgmt_string_t    imsg;

    Mikey mikey;
    mikey.displayIMessageInfo(imsg_gmk);
    mikey.displayIMessageInfo(imsg_csk);
    //mikey.displayIMessageInfo(imsg_pck);

    // Key retrieval from KMS
    mikey_sakke_key_material_t* gms_keys    = mikey_sakke_alloc_key_material("runtime:empty");
    mikey_sakke_key_material_t* gms2_keys    = mikey_sakke_alloc_key_material("runtime:empty");
    mikey_sakke_key_material_t* alice_keys  = mikey_sakke_alloc_key_material("runtime:empty");
    mikey_sakke_key_material_t* bob_keys    = mikey_sakke_alloc_key_material("runtime:empty");

    OctetString init_z = OctetString::skipws("040BADC7C87A5819200BEC1005010ABC38062C285ABB0A93E6D213BBBB59F6D6DED17CBF58A1A67BE8C80A55E087BD5FD5178E9586E9A9C6DF0B34C06F16C0FD0375F98A4ECA2AECDD17D7CEBE8468812F731F520C89CB45785AB973E42A96E60AE148B8F454C06CB8317FA6992B57B5CCDCC615F7325900DDF2260A807ED0A2F215C02A3385AA53A5914C1CD177293D25AC0003D55F90B105ADAED81B5A1F9CEF2C9AE6817A98291B74C221C486575706EF08D06456538C52A6F6E49568CE4693B6F49256683219EF56887E06359ABCDFDA1E315711345ABB6E8C246B0DCEC817EB7EEAA3402E57CCACB349821AE42AD39D3E341786501EF338F07A5E2A114256");
    OctetString init_kpak = OctetString::skipws("044C6FB7827E0F9EE7555A547DAFEE9B2825C9A4BBC688FF6A64DBE9E126F15AE45113F12C96E435B211CC5986AB2F2AF47D140623FFDDACFA8A3DCDCFA8E80C49");

    OctetString gms_id = OctetString::skipws("C4EBD4A105A1B788A56E49592DBDBE5F80440D6B135DD1FAED68A62560CCD3CC");
    OctetString gms_decryptkey = OctetString::skipws("04358C9F3DE58E17C4F3D92D99E9DAEA4D083FF4ADC0E87EEF1C2B4BC3830F877B4B594F5D27DBFB1A61B40F81AAF1F174D665D850840C2EE2E0A81626ADA9B2F95FB747DFF44F018A7FD84AE99CA8FB0B5AC27F3BA55DD722B7F8DCA3D81AE8B5055AC59A366636C80A5D4B01723B7DD2E0AAA597EDE0A24C0048102DE9AB225802802C67C4A035DA64A6FF16F120D8E40D33600F0251614B324BF7898382A1B6A35A4E5DCD67750A91E1F2F3CA009D532E81BD7EE6B07540C2D48688BF8F77F255A0A24CAE318BDB8D50AD89BDC3B2727C177FCD58FEBE5D8F64688DF40B664754163187833169AE8FA6F59A7C0FB05D2CA342446BAFB4BB6D281DD0676630D3");
    OctetString gms_ssk = OctetString::skipws("44A8F56A8324F29C7055181D675FC9E99341AC2B82F27C2C905A8C8353E1ACC5");
    OctetString gms_pvt = OctetString::skipws("046184746EA704293A6E448C6FCB27EC67E5FE1D7ED76BED8E3F813994B7C9B7F5EC73A8AD15AC636500AE2A8042DBABE55D0DB286C0FD0FCC105CC1A21653CF7B");

    OctetString gms2_id = OctetString::skipws("DAE408654097BF457647445D70006B950D3C22A070B04FE1E6F8573B6FE029BD");
    OctetString gms2_decryptkey = OctetString::skipws("040DB6D193D05D3CAD963FFB94BBC13D40A4888EFFE72E4944BE1C93312C9300E0BC066F08480C56D32006B886A44738FC066F6EFD65515FE67A181F2F159291B4DEFA6556ED72F9D271D5F13952711AAA6BD58619575A94403ADC58F7D7212B06E1810EFC8B104577930D207F48FE0CA869841B84E7691F2EF0B8ECCC3F407ABD017777B65F50DE1EC778B8809B0C9C6A9AC061669E8253C011044494B0946ED35948BF529465C164475B1C3DFC29580B90570740698043855A97EAA83972DD16FE8A39BDD07F39C6A096BED9EA487509556D9B965733D7FC1DB37106B2714FB38CA97164F8D5A4DA23B063CA0CD04E8A55453461EEEA6EEE56DAF3288E30A981");
    OctetString gms2_ssk = OctetString::skipws("9CE38CBA26492F4EDD92B622F351BE7913C9B8CF13E06D7D88A9518C3D75F432");
    OctetString gms2_pvt = OctetString::skipws("04DB85AB90614102772762331BE3B00B165A7D548766EAA407E016995DCBF300351EF30883287C3E670139E7871A46073BEDA6A8B8031B5218616BB614BDBD676C");

    OctetString alice_id = OctetString::skipws("4C36CE1C357A7B99105705D711BC0FC2D124C578F7923905FD0DAEB3A504AFE7");
    OctetString alice_decryptkey = OctetString::skipws("0446464B28B6473149BE4F92192C396A23F6D3C5129261D923C82192C58E6A0D63AD30A5C8E317519724B5D90F9F2495CD4FD04E4541F79B3582BD74888BA4F8D09D52A1BEA2DF611BF365FD64A265FE4BC457B0AAE45AB604B5A9FC18A45A5A0897E5668CE686A2190FC5BC0B9C46DF85B252E02DEC936E27D3960B8F71B8EE8F2E499EC641F593A61772E608094DB4661F4FCCFAFF16F0B64C5565AD3B20CFE6BD23DFB6D904822D05A2E0EAA75498BDDCCC1F9F91A2519890EA583390208BCEBC2AC5491633BBD195CF574DBAC5E5EC607CFFB181F8323E8F636C34DA94F584D93F9EA6E6F2C8364C562D952DB804B20506ECDAF426EF0755F2E5624C3AA5B6");
    OctetString alice_ssk = OctetString::skipws("0FC28ACB499D29969EEE9388778F3435A933CF2952AB93B48407D5D574EAFCAA");
    OctetString alice_pvt = OctetString::skipws("04F51F1A3A14EEAD00539AD0D116C323F3663C0F7C8B98D0761DCD861D708E48BBF7750D3BB8D4A661EC1D5751CED730687C368B9919EE9E2D355679335175188A");

    OctetString bob_id = OctetString::skipws("EC2590CAD36D8C71B675C83E84F4A6E3A1CF105BF641A892BCACD82AD47A883D");
    OctetString bob_decryptkey = OctetString::skipws("0428BCC7CCF751052C9BF5A2B410315F17B62EA04CB0D85238C5BD95E270A404CB365B8B952575C34E41B82178A50077E463376CD7D424432EA654213A806B4C0B89797B88319AE4295ACE7CFBA1134D557E85DBDCD5044F69FFCA975649F0C012F2EDB41D6133D2EE51FDA3793D4BF32A27A31A198F5362CD84F9A71E53C753932B3E54C40FCC721A7570152C98CE439B6D6AE0E4AF8BDFFDF25EB0F97D1259908B22359A841ED8B23BCAB3EBBFC2EA2A59B800A79A07980C61B33FF79EC6D427908EE4F1DB471BDFB3B2F7748DA883E9E35E84513FB75D3142F5F8AC907A284370BB88C5DAB3C263653A3FDB4BA8C03306A5AD6C72EF15A3A5FF63A6C41666DC");
    OctetString bob_ssk = OctetString::skipws("063F34CFCE609DC110F001203D4BF62C9C0AD4626E4CCCBB293A0393B29640B9");
    OctetString bob_pvt = OctetString::skipws("04F51F1A3A14EEAD00539AD0D116C323F3663C0F7C8B98D0761DCD861D708E48BBF7750D3BB8D4A661EC1D5751CED730687C368B9919EE9E2D355679335175188A");

    const char* gms_id_test     = mikey_sakke_gen_user_id_format_2_for_period(gms_uri, kms_uri, user_key_period, user_key_offset, key_period_no);
    const char* gms2_id_test    = mikey_sakke_gen_user_id_format_2_for_period(gms2_uri, kms_uri, user_key_period, user_key_offset, key_period_no);
    const char* alice_id_test   = mikey_sakke_gen_user_id_format_2_for_period(alice_uri, kms_uri, user_key_period, user_key_offset, key_period_no);
    const char* bob_id_test     = mikey_sakke_gen_user_id_format_2_for_period(bob_uri, kms_uri, user_key_period, user_key_offset, key_period_no);

    MIKEY_SAKKE_LOGD("Check MIKEY_SAKKE_UID for alice: %s/%s", alice_id.translate().c_str(), alice_id_test);
    ASSERT_EQ(memcmp(gms_id.translate().c_str(), gms_id_test, strlen(gms_id_test)), 0);
    ASSERT_EQ(memcmp(gms2_id.translate().c_str(), gms2_id_test, strlen(gms2_id_test)), 0);
    ASSERT_EQ(memcmp(alice_id.translate().c_str(), alice_id_test, strlen(alice_id_test)), 0);
    ASSERT_EQ(memcmp(bob_id.translate().c_str(), bob_id_test, strlen(bob_id_test)), 0);

    mikey_sakke_add_community(gms_keys, community);
    mikey_sakke_add_community(gms2_keys, community);
    mikey_sakke_add_community(alice_keys, community);
    mikey_sakke_add_community(bob_keys, community);

    // clang-format off
    mikey_sakke_provision_key_material(gms_keys, community, "KPAK", init_kpak.translate().c_str(), false);
    mikey_sakke_provision_key_material(gms_keys, community, "Z", init_z.translate().c_str(), false);
    mikey_sakke_provision_key_material(gms_keys, gms_id.translate().c_str(), "RSK", gms_decryptkey.translate().c_str(), true);
    mikey_sakke_provision_key_material(gms_keys, gms_id.translate().c_str(), "SSK", gms_ssk.translate().c_str(), true);
    mikey_sakke_provision_key_material(gms_keys, gms_id.translate().c_str(), "PVT", gms_pvt.translate().c_str(), false);
    mikey_sakke_provision_key_material(gms2_keys, community, "KPAK", init_kpak.translate().c_str(), false);
    mikey_sakke_provision_key_material(gms2_keys, community, "Z", init_z.translate().c_str(), false);
    mikey_sakke_provision_key_material(gms2_keys, gms2_id.translate().c_str(), "RSK", gms2_decryptkey.translate().c_str(), true);
    mikey_sakke_provision_key_material(gms2_keys, gms2_id.translate().c_str(), "SSK", gms2_ssk.translate().c_str(), true);
    mikey_sakke_provision_key_material(gms2_keys, gms2_id.translate().c_str(), "PVT", gms2_pvt.translate().c_str(), false);
    mikey_sakke_provision_key_material(alice_keys, community, "KPAK", init_kpak.translate().c_str(), false);
    mikey_sakke_provision_key_material(alice_keys, community, "Z", init_z.translate().c_str(), false);
    mikey_sakke_provision_key_material(alice_keys, alice_id.translate().c_str(), "RSK", alice_decryptkey.translate().c_str(), true);
    mikey_sakke_provision_key_material(alice_keys, alice_id.translate().c_str(), "SSK", alice_ssk.translate().c_str(), true);
    mikey_sakke_provision_key_material(alice_keys, alice_id.translate().c_str(), "PVT", alice_pvt.translate().c_str(), false);
    mikey_sakke_provision_key_material(bob_keys, community, "KPAK", init_kpak.translate().c_str(), false);
    mikey_sakke_provision_key_material(bob_keys, community, "Z", init_z.translate().c_str(), false);
    mikey_sakke_provision_key_material(bob_keys, bob_id.translate().c_str(), "RSK", bob_decryptkey.translate().c_str(), true);
    mikey_sakke_provision_key_material(bob_keys, bob_id.translate().c_str(), "SSK", bob_ssk.translate().c_str(), true);
    mikey_sakke_provision_key_material(bob_keys, bob_id.translate().c_str(), "PVT", bob_pvt.translate().c_str(), false);
    // clang-format on

    ASSERT_TRUE(mikey_sakke_validate_signing_keys(gms_id.translate().c_str(), gms_keys));
    ASSERT_TRUE(mikey_sakke_validate_signing_keys(gms2_id.translate().c_str(), gms2_keys));
    ASSERT_TRUE(mikey_sakke_validate_signing_keys(alice_id.translate().c_str(), alice_keys));
    //ASSERT_TRUE(mikey_sakke_validate_signing_keys(bob_id.translate().c_str(), bob_keys));

    mikey_sakke_set_public_parameter(gms_keys, community, "UserKeyPeriod", libmutil::itoa(user_key_period).c_str());
    mikey_sakke_set_public_parameter(gms_keys, community, "UserKeyOffset", libmutil::itoa(user_key_offset).c_str());
    mikey_sakke_set_public_parameter(gms_keys, community, "UserKeyPeriodNoSet", libmutil::itoa(key_period_no).c_str());
    mikey_sakke_set_public_parameter(gms_keys, community, "KmsUri", kms_uri);
    mikey_sakke_set_public_parameter(gms_keys, community, "SakkeSet", "1");
    mikey_sakke_set_public_parameter(gms2_keys, community, "UserKeyPeriod", libmutil::itoa(user_key_period).c_str());
    mikey_sakke_set_public_parameter(gms2_keys, community, "UserKeyOffset", libmutil::itoa(user_key_offset).c_str());
    mikey_sakke_set_public_parameter(gms2_keys, community, "UserKeyPeriodNoSet", libmutil::itoa(key_period_no).c_str());
    mikey_sakke_set_public_parameter(gms2_keys, community, "KmsUri", kms_uri);
    mikey_sakke_set_public_parameter(gms2_keys, community, "SakkeSet", "1");
    mikey_sakke_set_public_parameter(alice_keys, community, "UserKeyPeriod", libmutil::itoa(user_key_period).c_str());
    mikey_sakke_set_public_parameter(alice_keys, community, "UserKeyOffset", libmutil::itoa(user_key_offset).c_str());
    mikey_sakke_set_public_parameter(alice_keys, community, "UserKeyPeriodNoSet", libmutil::itoa(key_period_no).c_str());
    mikey_sakke_set_public_parameter(alice_keys, community, "KmsUri", kms_uri);
    mikey_sakke_set_public_parameter(alice_keys, community, "SakkeSet", "1");
    mikey_sakke_set_public_parameter(bob_keys, community, "UserKeyPeriod", libmutil::itoa(user_key_period).c_str());
    mikey_sakke_set_public_parameter(bob_keys, community, "UserKeyOffset", libmutil::itoa(user_key_offset).c_str());
    mikey_sakke_set_public_parameter(bob_keys, community, "UserKeyPeriodNoSet", libmutil::itoa(key_period_no).c_str());
    mikey_sakke_set_public_parameter(bob_keys, community, "KmsUri", kms_uri);
    mikey_sakke_set_public_parameter(bob_keys, community, "SakkeSet", "1");

    // Prepare
    mikey_sakke_user_t* gms2    = mikey_sakke_alloc_user(gms2_uri, gms2_keys);
    mikey_sakke_user_t* alice   = mikey_sakke_alloc_user(alice_uri, alice_keys);
    mikey_sakke_user_t* bob     = mikey_sakke_alloc_user(bob_uri, bob_keys);

    mikey_sakke_set_payload_signature_validation(gms2, false);
    mikey_sakke_set_payload_signature_validation(alice, false);
    mikey_sakke_set_payload_signature_validation(bob, false);


    // Test 1: GMK I-MESSAGE for alice from gms
    imsg.ptr = imsg_gmk.data();
    imsg.len = imsg_gmk.size();
    mikey_sakke_call_t* alice_incoming = mikey_sakke_alloc_call(alice);
    mikey_sakke_add_sender_stream(alice_incoming, 0xdeadbeef);
    bool gmk_authent = mikey_sakke_uas_auth(alice_incoming, imsg, gms_uri, nullptr);
    ASSERT_TRUE(gmk_authent);
    ASSERT_TRUE(mikey_sakke_call_is_secured(alice_incoming));
    struct mikey_sakke_key_data* alice_gmk = mikey_sakke_get_key_data(alice_incoming);
    ASSERT_EQ(alice_gmk->key_size, gmk_expected.size());
    ASSERT_EQ(alice_gmk->key_id_size, gmk_id_expected.size());
    ASSERT_EQ(alice_gmk->rand_size, gmk_rand_expected.size());
    ASSERT_EQ(memcmp(alice_gmk->key, gmk_expected.raw(), gmk_expected.size()), 0);
    ASSERT_EQ(memcmp(alice_gmk->key_id, gmk_id_expected.raw(), gmk_id_expected.size()), 0);
    ASSERT_EQ(memcmp(alice_gmk->rand, gmk_rand_expected.raw(), gmk_rand_expected.size()), 0);
    ASSERT_EQ(memcmp(alice_gmk->csb_id, gmk_guk_id_expected.raw(), gmk_guk_id_expected.size()), 0);

    // Test 2: CSK I-MESSAGE for gms2 from alice
    imsg.ptr = imsg_csk.data();
    imsg.len = imsg_csk.size();
    mikey_sakke_call_t* gms2_incoming = mikey_sakke_alloc_call(gms2);
    mikey_sakke_add_sender_stream(gms2_incoming, 0xdeadbeef);
    bool csk_authent = mikey_sakke_uas_auth(gms2_incoming, imsg, alice_uri, nullptr);
    ASSERT_TRUE(csk_authent);
    ASSERT_TRUE(mikey_sakke_call_is_secured(gms2_incoming));
    struct mikey_sakke_key_data* gms2_csk = mikey_sakke_get_key_data(gms2_incoming);
    ASSERT_EQ(gms2_csk->key_size, csk_expected.size());
    ASSERT_EQ(gms2_csk->key_id_size, csk_id_expected.size());
    ASSERT_EQ(gms2_csk->rand_size, csk_rand_expected.size());
    OctetString csk = OctetString{gms2_csk->key_size, gms2_csk->key};
    OctetString csk_id = OctetString{gms2_csk->key_id_size, gms2_csk->key_id};
    MIKEY_SAKKE_LOGI("Extracted CSK & ID: %s/%s", csk.translate().c_str(), csk_id.translate().c_str());
    //ASSERT_EQ(memcmp(gms2_csk->key, csk_expected.raw(), csk_expected.size()), 0);
    ASSERT_EQ(memcmp(gms2_csk->key_id, csk_id_expected.raw(), csk_id_expected.size()), 0);
    //ASSERT_EQ(memcmp(gms2_csk->rand, csk_rand_expected.raw(), csk_rand_expected.size()), 0);

    // Test 3: PCK I-MESSAGE for bob from alice
    /*imsg.ptr = imsg_pck.data();
    imsg.len = imsg_pck.size();
    mikey_sakke_call_t* bob_incoming = mikey_sakke_alloc_call(bob);
    mikey_sakke_add_sender_stream(bob_incoming, 0xdeadbeef);
    bool pck_authent = mikey_sakke_uas_auth(bob_incoming, imsg, alice_uri, nullptr);
    ASSERT_TRUE(pck_authent);
    ASSERT_TRUE(mikey_sakke_call_is_secured(bob_incoming));
    struct mikey_sakke_key_data* bob_pck = mikey_sakke_get_key_data(bob_incoming);
    ASSERT_EQ(bob_pck->key_size, pck_expected.size());
    ASSERT_EQ(bob_pck->key_id_size, pck_id_expected.size());
    ASSERT_EQ(bob_pck->rand_size, pck_rand_expected.size());
    OctetString pck = OctetString{bob_pck->key_size, bob_pck->key};
    OctetString pck_id = OctetString{bob_pck->key_id_size, bob_pck->key_id};
    MIKEY_SAKKE_LOGI("Extracted PCK & ID: %s/%s", pck.translate().c_str(), pck_id.translate().c_str());
    ASSERT_EQ(memcmp(bob_pck->key, pck_expected.raw(), pck_expected.size()), 0);
    ASSERT_EQ(memcmp(bob_pck->key_id, pck_id_expected.raw(), pck_id_expected.size()), 0);
    ASSERT_EQ(memcmp(bob_pck->rand, pck_rand_expected.raw(), pck_rand_expected.size()), 0);*/

    free((void*)gms_id_test);
    free((void*)gms2_id_test);
    free((void*)alice_id_test);
    free((void*)bob_id_test);
    mikey_sakke_free_call(gms2_incoming);
    mikey_sakke_free_call(alice_incoming);
    //mikey_sakke_free_call(bob_incoming);
    mikey_sakke_free_user(gms2);
    mikey_sakke_free_user(alice);
    mikey_sakke_free_user(bob);
    mikey_sakke_free_key_material(gms_keys);
    mikey_sakke_free_key_material(gms2_keys);
    mikey_sakke_free_key_material(alice_keys);
    mikey_sakke_free_key_material(bob_keys);
    mikey_sakke_key_data_destroy(alice_gmk);
    mikey_sakke_key_data_destroy(gms2_csk);
    //mikey_sakke_key_data_destroy(bob_pck);
}

TEST(test_vectors, streamwide_official_reference) {
    mikey_sakke_set_log_func(stw_log);
    mikey_sakke_set_log_level("info");
    uint8_t*   gmk             = mikey_sakke_gen_key(16);
    uint8_t*   gmk_id          = mikey_sakke_gen_key_id(GMK);
    uint8_t*   csk             = mikey_sakke_gen_key(16);
    uint8_t*   csk_id          = mikey_sakke_gen_key_id(CSK);
    uint8_t*   pck             = mikey_sakke_gen_key(16);
    uint8_t*   pck_id          = mikey_sakke_gen_key_id(PCK);
    const char kms_uri[]       = "kms.mydev.streamwide.com";
    const char gms_uri[]       = "gms@streamwide.com";
    const char alice_uri[]     = "sip:alice@streamwide.com";
    const char bob_uri[]       = "sip:bob@streamwide.com";
    const char iwf_uri[]       = "sip:iwf_legacy_v1.1.x_format@streamwide.com";

    auto o_gmk    = OctetString {16, gmk};
    auto o_gmk_id = OctetString {4, gmk_id};
    auto o_csk    = OctetString {16, csk};
    auto o_csk_id = OctetString {4, csk_id};
    auto o_pck    = OctetString {16, pck};
    auto o_pck_id = OctetString {4, pck_id};

    // Key retrieval from KMS
    mikey_sakke_key_material_t* gms_keys    = mikey_sakke_alloc_key_material("runtime:empty");
    mikey_sakke_key_material_t* alice_keys  = mikey_sakke_alloc_key_material("runtime:empty");
    mikey_sakke_key_material_t* bob_keys    = mikey_sakke_alloc_key_material("runtime:empty");
    mikey_sakke_key_material_t* iwf_keys    = mikey_sakke_alloc_key_material("runtime:empty");

    int init_format = 2;
    uint32_t   user_key_period = 16777215;
    uint32_t   user_key_offset = 0;
    const uint32_t key_period_no = 236;

    OctetString init_z = OctetString::skipws("046fc2cf00fd48467abe7c02f383002fc49b6632bf0f7071d958f1f128154e6fae1f69bb91691a191a358fe647a3e020d2365d52f81fb3af4ea271654f1a880274c1ae228ac72cc15d535394321bd2143cea2619fb3b0c6ce7a5f72714d8ef4d11cb0c991c3376ca31b168b01e66021effdbf7920bd66615e6f0d6a1e61c06e72e61b4138738c11bc249a3849e9c4cff327a7d0d2769c3d97a37f86adfb13baa257e628ce236f40360d3f7b8d95b0e3fcc19417602d7d6b8928b855eae9129be1f0b87d33e884906dd95a04a8bd61240bad60f9dfada64806726f8f08b86343f54046416f5198116e9798c218bcf9ca07d0baa4be50062bfe54e44495b6ed59cb6");
    OctetString init_kpak = OctetString::skipws("0448f9c2c48b50735f6bc70ec6691073243f1e0bd83cc73bb936d61ffcb2d6049a5b297e8205b29fbd8591cb582d6402add21451ce4beebeaaa7520e93b11cf28f");

    OctetString gms_id = OctetString::skipws("15a4d5b12856538d02d91fedbb766e6dd377b014c92e216666c8fb678608d20e");
    OctetString gms_decryptkey = OctetString::skipws("043f591611206a0913ecb68ab28e086ac1148fbd5ce4a40bf00a186653ecf6f0055f4f1b5ef8a4b527d33dd28c731c7b2829d6329283533d499b04c31e2d30437919f486ef76c8a6cbca2f279724539e52b3a1760077670fc35756a9417625d57876717811bd3f1fb8fb473b547ba874a8f5d747cd63b2ebcdb150f5b454a46ec2512a86f0672439d3121a0eddf5995f18e1c77e3423ea34427b62281977e3afb9b5c8766c5a32e1f9b29f0bb12d46a03f8f3ec7357e59f969473bcf4d4cdc3cdedb6e7982e6477117a3c02d86165896485323c96f53a330e5e995ce83b23127542f2177916d5007a5aa116680093911d4bc587cd94e2bdec36d7290ed4f2d3998");
    OctetString gms_ssk = OctetString::skipws("2e7237faa18a874b88d955199dea974b7d0fefcbbae1946baf659b26a4d05a5e");
    OctetString gms_pvt = OctetString::skipws("0468a24d49b184d7008d22f63a415debd38bfa9295f066fa6ada5951c2322d2eca1d6f1d994f22710daef776d9c54d9a338f32395080d6f2bdffb6c7895f12cda2");

    OctetString alice_id = OctetString::skipws("b5c452309219da6a3d805615548d6c1b0f4de45a6b48fb13d9a24d857fc03dc4");
    OctetString alice_decryptkey = OctetString::skipws("0428b44cd6dffd2e7fe73521a5c514738287df177c1ae841ba6f5d72601b9c6bc5509c3fd800ac1fee833dd81c74ab39d2740a10fba25cd9b0debb25a3da958cf52e35e863d2db37ea22b318d23d9911d36f585eb110e430123f3cd84d2692a4013bc7f59533e5da2083d8e6e8b96764eb8e8be599dc2361e7428460b8490200417baa5bac10efaa5262301b3110f6da9e8bc9c4b62827c3d4f4070a8e341346a326a23f219d2a99298036615956bb85a60cf303d15d469c1ee837c29cba5dccb28d74e4ba0d83dac9400d72eecb1817cc60127203f1321e82b7a24f60c07f1804a9895cbb455a94694a5ef627b1c631760295dad53f0eed1714ba52d5a932bddd");
    OctetString alice_ssk = OctetString::skipws("a1be54a56c7905c06abd2be177fc0c137a32278c9067550b0f0d93fb630d2428");
    OctetString alice_pvt = OctetString::skipws("0426cd8b0a33af9b381ee53ebc6841aed5c1c98fb0d2beb9c7ff98d7c79808d1f566659f6b735016192dd9984df56e54f3f95c76ac4638c1f3d3228f3c752c8cc8");

    OctetString bob_id = OctetString::skipws("780851cda91a9c33f941cd3a2831697e2893264754e363f8a0cef827eb201a81");
    OctetString bob_decryptkey = OctetString::skipws("04421d385f108bd51f66abbce40b899efe187dbb08085d9a535fca8766677db317812e48da407235d73399d4d2e2ed4f5a35d7694b64595ce0599e4d3592f5b57ede83890fd798aec2cd96f333d6139d9f7ecfecbb79b769f5fbbc6825beeb25999acdf6fb2edd369176f45db0caf5909aa81512e57064c46ae1c23df9284ffba55741cde0b7a8145fdbea76b4ee243d79bd70db4300c55570f342ca0df98e8f3b410e1df4ccbdd279403d3da06cad4c5db8d4e078a191a7a0545391e8ca72e51c793448c4ba8be71fbac90a84ded3d6127c4d7438a3132f354b283d65da75a5070ecd96f02d694c505efcb05caf2290bf15ee45c15a0e652496b88acbaf1d26a3");
    OctetString bob_ssk = OctetString::skipws("a36885736f21b6ceba48448093086f4ada1ce099bd77e3047c04529ac3f4d4eb");
    OctetString bob_pvt = OctetString::skipws("049c203fda536ae9481eb7f3a1e4662d0adaa6a3b7d3fff0c2dfadd148a754af424d434253b62dcd08eb6aedb6cd091e09f8539d41d3ef2d0ce07e8ead352f2dd9");

    OctetString iwf_id = OctetString::skipws("edb3cd733168a81106e366c2ddc0e4bc323e9069d48edfe2b3b0f7033bae962a");
    OctetString iwf_decryptkey = OctetString::skipws("0424b74f88f8fb0cc7b1fa8b48ef1cd676ac776a3dc98d41c7e334308a7068906d44eb13ea49c472b8835685a4151a2705fb78e0371ff351d7ed38de0977ca10ad23c91a569010718f0498daa45f46d8c57e40d96081b839d59c0a1ce06a5044f53ec9b379e730da0605cafcb922b018023c463478d63298bad759dbcae40e8120703f7badd9e5635a22e2a95d7fa94455225065d1d417b3eba279a77882d50425336ed8c5529c608e1777dbad5da9cb23d2fdc5ff0225b1c2237463ac107d9a9f3160e2e4b0e6601fa7609fe28640d8b03cdda21411370a5610758436ab98793caef1391ff7eaa01ee15e4893d72c648eba206d17199cf416e56e09e7bca3ae3d");
    OctetString iwf_ssk = OctetString::skipws("ed3162edf45f6e6f0f0939a02c84795c2ab78f714c91fe0254ca0f48eacf6a20");
    OctetString iwf_pvt = OctetString::skipws("0411d4c57e7b945588148a55f9e88bd1d62017f4fab600af6bf4dcdb05e6f75e9441e20f7a9e2371ebb34692b941270b52744d1699538b41a4cdf043101e23449d");

    mikey_sakke_add_community(gms_keys, community);
    mikey_sakke_add_community(alice_keys, community);
    mikey_sakke_add_community(bob_keys, community);
    mikey_sakke_add_community(iwf_keys, community);

    // clang-format off
    mikey_sakke_provision_key_material(gms_keys, community, "KPAK", init_kpak.translate().c_str(), false);
    mikey_sakke_provision_key_material(gms_keys, community, "Z", init_z.translate().c_str(), false);
    mikey_sakke_provision_key_material(gms_keys, gms_id.translate().c_str(), "RSK", gms_decryptkey.translate().c_str(), true);
    mikey_sakke_provision_key_material(gms_keys, gms_id.translate().c_str(), "SSK", gms_ssk.translate().c_str(), true);
    mikey_sakke_provision_key_material(gms_keys, gms_id.translate().c_str(), "PVT", gms_pvt.translate().c_str(), false);
    mikey_sakke_provision_key_material(alice_keys, community, "KPAK", init_kpak.translate().c_str(), false);
    mikey_sakke_provision_key_material(alice_keys, community, "Z", init_z.translate().c_str(), false);
    mikey_sakke_provision_key_material(alice_keys, alice_id.translate().c_str(), "RSK", alice_decryptkey.translate().c_str(), true);
    mikey_sakke_provision_key_material(alice_keys, alice_id.translate().c_str(), "SSK", alice_ssk.translate().c_str(), true);
    mikey_sakke_provision_key_material(alice_keys, alice_id.translate().c_str(), "PVT", alice_pvt.translate().c_str(), false);
    mikey_sakke_provision_key_material(bob_keys, community, "KPAK", init_kpak.translate().c_str(), false);
    mikey_sakke_provision_key_material(bob_keys, community, "Z", init_z.translate().c_str(), false);
    mikey_sakke_provision_key_material(bob_keys, bob_id.translate().c_str(), "RSK", bob_decryptkey.translate().c_str(), true);
    mikey_sakke_provision_key_material(bob_keys, bob_id.translate().c_str(), "SSK", bob_ssk.translate().c_str(), true);
    mikey_sakke_provision_key_material(bob_keys, bob_id.translate().c_str(), "PVT", bob_pvt.translate().c_str(), false);
    mikey_sakke_provision_key_material(iwf_keys, community, "KPAK", init_kpak.translate().c_str(), false);
    mikey_sakke_provision_key_material(iwf_keys, community, "Z", init_z.translate().c_str(), false);
    mikey_sakke_provision_key_material(iwf_keys, iwf_id.translate().c_str(), "RSK", iwf_decryptkey.translate().c_str(), true);
    mikey_sakke_provision_key_material(iwf_keys, iwf_id.translate().c_str(), "SSK", iwf_ssk.translate().c_str(), true);
    mikey_sakke_provision_key_material(iwf_keys, iwf_id.translate().c_str(), "PVT", iwf_pvt.translate().c_str(), false);
    // clang-format on

    ASSERT_TRUE(mikey_sakke_validate_signing_keys(gms_id.translate().c_str(), gms_keys));
    ASSERT_TRUE(mikey_sakke_validate_signing_keys(alice_id.translate().c_str(), alice_keys));
    ASSERT_TRUE(mikey_sakke_validate_signing_keys(bob_id.translate().c_str(), bob_keys));
    ASSERT_TRUE(mikey_sakke_validate_signing_keys(iwf_id.translate().c_str(), iwf_keys));

    mikey_sakke_set_public_parameter(gms_keys, community, "UserKeyPeriod", libmutil::itoa(user_key_period).c_str());
    mikey_sakke_set_public_parameter(gms_keys, community, "UserKeyOffset", libmutil::itoa(user_key_offset).c_str());
    mikey_sakke_set_public_parameter(gms_keys, community, "UserKeyPeriodNoSet", libmutil::itoa(key_period_no).c_str());
    mikey_sakke_set_public_parameter(gms_keys, community, "KmsUri", kms_uri);
    mikey_sakke_set_public_parameter(gms_keys, community, "SakkeSet", "1");
    mikey_sakke_set_public_parameter(alice_keys, community, "UserKeyPeriod", libmutil::itoa(user_key_period).c_str());
    mikey_sakke_set_public_parameter(alice_keys, community, "UserKeyOffset", libmutil::itoa(user_key_offset).c_str());
    mikey_sakke_set_public_parameter(alice_keys, community, "UserKeyPeriodNoSet", libmutil::itoa(key_period_no).c_str());
    mikey_sakke_set_public_parameter(alice_keys, community, "KmsUri", kms_uri);
    mikey_sakke_set_public_parameter(alice_keys, community, "SakkeSet", "1");
    mikey_sakke_set_public_parameter(bob_keys, community, "UserKeyPeriod", libmutil::itoa(user_key_period).c_str());
    mikey_sakke_set_public_parameter(bob_keys, community, "UserKeyOffset", libmutil::itoa(user_key_offset).c_str());
    mikey_sakke_set_public_parameter(bob_keys, community, "UserKeyPeriodNoSet", libmutil::itoa(key_period_no).c_str());
    mikey_sakke_set_public_parameter(bob_keys, community, "KmsUri", kms_uri);
    mikey_sakke_set_public_parameter(bob_keys, community, "SakkeSet", "1");
    mikey_sakke_set_public_parameter(iwf_keys, community, "UserKeyPeriod", libmutil::itoa(user_key_period).c_str());
    mikey_sakke_set_public_parameter(iwf_keys, community, "UserKeyOffset", libmutil::itoa(user_key_offset).c_str());
    mikey_sakke_set_public_parameter(iwf_keys, community, "UserKeyPeriodNoSet", libmutil::itoa(key_period_no).c_str());
    mikey_sakke_set_public_parameter(iwf_keys, community, "KmsUri", kms_uri);
    mikey_sakke_set_public_parameter(iwf_keys, community, "SakkeSet", "1");


    // Prepare
    mikey_sakke_user_t* gms          = mikey_sakke_alloc_user(gms_uri, gms_keys);
    mikey_sakke_call_t* gms_outgoing = mikey_sakke_alloc_call(gms);
    mikey_sakke_add_sender_stream(gms_outgoing, 0xcafebabe);
    mikey_sakke_user_t* alice          = mikey_sakke_alloc_user(alice_uri, alice_keys);
    mikey_sakke_call_t* alice_outgoing = mikey_sakke_alloc_call(alice);
    mikey_sakke_add_sender_stream(alice_outgoing, 0xcafebabe);
    mikey_sakke_user_t* bob          = mikey_sakke_alloc_user(bob_uri, bob_keys);
    mikey_sakke_call_t* bob_outgoing = mikey_sakke_alloc_call(bob);
    mikey_sakke_add_sender_stream(bob_outgoing, 0xcafebabe);
    mikey_sakke_user_t* iwf          = mikey_sakke_alloc_user(iwf_uri, iwf_keys);
    mikey_sakke_call_t* iwf_outgoing = mikey_sakke_alloc_call(iwf);
    mikey_sakke_add_sender_stream(iwf_outgoing, 0xcafebabe);

    struct key_agreement_params* params = NULL;
    // Generate GMK I_MESSAGE from GMS to alice
    params = key_agreement_params_create(GMK, 16, gmk, 4, gmk_id, 0, nullptr);
    mikey_key_mgmt_string_t      gmk_imessage     = mikey_sakke_group_init(gms_outgoing, alice_uri, params);
    key_agreement_params_delete(params);

    // Generate CSK I_MESSAGE from alice to GMS
    params = key_agreement_params_create(CSK, 16, csk, 4, csk_id, 0, nullptr);
    mikey_key_mgmt_string_t      csk_imessage     = mikey_sakke_group_init(alice_outgoing, gms_uri, params);
    key_agreement_params_delete(params);

    // Generate PCK I_MESSAGE from alice to bob
    params = key_agreement_params_create(PCK, 16, pck, 4, pck_id, 0, nullptr);
    mikey_key_mgmt_string_t      pck_imessage     = mikey_sakke_group_init(alice_outgoing, bob_uri, params);
    key_agreement_params_delete(params);

    // Generate GMK I_MESSAGE from GMS to iwf
    params = key_agreement_params_create(GMK, 16, gmk, 4, gmk_id, 0, nullptr);
    mikey_key_mgmt_string_t      gmk_iwf_imessage     = mikey_sakke_group_init(gms_outgoing, iwf_uri, params);
    key_agreement_params_delete(params);


    Mikey mikey;
    std::string gmk_str = std::string(gmk_imessage.ptr, gmk_imessage.len);
    std::string csk_str = std::string(csk_imessage.ptr, csk_imessage.len);
    std::string pck_str = std::string(pck_imessage.ptr, pck_imessage.len);
    std::string gmk_iwf_str = std::string(gmk_iwf_imessage.ptr, gmk_iwf_imessage.len);
    mikey.displayIMessageInfo(gmk_str);
    mikey.displayIMessageInfo(csk_str);
    mikey.displayIMessageInfo(pck_str);
    mikey.displayIMessageInfo(gmk_iwf_str);

    // Re-read GMK I-MESSAGE by alice from gms
    mikey_sakke_call_t* alice_incoming = mikey_sakke_alloc_call(alice);
    mikey_sakke_add_sender_stream(alice_incoming, 0xdeadbeef);
    bool gmk_authent = mikey_sakke_uas_auth(alice_incoming, gmk_imessage, gms_uri, nullptr);
    ASSERT_TRUE(gmk_authent);
    ASSERT_TRUE(mikey_sakke_call_is_secured(alice_incoming));
    struct mikey_sakke_key_data* alice_gmk = mikey_sakke_get_key_data(alice_incoming);
    OctetString gmk_rand = OctetString{alice_gmk->rand_size, alice_gmk->rand};
    OctetString guk_id = OctetString{alice_gmk->csb_id_size, alice_gmk->csb_id};
    // Re-read CSK I-MESSAGE by gms from alice
    mikey_sakke_call_t* gms_incoming = mikey_sakke_alloc_call(gms);
    mikey_sakke_add_sender_stream(gms_incoming, 0xdeadbeef);
    bool gms_authent = mikey_sakke_uas_auth(gms_incoming, csk_imessage, alice_uri, nullptr);
    ASSERT_TRUE(gmk_authent);
    ASSERT_TRUE(mikey_sakke_call_is_secured(gms_incoming));
    struct mikey_sakke_key_data* gms_csk = mikey_sakke_get_key_data(gms_incoming);
    OctetString csk_rand = OctetString{gms_csk->rand_size, gms_csk->rand};
    // Re-read PCK I-MESSAGE by bob from alice
    mikey_sakke_call_t* bob_incoming = mikey_sakke_alloc_call(bob);
    mikey_sakke_add_sender_stream(bob_incoming, 0xdeadbeef);
    bool pck_authent = mikey_sakke_uas_auth(bob_incoming, pck_imessage, alice_uri, nullptr);
    ASSERT_TRUE(pck_authent);
    ASSERT_TRUE(mikey_sakke_call_is_secured(bob_incoming));
    struct mikey_sakke_key_data* bob_pck = mikey_sakke_get_key_data(bob_incoming);
    OctetString pck_rand = OctetString{bob_pck->rand_size, bob_pck->rand};
    // Re-read GMK I-MESSAGE by iwf from gms
    mikey_sakke_call_t* iwf_incoming = mikey_sakke_alloc_call(iwf);
    mikey_sakke_add_sender_stream(iwf_incoming, 0xdeadbeef);
    bool gmk_iwf_authent = mikey_sakke_uas_auth(iwf_incoming, gmk_iwf_imessage, gms_uri, nullptr);
    ASSERT_TRUE(gmk_iwf_authent);
    ASSERT_TRUE(mikey_sakke_call_is_secured(iwf_incoming));
    struct mikey_sakke_key_data* iwf_gmk = mikey_sakke_get_key_data(iwf_incoming);
    OctetString iwf_rand = OctetString{iwf_gmk->rand_size, iwf_gmk->rand};
    ASSERT_TRUE(memcmp(o_gmk.raw(), iwf_gmk->key, o_gmk.size())==0);

    //struct kms_key_material_init init_keys = mikey_sakke_get_key_material_init(gms);
    const char* pub_kms = mikey_sakke_get_public_parameter(gms_keys, community, "KmsUri");
    const char* pub_period = mikey_sakke_get_public_parameter(gms_keys, community, "UserKeyPeriod");
    const char* pub_offset = mikey_sakke_get_public_parameter(gms_keys, community, "UserKeyOffset");
    const char* pub_format = mikey_sakke_get_public_parameter(gms_keys, community, "UserIdFormat");
    std::string output = "\n# Streamwide Test Vectors (v5)\n## MIKEYSAKKE-UID\nFILL-UP\n\n## MIKEYSAKKE-PAYLOAD\n### Input\n* KMS Init";
    output += std::string("\n    * KmsUri        : ") + pub_kms;
    output += std::string("\n    * UserIdFormat  : ") + libmutil::itoa(init_format);
    output += std::string("\n    * UserKeyPeriod : ") + pub_period;
    output += std::string("\n    * UserKeyOffset : ") + pub_offset;
    output += std::string("\n    * PubEncKey     : ") + init_z.translate().c_str();
    output += std::string("\n    * PubAuthKey    : ") + init_kpak.translate().c_str();
    output += std::string("\n* KMS KeyProv for GMS");
    output += std::string("\n    * UserUri           : ") + gms_uri;
    output += std::string("\n    * UserID            : ") + gms_id.translate().c_str();
    output += std::string("\n    * KeyPeriodNo       : ") + libmutil::itoa(key_period_no);
    output += std::string("\n    * UserDecryptKey    : ") + gms_decryptkey.translate().c_str();
    output += std::string("\n    * UserSigningKeySSK : ") + gms_ssk.translate().c_str();
    output += std::string("\n    * UserPubTokenPVT   : ") + gms_pvt.translate().c_str();
    output += std::string("\n* KMS KeyProv for Alice");
    output += std::string("\n    * UserUri           : ") + alice_uri;
    output += std::string("\n    * UserID            : ") + alice_id.translate().c_str();
    output += std::string("\n    * KeyPeriodNo       : ") + libmutil::itoa(key_period_no);
    output += std::string("\n    * UserDecryptKey    : ") + alice_decryptkey.translate().c_str();
    output += std::string("\n    * UserSigningKeySSK : ") + alice_ssk.translate().c_str();
    output += std::string("\n    * UserPubTokenPVT   : ") + alice_pvt.translate().c_str();
    output += std::string("\n* KMS KeyProv for IWF");
    output += std::string("\n    * UserUri           : ") + iwf_uri;
    output += std::string("\n    * UserID            : ") + iwf_id.translate().c_str();
    output += std::string("\n    * KeyPeriodNo       : ") + libmutil::itoa(key_period_no);
    output += std::string("\n    * UserDecryptKey    : ") + iwf_decryptkey.translate().c_str();
    output += std::string("\n    * UserSigningKeySSK : ") + iwf_ssk.translate().c_str();
    output += std::string("\n    * UserPubTokenPVT   : ") + iwf_pvt.translate().c_str();
    output += std::string("\n* KMS KeyProv for Bob");
    output += std::string("\n    * UserUri           : ") + bob_uri;
    output += std::string("\n    * UserID            : ") + bob_id.translate().c_str();
    output += std::string("\n    * KeyPeriodNo       : ") + libmutil::itoa(key_period_no);
    output += std::string("\n    * UserDecryptKey    : ") + bob_decryptkey.translate().c_str();
    output += std::string("\n    * UserSigningKeySSK : ") + bob_ssk.translate().c_str();
    output += std::string("\n    * UserPubTokenPVT   : ") + bob_pvt.translate().c_str();
    output += std::string("\n\n### Test 1: GMK");
    output += std::string("\n    * GMK           : ") + o_gmk.translate().c_str();
    output += std::string("\n    * GMK-ID        : ") + o_gmk_id.translate().c_str();
    output += std::string("\n    * GMK-RAND      : ") + gmk_rand.translate().c_str();
    output += std::string("\n    * GUK-ID        : ") + guk_id.translate().c_str();
    output += std::string("\n    * Initiator URI : ") + gms_uri;
    output += std::string("\n    * Responder URI : ") + alice_uri;
    output += std::string("\n    * I-MESSAGE     : ") + gmk_imessage.ptr;
    output += std::string("\n\n### Test 2: CSK");
    output += std::string("\n    * CSK           : ") + o_csk.translate().c_str();
    output += std::string("\n    * CSK-ID        : ") + o_csk_id.translate().c_str();
    output += std::string("\n    * CSK-RAND      : ") + csk_rand.translate().c_str();
    output += std::string("\n    * Initiator URI : ") + alice_uri;
    output += std::string("\n    * Responder URI : ") + gms_uri;
    output += std::string("\n    * I-MESSAGE     : ") + csk_imessage.ptr;
    output += std::string("\n\n### Test 3: PCK");
    output += std::string("\n    * PCK           : ") + o_pck.translate().c_str();
    output += std::string("\n    * PCK-ID        : ") + o_pck_id.translate().c_str();
    output += std::string("\n    * PCK-RAND      : ") + pck_rand.translate().c_str();
    output += std::string("\n    * Initiator URI : ") + alice_uri;
    output += std::string("\n    * Responder URI : ") + bob_uri;
    output += std::string("\n    * I-MESSAGE     : ") + pck_imessage.ptr;
    output += std::string("\n\n### Test 4: GMK (legacy format for IWF)");
    output += std::string("\n    * GMK           : ") + o_gmk.translate().c_str();
    output += std::string("\n    * GMK-ID        : ") + o_gmk_id.translate().c_str();
    output += std::string("\n    * GMK-RAND      : ") + iwf_rand.translate().c_str();
    output += std::string("\n    * Initiator URI : ") + gms_uri;
    output += std::string("\n    * Responder URI : ") + iwf_uri;
    output += std::string("\n    * I-MESSAGE     : ") + gmk_iwf_imessage.ptr;
    MIKEY_SAKKE_LOGI("%s", output.c_str());

    free(gmk);
    free(gmk_id);
    free(csk);
    free(csk_id);
    free(pck);
    free(pck_id);
    free((void*)pub_kms);
    free((void*)pub_period);
    free((void*)pub_offset);
    free((void*)pub_format);
    mikey_sakke_free_key_mgmt_string(gmk_imessage);
    mikey_sakke_free_key_mgmt_string(csk_imessage);
    mikey_sakke_free_key_mgmt_string(pck_imessage);
    mikey_sakke_free_key_mgmt_string(gmk_iwf_imessage);
    mikey_sakke_free_call(gms_incoming);
    mikey_sakke_free_call(alice_incoming);
    mikey_sakke_free_call(bob_incoming);
    mikey_sakke_free_call(iwf_incoming);
    mikey_sakke_free_call(gms_outgoing);
    mikey_sakke_free_call(alice_outgoing);
    mikey_sakke_free_call(bob_outgoing);
    mikey_sakke_free_call(iwf_outgoing);
    mikey_sakke_free_user(gms);
    mikey_sakke_free_user(alice);
    mikey_sakke_free_user(bob);
    mikey_sakke_free_user(iwf);
    mikey_sakke_free_key_material(gms_keys);
    mikey_sakke_free_key_material(alice_keys);
    mikey_sakke_free_key_material(bob_keys);
    mikey_sakke_free_key_material(iwf_keys);
    mikey_sakke_key_data_destroy(alice_gmk);
    mikey_sakke_key_data_destroy(gms_csk);
    mikey_sakke_key_data_destroy(bob_pck);
    mikey_sakke_key_data_destroy(iwf_gmk);
}