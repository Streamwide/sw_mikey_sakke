#include "libmutil/Logger.h"
#include "mikeysakke4c.h"
#include "gtest/gtest.h"
#include <util/octet-string.h>
#include <cstddef>
#include <cstdint>

void stw_log(int log_level, const char* filename, unsigned line, const char* function, char* thread_name, long thread_id, const char* log) {
    fprintf(stderr, "[%s:%d][%s] %s\n", filename, line, function, log);
}

TEST(test_vector_etherstack, test_vector_etherstack_S01) {
    mikey_sakke_set_log_func(stw_log);
    mikey_sakke_set_log_level("debug");

    const char* sender_uri = "sip:p25user01@etherstack.com";
    uint8_t key_type = 0x4; // MCPTT_GROUP_CALL
    OctetString gmk  = OctetString::skipws("fcfe65cd967c58d260b603ccb9a887a9");
    OctetString gmk_id = OctetString::skipws("9bf9d37");
    OctetString gmk_rand = OctetString::skipws("6819e679461120e10ac458cce67b8024");
    OctetString guk_id_expected = OctetString::skipws("01c8de7b");
    std::size_t guk_id_size = 0;
    uint8_t     master_salt_out[12];
    uint8_t     master_key_out[16];
    OctetString master_salt_out_expected = OctetString::skipws("8b2f081ce8e8bdab1f8d9eb8");
    OctetString master_key_out_expected = OctetString::skipws("64837d2b4d69a266e4489d3807353ad9");

    uint8_t* guk_id = mikey_sakke_gen_guk_id(sender_uri, gmk.raw(), gmk.size(), gmk_id.raw(), gmk_id.size(), &guk_id_size);
    auto guk_id_os = OctetString {guk_id_size, guk_id};
    MIKEY_SAKKE_LOGI("Generated GUK-ID: %s", guk_id_os.translate().c_str());
    ASSERT_EQ(memcmp(guk_id_expected.raw(), guk_id, guk_id_expected.size()), 0);

    mikey_sakke_gen_salt2(key_type, guk_id, gmk.raw(), gmk.size(), master_salt_out, 12,
                           gmk_rand.raw(), gmk_rand.size());
    auto master_salt_out_os = OctetString {12, master_salt_out};
    MIKEY_SAKKE_LOGI("Generated master salt: %s", master_salt_out_os.translate().c_str());
    ASSERT_EQ(memcmp(master_salt_out_expected.raw(), master_salt_out, master_salt_out_expected.size()), 0);
    
    mikey_sakke_gen_tek2(key_type, guk_id, gmk.raw(), gmk.size(), master_key_out, 16,
                           gmk_rand.raw(), gmk_rand.size());
    auto master_key_out_os = OctetString {16, master_key_out};
    MIKEY_SAKKE_LOGI("Generated master key: %s", master_key_out_os.translate().c_str());
    ASSERT_EQ(memcmp(master_key_out_expected.raw(), master_key_out, master_key_out_expected.size()), 0);

    free(guk_id);
}

TEST(test_vector_etherstack, test_vector_etherstack_S02) {
    mikey_sakke_set_log_func(stw_log);
    mikey_sakke_set_log_level("debug");

    const char* sender_uri = "sip:p25user02@etherstack.co.jp";
    uint8_t key_type = 0x4; // MCPTT_GROUP_CALL
    OctetString gmk  = OctetString::skipws("fcfe65cd967c58d260b603ccb9a887a9");
    OctetString gmk_id = OctetString::skipws("9bf9d37");
    OctetString gmk_rand = OctetString::skipws("6819e679461120e10ac458cce67b8024");
    OctetString guk_id_expected = OctetString::skipws("0abe69d0");
    std::size_t guk_id_size = 0;
    uint8_t     master_salt_out[12];
    uint8_t     master_key_out[16];
    OctetString master_salt_out_expected = OctetString::skipws("75 0e a7 42 2b 4d 5a 8f f4 75 c6 d5");
    OctetString master_key_out_expected = OctetString::skipws("de 81 b7 0c 4a e0 ff 3f 79 36 4d f5 86 c2 e0 ce");

    uint8_t* guk_id = mikey_sakke_gen_guk_id(sender_uri, gmk.raw(), gmk.size(), gmk_id.raw(), gmk_id.size(), &guk_id_size);
    auto guk_id_os = OctetString {guk_id_size, guk_id};
    MIKEY_SAKKE_LOGI("Generated GUK-ID: %s", guk_id_os.translate().c_str());
    ASSERT_EQ(memcmp(guk_id_expected.raw(), guk_id, guk_id_expected.size()), 0);

    mikey_sakke_gen_salt2(key_type, guk_id, gmk.raw(), gmk.size(), master_salt_out, 12,
                           gmk_rand.raw(), gmk_rand.size());
    auto master_salt_out_os = OctetString {12, master_salt_out};
    MIKEY_SAKKE_LOGI("Generated master salt: %s", master_salt_out_os.translate().c_str());
    ASSERT_EQ(memcmp(master_salt_out_expected.raw(), master_salt_out, master_salt_out_expected.size()), 0);
    
    mikey_sakke_gen_tek2(key_type, guk_id, gmk.raw(), gmk.size(), master_key_out, 16,
                           gmk_rand.raw(), gmk_rand.size());
    auto master_key_out_os = OctetString {16, master_key_out};
    MIKEY_SAKKE_LOGI("Generated master key: %s", master_key_out_os.translate().c_str());
    ASSERT_EQ(memcmp(master_key_out_expected.raw(), master_key_out, master_key_out_expected.size()), 0);

    free(guk_id);
}

TEST(test_vector_etherstack, test_vector_etherstack_S03) {
    mikey_sakke_set_log_func(stw_log);
    mikey_sakke_set_log_level("debug");

    const char* sender_uri = "sip:92100002447@att.com";
    uint8_t key_type = 0x4; // MCPTT_GROUP_CALL
    OctetString gmk  = OctetString::skipws("fcfe65cd967c58d260b603ccb9a887a9");
    OctetString gmk_id = OctetString::skipws("9bf9d37");
    OctetString gmk_rand = OctetString::skipws("6819e679461120e10ac458cce67b8024");
    OctetString guk_id_expected = OctetString::skipws("0c449727");
    std::size_t guk_id_size = 0;
    uint8_t     master_salt_out[12];
    uint8_t     master_key_out[16];
    OctetString master_salt_out_expected = OctetString::skipws("97 a1 54 fb 24 ef bf b3 53 a2 65 e2");
    OctetString master_key_out_expected = OctetString::skipws("f0 97 ac 33 25 f1 f7 84 bc 8b a4 11 2c 5e 5f 88");

    uint8_t* guk_id = mikey_sakke_gen_guk_id(sender_uri, gmk.raw(), gmk.size(), gmk_id.raw(), gmk_id.size(), &guk_id_size);
    auto guk_id_os = OctetString {guk_id_size, guk_id};
    MIKEY_SAKKE_LOGI("Generated GUK-ID: %s", guk_id_os.translate().c_str());
    ASSERT_EQ(memcmp(guk_id_expected.raw(), guk_id, guk_id_expected.size()), 0);

    mikey_sakke_gen_salt2(key_type, guk_id, gmk.raw(), gmk.size(), master_salt_out, 12,
                           gmk_rand.raw(), gmk_rand.size());
    auto master_salt_out_os = OctetString {12, master_salt_out};
    MIKEY_SAKKE_LOGI("Generated master salt: %s", master_salt_out_os.translate().c_str());
    ASSERT_EQ(memcmp(master_salt_out_expected.raw(), master_salt_out, master_salt_out_expected.size()), 0);
    
    mikey_sakke_gen_tek2(key_type, guk_id, gmk.raw(), gmk.size(), master_key_out, 16,
                           gmk_rand.raw(), gmk_rand.size());
    auto master_key_out_os = OctetString {16, master_key_out};
    MIKEY_SAKKE_LOGI("Generated master key: %s", master_key_out_os.translate().c_str());
    ASSERT_EQ(memcmp(master_key_out_expected.raw(), master_key_out, master_key_out_expected.size()), 0);

    free(guk_id);
}

TEST(test_vector_etherstack, test_vector_etherstack_SPK) {
    mikey_sakke_set_log_func(stw_log);
    mikey_sakke_set_log_level("debug");

    const char* sender_uri = "sip:92100002447@att.com";
    uint8_t key_type = 0x6; // CSK_SRTCP_PROTECTION_FOR_MCPTT
    OctetString gmk  = OctetString::skipws("28 ba 74 44 7f 03 7d cc 09 ad 7f 25 76 dc 2d ef");
    OctetString gmk_id = OctetString::skipws("1c5f7886");
    OctetString gmk_rand = OctetString::skipws("30 33 30 32 34 36 61 30 37 30 64 61 33 33 32 65");
    OctetString guk_id_expected = OctetString::skipws("0c449727");
    std::size_t guk_id_size = 0;
    uint8_t     master_salt_out[12];
    uint8_t     master_key_out[16];
    OctetString master_salt_out_expected = OctetString::skipws("d1 d6 48 b2 a0 04 06 33 a3 dd 72 e5 ");
    OctetString master_key_out_expected = OctetString::skipws("18 5d 08 cb 5a 22 6d 19 d7 16 79 ad f5 e4 15 be");

    mikey_sakke_gen_salt2(key_type, gmk_id.raw(), gmk.raw(), gmk.size(), master_salt_out, 12,
                           gmk_rand.raw(), gmk_rand.size());
    auto master_salt_out_os = OctetString {12, master_salt_out};
    MIKEY_SAKKE_LOGI("Generated master salt: %s", master_salt_out_os.translate().c_str());
    ASSERT_EQ(memcmp(master_salt_out_expected.raw(), master_salt_out, master_salt_out_expected.size()), 0);
    
    mikey_sakke_gen_tek2(key_type, gmk_id.raw(), gmk.raw(), gmk.size(), master_key_out, 16,
                           gmk_rand.raw(), gmk_rand.size());
    auto master_key_out_os = OctetString {16, master_key_out};
    MIKEY_SAKKE_LOGI("Generated master key: %s", master_key_out_os.translate().c_str());
    ASSERT_EQ(memcmp(master_key_out_expected.raw(), master_key_out, master_key_out_expected.size()), 0);
}


TEST(test_vector_etherstack, test_guk_only) {
    mikey_sakke_set_log_func(stw_log);
    mikey_sakke_set_log_level("debug");

    const char* sender_uri = "sip:P25SU-00003002000531@server-dev43-ws.streamwideus.com";
    uint8_t key_type = 0x4; // MCPTT_GROUP_CALL
    OctetString gmk  = OctetString::skipws("52079f77690731437e407a5b4845aab3");
    OctetString gmk_id = OctetString::skipws("03f3453d");
    //OctetString gmk_rand = OctetString::skipws("6819e679461120e10ac458cce67b8024");
    OctetString guk_id_expected = OctetString::skipws("0e0e03f2");
    std::size_t guk_id_size = 0;
    uint8_t     master_salt_out[12];
    uint8_t     master_key_out[16];
    //OctetString master_salt_out_expected = OctetString::skipws("8b2f081ce8e8bdab1f8d9eb8");
    //OctetString master_key_out_expected = OctetString::skipws("64837d2b4d69a266e4489d3807353ad9");

    uint8_t* guk_id = mikey_sakke_gen_guk_id(sender_uri, gmk.raw(), gmk.size(), gmk_id.raw(), gmk_id.size(), &guk_id_size);
    auto guk_id_os = OctetString {guk_id_size, guk_id};
    MIKEY_SAKKE_LOGI("Generated GUK-ID: %s", guk_id_os.translate().c_str());
    ASSERT_EQ(memcmp(guk_id_expected.raw(), guk_id, guk_id_expected.size()), 0);

    free(guk_id);
}