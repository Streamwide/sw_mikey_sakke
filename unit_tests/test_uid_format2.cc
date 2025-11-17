#include "gtest/gtest.h"
#include <libmikey/KeyAgreementSAKKE.h>
#include "mikeysakke4c.h"
#include <libmutil/Logger.h>

void stw_log(int log_level, const char* filename, unsigned line, const char* function, char* thread_name, long thread_id, const char* log) {
    fprintf(stderr, "[%s:%d][%s] %s\n", filename, line, function, log);
}

TEST(test_uid_format2, generator) {
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    std::string uri("alice@org.com");
    std::string kmsUri("127.0.0.1:8080");
    uint32_t    keyPeriod         = 2592000;
    uint32_t    key_period_offset = 0;

    // 5th argument is time period.
    // If not specified, the UID will be generated according to current time
    auto uid = genMikeySakkeUid(uri, kmsUri, keyPeriod, key_period_offset, 631);
    MIKEY_SAKKE_LOGD("generated uid %s", uid.translate().c_str());

    OctetString expectedUid = OctetString::skipws("309d9c5b8e681c330283f85e04dab2ca4daa7dfd125f1d7bf9aa9f4e11fe91af");
    ASSERT_TRUE(uid.equals(expectedUid));
}

TEST(test_uid_format2, generator2) {
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    std::string uri("alice@org.com");
    std::string kmsUri("0.0.0.0:8080");
    uint32_t    keyPeriod         = 2592000;
    uint32_t    key_period_offset = 0;
    uint32_t    key_period_no     = 1490;

    // 5th argument is time period.
    // If not specified, the UID will be generated according to current time
    auto uid = genMikeySakkeUid(uri, kmsUri, keyPeriod, key_period_offset, key_period_no);
    MIKEY_SAKKE_LOGD("generated uid %s", uid.translate().c_str());

    OctetString expectedUid = OctetString::skipws("35bad79faa9b23bf1656a5dbead20cd5226a75453ee470201e280dd6f8fb6e70");
    ASSERT_TRUE(uid.equals(expectedUid));
}

TEST(test_uid_format2, ts33180_example) {
    //mikey_sakke_set_log_func(stw_log);
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    std::string uri("sip:user@example.org");
    std::string kmsUri("kms.example.org");
    uint32_t    keyPeriod         = 2592000;
    uint32_t    key_period_offset = 0;
    uint32_t    key_period_no     = 1388;

    // 5th argument is time period.
    // If not specified, the UID will be generated according to current time
    auto uid = genMikeySakkeUid(uri, kmsUri, keyPeriod, key_period_offset, key_period_no);
    MIKEY_SAKKE_LOGD("generated uid %s", uid.translate().c_str());

    OctetString expectedUid = OctetString::skipws("3a81fb14c3b1d0fe43c9c577104d55a6d81788bfd2f09743c4557746a5a0353b");
    ASSERT_TRUE(uid.equals(expectedUid));
}

TEST(test_uid_format2, mikeysakke_payload_1) {
    //mikey_sakke_set_log_func(stw_log);
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    std::string uri("sip:user@example.org");
    std::string kmsUri("kms.example.org");
    uint32_t    keyPeriod         = 2592000;
    uint32_t    key_period_offset = 0;
    uint32_t    key_period_no     = 1;

    // 5th argument is time period.
    // If not specified, the UID will be generated according to current time
    auto uid = genMikeySakkeUid(uri, kmsUri, keyPeriod, key_period_offset, key_period_no);
    MIKEY_SAKKE_LOGD("generated uid %s", uid.translate().c_str());

    OctetString expectedUid = OctetString::skipws("74e2af803ab5d72841bbced0ce319ffe64f6fe23c88a2d258aabcf6ac5658ef4");
    ASSERT_TRUE(uid.equals(expectedUid));
}

TEST(test_uid_format2, mikeysakke_payload_2) {
    //mikey_sakke_set_log_func(stw_log);
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    std::string uri("sip:user@example.org");
    std::string kmsUri("kms.example.org");
    uint32_t    keyPeriod         = 10;
    uint32_t    key_period_offset = 0;
    uint32_t    key_period_no     = 10;

    // 5th argument is time period.
    // If not specified, the UID will be generated according to current time
    auto uid = genMikeySakkeUid(uri, kmsUri, keyPeriod, key_period_offset, key_period_no);
    MIKEY_SAKKE_LOGD("generated uid %s", uid.translate().c_str());

    OctetString expectedUid = OctetString::skipws("94fb1a697c15d7e9d6b7062066affebda2d9e346e0090d67525c0c3ce666eafa");
    ASSERT_TRUE(uid.equals(expectedUid));
}

TEST(test_uid_format2, mikeysakke_payload_3) {
    //mikey_sakke_set_log_func(stw_log);
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    std::string uri("sip:user@example.org");
    std::string kmsUri("kms.example.org");
    uint32_t    keyPeriod         = 25920000;
    uint32_t    key_period_offset = 100;
    uint32_t    key_period_no     = 1;

    // 5th argument is time period.
    // If not specified, the UID will be generated according to current time
    auto uid = genMikeySakkeUid(uri, kmsUri, keyPeriod, key_period_offset, key_period_no);
    MIKEY_SAKKE_LOGD("generated uid %s", uid.translate().c_str());

    OctetString expectedUid = OctetString::skipws("3c0ad8828cfae1ad1d08b27cc7b61258c6cfcd405081b68cd778f1e1c7f562a7");
    ASSERT_TRUE(uid.equals(expectedUid));
}

TEST(test_uid_format2, mikeysakke_payload_4) {
    //mikey_sakke_set_log_func(stw_log);
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    std::string uri("sip:user@example.org");
    std::string kmsUri("kms.example.org");
    uint32_t    keyPeriod         = 25920000;
    uint32_t    key_period_offset = 100;
    uint32_t    key_period_no     = 2048;

    // 5th argument is time period.
    // If not specified, the UID will be generated according to current time
    auto uid = genMikeySakkeUid(uri, kmsUri, keyPeriod, key_period_offset, key_period_no);
    MIKEY_SAKKE_LOGD("generated uid %s", uid.translate().c_str());

    OctetString expectedUid = OctetString::skipws("c88b3fa5e36a08985d10f7b31a631b0265e8249f0312435e4984dbc3765c7f0c");
    ASSERT_TRUE(uid.equals(expectedUid));
}

TEST(test_uid_format2, mikeysakke_payload_5) {
    //mikey_sakke_set_log_func(stw_log);
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    std::string uri("sip:user@example.org");
    std::string kmsUri("kms.example.org");
    uint32_t    keyPeriod         = 25920000;
    uint32_t    key_period_offset = 45920000;
    uint32_t    key_period_no     = 20393844;

    // 5th argument is time period.
    // If not specified, the UID will be generated according to current time
    auto uid = genMikeySakkeUid(uri, kmsUri, keyPeriod, key_period_offset, key_period_no);
    MIKEY_SAKKE_LOGD("generated uid %s", uid.translate().c_str());

    OctetString expectedUid = OctetString::skipws("8dc05540167345538475101514f4eabd384abd6ba665782abb312ecaf05934e1");
    ASSERT_TRUE(uid.equals(expectedUid));
}

TEST(test_uid_format2, softil_test) {
    //mikey_sakke_set_log_func(stw_log);
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    std::string uri("sip:33666000333@server-rbonamy-vm.streamwide.com");
    std::string kmsUri("kms.streamwide.com:8080");
    uint32_t    keyPeriod         = 2592000;
    uint32_t    key_period_offset = 0;
    uint32_t    key_period_no     = 94;

    // 5th argument is time period.
    // If not specified, the UID will be generated according to current time
    auto uid = genMikeySakkeUid(uri, kmsUri, keyPeriod, key_period_offset, key_period_no);
    MIKEY_SAKKE_LOGD("generated uid %s", uid.translate().c_str());

    OctetString expectedUid = OctetString::skipws("3a81fb14c3b1d0fe43c9c577104d55a6d81788bfd2f09743c4557746a5a0353b");
}
