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
    std::string kmsUri("192.168.4.101:8080");
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
    mikey_sakke_set_log_func(stw_log);
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

