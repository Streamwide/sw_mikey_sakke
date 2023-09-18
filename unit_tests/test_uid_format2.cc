#include "gtest/gtest.h"
#include <libmikey/KeyAgreementSAKKE.h>
#include <libmutil/Logger.h>

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