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

TEST(test_vectors, derivations) {
    mikey_sakke_set_log_level("debug");
    uint8_t     dppkid[]          = {0xde, 0xad, 0xba, 0xad};
    uint8_t    dpck_expected[]    = {0xf8, 0xa0, 0x91, 0xb4, 0xef, 0x8d, 0x65, 0xf, 0xd3, 0xd1, 0x5b, 0x2, 0xfd, 0xdb, 0x99, 0x17};
    
    auto o_dppkid = OctetString {4, dppkid};
    auto o_gmk = OctetString {16, gmk};

    std::vector<uint8_t> dpck = MikeySakkeCrypto::DerivateDppkToDpck(o_dppkid, o_gmk);
    for (uint i=0; i<dpck.size(); i++)
        ASSERT_EQ(dpck[i], dpck_expected[i]);
}