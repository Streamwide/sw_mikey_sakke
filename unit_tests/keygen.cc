#include "libmutil/Logger.h"
#include "mikeysakke4c.h"
#include "gtest/gtest.h"

TEST(keygen, CSK_b64) {
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    auto csk_b64      = mikey_sakke_gen_key_b64(16);
    auto csk_id_b64   = mikey_sakke_gen_key_id_b64(CSK);
    auto csk_rand_b64 = mikey_sakke_gen_key_b64(16);

    MIKEY_SAKKE_LOGI("CSK : %s", csk_b64);
    MIKEY_SAKKE_LOGI("CSK-ID : %s", csk_id_b64);
    MIKEY_SAKKE_LOGI("CSK-Rand : %s", csk_rand_b64);

    free(csk_b64);
    free(csk_id_b64);
    free(csk_rand_b64);
}

TEST(keygen, GMK_b64) {
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    auto gmk_b64      = mikey_sakke_gen_key_b64(16);
    auto gmk_id_b64   = mikey_sakke_gen_key_id_b64(GMK);
    auto gmk_rand_b64 = mikey_sakke_gen_key_b64(16);

    MIKEY_SAKKE_LOGI("GMK : %s", gmk_b64);
    MIKEY_SAKKE_LOGI("GMK-ID : %s", gmk_id_b64);
    MIKEY_SAKKE_LOGI("GMK-Rand : %s", gmk_rand_b64);

    free(gmk_b64);
    free(gmk_id_b64);
    free(gmk_rand_b64);
}

TEST(keygen, CSK_256b_b64) {
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    auto csk_b64      = mikey_sakke_gen_key_b64(32);
    auto csk_id_b64   = mikey_sakke_gen_key_id_b64(CSK);
    auto csk_rand_b64 = mikey_sakke_gen_key_b64(32);

    MIKEY_SAKKE_LOGI("CSK : %s", csk_b64);
    MIKEY_SAKKE_LOGI("CSK-ID : %s", csk_id_b64);
    MIKEY_SAKKE_LOGI("CSK-Rand : %s", csk_rand_b64);

    free(csk_b64);
    free(csk_id_b64);
    free(csk_rand_b64);
}

TEST(keygen, GMK_256b_b64) {
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");

    auto gmk_b64      = mikey_sakke_gen_key_b64(32);
    auto gmk_id_b64   = mikey_sakke_gen_key_id_b64(GMK);
    auto gmk_rand_b64 = mikey_sakke_gen_key_b64(32);

    MIKEY_SAKKE_LOGI("GMK : %s", gmk_b64);
    MIKEY_SAKKE_LOGI("GMK-ID : %s", gmk_id_b64);
    MIKEY_SAKKE_LOGI("GMK-Rand : %s", gmk_rand_b64);

    free(gmk_b64);
    free(gmk_id_b64);
    free(gmk_rand_b64);
}