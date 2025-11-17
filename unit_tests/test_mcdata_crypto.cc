#include "gtest/gtest.h"
#include <libmutil/Logger.h>
#include <test_data.h>
#include <util/mcdata-crypto.h>
#include <mikeysakke4c.h>
#include <mscrypto/sakke.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>

/* Declared here, only for NIST test purposes */
uint8_t *doEncryptCustom(const int algo, const uint8_t* enc_key, const uint8_t* clear, const uint32_t clear_len, const uint8_t* ad, const uint8_t ad_len, const uint8_t* iv, const uint8_t iv_len, uint32_t* len_out);
uint8_t *doDecryptCustom(const int algo, const uint8_t* enc_key, const uint8_t* clear, const uint32_t clear_len, const uint8_t* ad, const uint8_t ad_len, const uint8_t iv_len, uint32_t* len_out);

void stw_log(int log_level, const char* filename, unsigned line, const char* function, char* thread_name, long thread_id, const char* log) {
    fprintf(stderr, "[%s:%d][%s] %s\n", filename, line, function, log);
}

/* AES-GCM test data from NIST public test vectors */
static const unsigned char nist_gcm_key[] = {
	0xee,0xbc,0x1f,0x57,0x48,0x7f,0x51,0x92,0x1c,0x04,0x65,0x66,
	0x5f,0x8a,0xe6,0xd1,0x65,0x8b,0xb2,0x6d,0xe6,0xf8,0xa0,0x69,
	0xa3,0x52,0x02,0x93,0xa5,0x72,0x07,0x8f
};

static const unsigned char nist_gcm_iv[] = {
	0x99,0xaa,0x3e,0x68,0xed,0x81,0x73,0xa0,0xee,0xd0,0x66,0x84
};

static const unsigned char nist_gcm_pt[] = {
	0xf5,0x6e,0x87,0x05,0x5b,0xc3,0x2d,0x0e,0xeb,0x31,0xb2,0xea,
	0xcc,0x2b,0xf2,0xa5
};

static const unsigned char nist_gcm_aad[] = {
	0x4d,0x23,0xc3,0xce,0xc3,0x34,0xb4,0x9b,0xdb,0x37,0x0c,0x43,
	0x7f,0xec,0x78,0xde
};

static const unsigned char nist_gcm_ct[] = {
	0xf7,0x26,0x44,0x13,0xa8,0x4c,0x0e,0x7c,0xd5,0x36,0x86,0x7e,
	0xb9,0xf2,0x17,0x36
};

/* STW format is ciphered_text + tag + iv */
static const unsigned char nist_gcm_ct_stw_payload[] = {
	0xf7,0x26,0x44,0x13,0xa8,0x4c,0x0e,0x7c,0xd5,0x36,0x86,0x7e,
	0xb9,0xf2,0x17,0x36,
    0x67,0xba,0x05,0x10,0x26,0x2a,0xe4,0x87,0xd7,0x37,0xee,0x62,
	0x98,0xf7,0x7e,0x0c,
    0x99,0xaa,0x3e,0x68,0xed,0x81,0x73,0xa0,0xee,0xd0,0x66,0x84
};

static unsigned char nist_gcm_tag[] = {
	0x67,0xba,0x05,0x10,0x26,0x2a,0xe4,0x87,0xd7,0x37,0xee,0x62,
	0x98,0xf7,0x7e,0x0c
};

TEST(test_mcdata_crypto, test_crypto_nist_256) {
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");
    uint8_t*    ciphered;
    int         len_out;
    uint8_t*    decrypted;

    /* Test ciphering the plaintext */
    ciphered = doEncryptCustom(MCDATA_AEAD_AES_256_GCM, nist_gcm_key, (uint8_t*)nist_gcm_pt, sizeof(nist_gcm_pt), nist_gcm_aad, DEFAULT_AEAD_AES_GCM_TAG_LENGTH, nist_gcm_iv, DEFAULT_AEAD_AES_GCM_IV_LENGTH, (uint32_t*)&len_out);

    /* Check the len of the output */
    ASSERT_EQ(len_out, sizeof(nist_gcm_pt)+DEFAULT_AEAD_AES_GCM_TAG_LENGTH+DEFAULT_AEAD_AES_GCM_IV_LENGTH);
    /* Check the data ciphered value */
    ASSERT_EQ(memcmp(ciphered, nist_gcm_ct, sizeof(nist_gcm_ct)), 0);
    /* Check the tag value */
    ASSERT_EQ(memcmp(ciphered+sizeof(nist_gcm_ct), nist_gcm_tag, sizeof(nist_gcm_tag)), 0);
    /* Check the iv value */
    ASSERT_EQ(memcmp(ciphered+sizeof(nist_gcm_ct)+DEFAULT_AEAD_AES_GCM_TAG_LENGTH, nist_gcm_iv, sizeof(nist_gcm_iv)), 0);
    ASSERT_NE(len_out, 0);

    /* Test unciphering the cipher */
    decrypted = doDecrypt(MCDATA_AEAD_AES_256_GCM, nist_gcm_key, (uint8_t*)nist_gcm_ct_stw_payload, sizeof(nist_gcm_ct_stw_payload), nist_gcm_aad, (uint32_t*)&len_out);

    /* Check the len of the output */
    ASSERT_EQ(len_out, sizeof(nist_gcm_ct));
    /* Check the data ciphered value */
    ASSERT_EQ(memcmp(decrypted, nist_gcm_pt, sizeof(nist_gcm_pt)), 0);
    ASSERT_NE(len_out, 0);

    free(ciphered);
    free(decrypted);
}

TEST(test_mcdata_crypto, test_crypto_nominal_aligned) {
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");
    int         len_ciphered;
    int         len_decrypted;
    char        clear[] = "toto123456123456";
    uint8_t*    ciphered;
    uint8_t*    decrypted;
    uint8_t     enc_key[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
    uint8_t     enc_key256[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
    uint8_t     ad[] = {0x16, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x01};

    ciphered = doEncrypt(MCDATA_AEAD_AES_128_GCM, enc_key, (uint8_t*)clear, strlen(clear), ad, (uint32_t*)&len_ciphered);
    decrypted = doDecrypt(MCDATA_AEAD_AES_128_GCM, enc_key, ciphered, len_ciphered, ad, (uint32_t*)&len_decrypted);

    ASSERT_EQ(strlen(clear), len_decrypted);
    ASSERT_EQ(memcmp(clear, decrypted, len_decrypted), 0);
    ASSERT_NE(len_decrypted, 0);

    free(ciphered);
    free(decrypted);

    ciphered = doEncrypt(MCDATA_AEAD_AES_256_GCM, enc_key256, (uint8_t*)clear, strlen(clear), ad, (uint32_t*)&len_ciphered);
    decrypted = doDecrypt(MCDATA_AEAD_AES_256_GCM, enc_key256, ciphered, len_ciphered, ad, (uint32_t*)&len_decrypted);

    ASSERT_EQ(strlen(clear), len_decrypted);
    ASSERT_EQ(memcmp(clear, decrypted, len_decrypted), 0);
    ASSERT_NE(len_decrypted, 0);

    free(ciphered);
    free(decrypted);
}

TEST(test_mcdata_crypto, test_crypto_nominal_unaligned) {
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");
    int         len_ciphered;
    int         len_decrypted;
    char        clear[] = "toto";
    uint8_t*    ciphered;
    uint8_t*    decrypted;
    uint8_t     enc_key[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
    uint8_t     enc_key256[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
    uint8_t     ad[] = {0x16, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x01};

    ciphered = doEncrypt(MCDATA_AEAD_AES_128_GCM, enc_key, (uint8_t*)clear, strlen(clear), ad, (uint32_t*)&len_ciphered);
    decrypted = doDecrypt(MCDATA_AEAD_AES_128_GCM, enc_key, ciphered, len_ciphered, ad, (uint32_t*)&len_decrypted);

    ASSERT_EQ(strlen(clear), len_decrypted);
    ASSERT_EQ(memcmp(clear, decrypted, len_decrypted), 0);
    ASSERT_NE(len_decrypted, 0);

    free(ciphered);
    free(decrypted);

    ciphered = doEncrypt(MCDATA_AEAD_AES_256_GCM, enc_key256, (uint8_t*)clear, strlen(clear), ad, (uint32_t*)&len_ciphered);
    decrypted = doDecrypt(MCDATA_AEAD_AES_256_GCM, enc_key256, ciphered, len_ciphered, ad, (uint32_t*)&len_decrypted);

    ASSERT_EQ(strlen(clear), len_decrypted);
    ASSERT_EQ(memcmp(clear, decrypted, len_decrypted), 0);
    ASSERT_NE(len_decrypted, 0);

    free(ciphered);
    free(decrypted);
}


TEST(test_mcdata_crypto, test_crypto_nominal_long) {
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");
    int         len_ciphered;
    int         len_decrypted;
    char        clear[] =   "totoezrferf zpeorfj eqpofvj qdofivj sdlmfkvn qepoifgh"\
                            "aeporigjhqeproif nqdkjvn qsmdoivj qeoidvfj nqldkfjvn "\
                            "dqfqpdfqdjflkqs,dfmlqsdfml,qsdfkln,qdslfknqsdflkn,nqs"\
                            "flknqsdflknkqsdfldknqsdflknqsdflknqsdflknqsdf;, qsdk "\
                            "aeporigjhqeproif nqdkjvn qsmdoivj qeoidvfj nqldkfjvn "\
                            "dqfqpdfqdjflkqs,dfmlqsdfml,qsdfkln,qdslfknqsdflkn,nqs"\
                            "flknqsdflknkqsdfldknqsdflknqsdflknqsdflknqsdf;, qsdk "\
                            "aeporigjhqeproif nqdkjvn qsmdoivj qeoidvfj nqldkfjvn "\
                            "dqfqpdfqdjflkqs,dfmlqsdfml,qsdfkln,qdslfknqsdflkn,nqs"\
                            "flknqsdflknkqsdfldknqsdflknqsdflknqsdflknqsdf;, qsdk "\
                            "aeporigjhqeproif nqdkjvn qsmdoivj qeoidvfj nqldkfjvn "\
                            "dqfqpdfqdjflkqs,dfmlqsdfml,qsdfkln,qdslfknqsdflkn,nqs"\
                            "flknqsdflknkqsdfldknqsdflknqsdflknqsdflknqsdf;, qsdk "\
                            "qsldfkfnqsdpofjqspdofkqsdmfk";
    uint8_t*    ciphered;
    uint8_t*    decrypted;
    uint8_t     enc_key[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
    uint8_t     enc_key256[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
    uint8_t     ad[] = {0x16, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x01};

    ciphered = doEncrypt(MCDATA_AEAD_AES_128_GCM, enc_key, (uint8_t*)clear, strlen(clear), ad, (uint32_t*)&len_ciphered);
    decrypted = doDecrypt(MCDATA_AEAD_AES_128_GCM, enc_key, ciphered, len_ciphered, ad, (uint32_t*)&len_decrypted);

    ASSERT_EQ(strlen(clear), len_decrypted);
    ASSERT_EQ(memcmp(clear, decrypted, len_decrypted), 0);
    ASSERT_NE(len_decrypted, 0);

    free(ciphered);
    free(decrypted);

    ciphered = doEncrypt(MCDATA_AEAD_AES_256_GCM, enc_key256, (uint8_t*)clear, strlen(clear), ad, (uint32_t*)&len_ciphered);
    decrypted = doDecrypt(MCDATA_AEAD_AES_256_GCM, enc_key256, ciphered, len_ciphered, ad, (uint32_t*)&len_decrypted);

    ASSERT_EQ(strlen(clear), len_decrypted);
    ASSERT_EQ(memcmp(clear, decrypted, len_decrypted), 0);
    ASSERT_NE(len_decrypted, 0);

    free(ciphered);
    free(decrypted);
}

TEST(test_mcdata_crypto, test_crypto_nominal_unaligned_custom_iv_len) {
    mikey_sakke_set_log_func(stw_log);
    MIKEY_SAKKE_LOG_SET_LEVEL("debug");
    int         len_ciphered;
    int         len_decrypted;
    char        clear[] = "toto12345-libMikeySakke";
    uint8_t*    ciphered;
    uint8_t*    decrypted;
    uint8_t     enc_key[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
    uint8_t     enc_key256[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16};
    uint8_t     ad[] = {0x16, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x01, 0x16, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x01};
    uint8_t     iv[] = {0x2, 0x1, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x10, 0x09, 0x11, 0x12, 0x13, 0x15, 0x14, 0x16};

    uint8_t ad_len = 32;
    uint8_t iv_len = 16;


    ciphered = doEncryptCustom(MCDATA_AEAD_AES_128_GCM, enc_key, (uint8_t*)clear, strlen(clear), ad, ad_len, iv, iv_len, (uint32_t*)&len_ciphered);
    ASSERT_NE(ciphered, nullptr);
    ASSERT_NE(len_ciphered, 0);
    ASSERT_EQ(len_ciphered, strlen(clear)+DEFAULT_AEAD_AES_GCM_TAG_LENGTH+iv_len);
    decrypted = doDecryptCustom(MCDATA_AEAD_AES_128_GCM, enc_key, ciphered, len_ciphered, ad, ad_len, iv_len, (uint32_t*)&len_decrypted);

    ASSERT_EQ(memcmp(clear, decrypted, strlen(clear)), 0);
    ASSERT_NE(len_decrypted, 0);
    ASSERT_EQ(strlen(clear), len_decrypted);

    free(ciphered);
    free(decrypted);

    ciphered = doEncryptCustom(MCDATA_AEAD_AES_256_GCM, enc_key256, (uint8_t*)clear, strlen(clear), ad, ad_len, iv, iv_len, (uint32_t*)&len_ciphered);
    ASSERT_NE(ciphered, nullptr);
    ASSERT_NE(len_ciphered, 0);
    decrypted = doDecryptCustom(MCDATA_AEAD_AES_256_GCM, enc_key256, ciphered, len_ciphered, ad, ad_len, iv_len, (uint32_t*)&len_decrypted);

    ASSERT_EQ(memcmp(clear, decrypted, strlen(clear)), 0);
    ASSERT_NE(len_decrypted, 0);
    ASSERT_EQ(strlen(clear), len_decrypted);

    free(ciphered);
    free(decrypted);
}