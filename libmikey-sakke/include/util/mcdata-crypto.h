#ifndef MCDATA_CRYPTO_H
#define MCDATA_CRYPTO_H

#if __cplusplus
extern "C" {
#endif

enum {
    MCDATA_AEAD_AES_128_GCM        = 1,
    MCDATA_AEAD_AES_256_GCM        = 2
};

#define DEFAULT_AEAD_AES_GCM_TAG_LENGTH 16
#define DEFAULT_AEAD_AES_GCM_IV_LENGTH  12

uint8_t *doEncrypt(const int algo, const uint8_t* enc_key, const uint8_t* clear, const uint32_t clear_len, const uint8_t* ad, uint32_t* len_out);
uint8_t *doDecrypt(const int algo, const uint8_t* enc_key, const uint8_t* ciphered, const uint32_t ciphered_len, const uint8_t* ad, uint32_t* len_out);

/*
-> Not declared to prevent wrong usage
uint8_t *doEncrypt_with_iv(int algo, uint8_t* enc_key, uint8_t* clear, uint32_t clear_len, uint8_t* ad, uint8_t* iv, uint32_t* len_out);
*/

#if __cplusplus
}
#endif

#endif // MCDATA_CRYPTO_H