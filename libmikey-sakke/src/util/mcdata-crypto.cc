#include <openssl/evp.h>
#include "util/mcdata-crypto.h"
#include <libmutil/Logger.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <libmcrypto/rand.h>
#include <cstring>


/* WARNING: this has been tested only on OpenSSL 3.0.7 */

/**
 * AD: associated data must but 16 Bytes long
 * IV: Initialization vector must but 12 Bytes long
 * Returns the ciphered payload formatted as a concatenation "CIPHER_DATA(len=clear_len)|TAG(16B)|IV(12B)"
 */
uint8_t* doEncrypt_AEAD_AES_GCM(const int key_length, const uint8_t* enc_key, const uint8_t* clear, const uint32_t clear_len, const uint8_t* ad, const uint8_t* iv, uint32_t* len_out) {
    int     tmp_len;
    int     tmp;
    uint8_t* ciphered = (uint8_t*)malloc(clear_len * sizeof(*clear)+DEFAULT_AEAD_AES_GCM_TAG_LENGTH+DEFAULT_AEAD_AES_GCM_IV_LENGTH);

    // 1. Get a crypto context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    // 2. Choose the algorithm
    if (key_length == 16) {
        tmp = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    } else if (key_length == 32) {
        tmp = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    }

    // 3. Explicitly declare the IV length. NIST does reccommand to have a 96bit (12B) long IV
    tmp = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, DEFAULT_AEAD_AES_GCM_IV_LENGTH, NULL);
    if (!tmp) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "EVP_CIPHER_CTX_ctrl (iv_len): %s (%lu)\n",
			ERR_reason_error_string(ERR_get_error()), ERR_get_error());
    }

    // 4. Setup the crypto suite with encryption key & the IV
    tmp = EVP_EncryptInit_ex (ctx, NULL, NULL, enc_key, iv);

    /*tmp = EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (!tmp) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "EVP_EncryptInit_ex (padding): %s (%lu)\n",
			ERR_reason_error_string(ERR_get_error()), ERR_get_error());
    }*/

    // 5. Cipher the "associated data" to perform later the authentication
    if (ad != NULL) {
        tmp = EVP_EncryptUpdate(ctx, NULL, &tmp_len, ad, DEFAULT_AEAD_AES_GCM_TAG_LENGTH);
        if (!tmp) {
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "EVP_DecryptUpdate (tag): %s (%lu)\n",
			ERR_reason_error_string(ERR_get_error()), ERR_get_error());
        }
    }

    // 6. Cipher the input data itself
    tmp = EVP_EncryptUpdate(ctx, ciphered, (int*)len_out, clear, clear_len);
    if (!tmp) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "EVP_EncryptUpdate (ciphered): %s (%lu)\n",
			ERR_reason_error_string(ERR_get_error()), ERR_get_error());
        MIKEY_SAKKE_LOGE("Crypto: Issue during EVP_EncryptUpdate (ciphered)");
    }

    // 7. Close the ciphering calculation, tmp_len must be 0
    tmp = EVP_EncryptFinal_ex(ctx, ciphered, &tmp_len);
    if (!tmp) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "EVP_EncryptFinal_ex: %s (%lu)\n",
			ERR_reason_error_string(ERR_get_error()), ERR_get_error());
        MIKEY_SAKKE_LOGE("Crypto: Issue during EVP_EncryptFinal_ex()");
    }

    // 8. Get the tag (the ciphered associated data) for further authentication checks, copy it at the end of the cipher payload
    tmp = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, DEFAULT_AEAD_AES_GCM_TAG_LENGTH, ciphered+*len_out);
    if (!tmp) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "EVP_CIPHER_CTX_ctrl (get tag): %s (%lu)\n",
			ERR_reason_error_string(ERR_get_error()), ERR_get_error());
        MIKEY_SAKKE_LOGE("Crypto: Issue during EVP_EncryptFinal_ex()");
    }
    *len_out += DEFAULT_AEAD_AES_GCM_TAG_LENGTH;

    // 9. Copy the IV value at the end of the ciphered payload, for an easy re-use in UnCrypt function
    memcpy(ciphered+*len_out, iv, DEFAULT_AEAD_AES_GCM_IV_LENGTH);
    *len_out += DEFAULT_AEAD_AES_GCM_IV_LENGTH;

    // DEBUG purpose
    //printf("Ciphered STW payload:\n");
	//BIO_dump_fp(stdout, ciphered, *len_out);

    EVP_CIPHER_CTX_free(ctx);

    return ciphered;
}

uint8_t* doDecrypt_AEAD_AES_GCM(const int key_length, const uint8_t* enc_key, const uint8_t* ciphered, const uint32_t ciphered_len, const uint8_t* ad, uint32_t* len_out) {
    int         tmp_len;
    int         tmp;
    const uint8_t*    iv = ciphered+ciphered_len-DEFAULT_AEAD_AES_GCM_IV_LENGTH;

    uint8_t* clear = (uint8_t*)malloc(ciphered_len * sizeof(*clear)-DEFAULT_AEAD_AES_GCM_TAG_LENGTH-DEFAULT_AEAD_AES_GCM_IV_LENGTH);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (key_length == 16) {
        tmp = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    } else if (key_length == 32) {
        tmp = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    }
    tmp = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    if (!tmp) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "EVP_CIPHER_CTX_ctrl (iv_len): %s (%lu)\n",
			ERR_reason_error_string(ERR_get_error()), ERR_get_error());
    }
    tmp = EVP_DecryptInit_ex(ctx, NULL, NULL, enc_key, iv);
    if (!tmp) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "EVP_DecryptInit_ex: %s (%lu)\n",
			ERR_reason_error_string(ERR_get_error()), ERR_get_error());
    }
#if 0
	/* Set expected tag value. A restriction in OpenSSL 1.0.1c and earlier
         * required the tag before any AAD or ciphertext */
	tmp = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, ciphered+ciphered_len-DEFAULT_AEAD_AES_GCM_IV_LENGTH-DEFAULT_AEAD_AES_GCM_TAG_LENGTH);
#endif
    //tmp = EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (!tmp) {
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "EVP_DecryptInit_ex (padding): %s (%lu)\n",
			ERR_reason_error_string(ERR_get_error()), ERR_get_error());
    }

    if (ad != NULL) {
        tmp = EVP_DecryptUpdate(ctx, NULL, &tmp_len, ad, DEFAULT_AEAD_AES_GCM_TAG_LENGTH);
        if (!tmp) {
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "EVP_DecryptUpdate (tag): %s (%lu)\n",
			ERR_reason_error_string(ERR_get_error()), ERR_get_error());
        }
    }
    tmp = EVP_DecryptUpdate(ctx, clear, (int*)len_out, ciphered, ciphered_len-DEFAULT_AEAD_AES_GCM_TAG_LENGTH-DEFAULT_AEAD_AES_GCM_IV_LENGTH);
    if (!tmp) {
        fprintf(stderr, "EVP_DecryptUpdate: %s (%lu)\n",
			ERR_reason_error_string(ERR_get_error()), ERR_get_error());
    }
    if (ad != NULL) {
        tmp = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, DEFAULT_AEAD_AES_GCM_TAG_LENGTH, (void *)(ciphered+*len_out));
        if (!tmp) {
            MIKEY_SAKKE_LOGE("Crypto: Issue during EVP_CIPHER_CTX_ctrl(set tag)");
            ERR_print_errors_fp(stderr);
            fprintf(stderr, "EVP_CIPHER_CTX_ctrl (set tag): %s (%lu)\n",
                ERR_reason_error_string(ERR_get_error()), ERR_get_error());
        }
    }
    tmp = EVP_DecryptFinal_ex(ctx, clear, &tmp_len);
    if (!tmp) {
        /* Force the caller to know that Verification Tag failed */
        *len_out = 0;
        MIKEY_SAKKE_LOGE("Crypto: Issue during EVP_DecryptFinal_ex() // Tag not verified ?");
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "EVP_DecryptFinal_ex (tag verif error ?): %s (%lu)\n",
			ERR_reason_error_string(ERR_get_error()), ERR_get_error());
    }
    *len_out += tmp_len;
    EVP_CIPHER_CTX_free(ctx);

    return clear;
}

/**
 * ad (additional data) MUST be 16 bytes long (or null, but in this case, no authentication is possible)
 * iv (initialization vector) MUST be 12 bytes long (reccommendation from NIST)
 * 
 * WARNING: if you call this function directly, make sure to have a couple key/iv unique for each ciphered text
 *          else, it weakness the crypto security
 */
uint8_t *doEncryptWithIv(const int algo, const uint8_t* enc_key, const uint8_t* clear, const uint32_t clear_len, const uint8_t* ad, const uint8_t* iv, uint32_t* len_out) {
    uint8_t*    ret = NULL;

    if (enc_key == NULL || clear == NULL) {
        MIKEY_SAKKE_LOGE("Crypto: Wrong argument (enc_key or clear text is NULL pointed)");
    } else if (algo == MCDATA_AEAD_AES_128_GCM) {
        ret = doEncrypt_AEAD_AES_GCM(16, enc_key, clear, clear_len, ad, iv, len_out);
    } else if (algo == MCDATA_AEAD_AES_256_GCM) {
        ret = doEncrypt_AEAD_AES_GCM(32, enc_key, clear, clear_len, ad, iv, len_out);
    } else {
        MIKEY_SAKKE_LOGE("Crypto: Ciphering algo (%d) is not supported", algo);
    }
    return ret;
}

/**
 * ad (additional data) MUST be 16 bytes long (or null, but in this case, no authentication is possible)
 */
uint8_t *doEncrypt(const int algo, const uint8_t* enc_key, const uint8_t* clear, const uint32_t clear_len, const uint8_t* ad, uint32_t* len_out) {
    uint8_t iv[DEFAULT_AEAD_AES_GCM_IV_LENGTH];

    /* As the couple key/iv MUST always be unique, then it is better to randomize IV at each call */
    Rand::randomize(iv, DEFAULT_AEAD_AES_GCM_IV_LENGTH);
    return doEncryptWithIv(algo, enc_key, clear, clear_len, ad, iv, len_out);
}

/**
 * ad (additional data) MUST be 16 bytes long (or null, but in this case, no authentication is possible)
 */
uint8_t *doDecrypt(const int algo, const uint8_t* enc_key, const uint8_t* ciphered, const uint32_t ciphered_len, const uint8_t* ad, uint32_t* len_out) {
    uint8_t*    ret = NULL;

    if (enc_key == NULL || ciphered == NULL) {
        MIKEY_SAKKE_LOGE("Crypto: Wrong argument (enc_key or clear text is NULL pointed)");
    } else if (algo == MCDATA_AEAD_AES_128_GCM) {
        ret = doDecrypt_AEAD_AES_GCM(16, enc_key, ciphered, ciphered_len, ad, len_out);
    } else if (algo == MCDATA_AEAD_AES_256_GCM) {
        ret = doDecrypt_AEAD_AES_GCM(32, enc_key, ciphered, ciphered_len, ad, len_out);
    } else {
        MIKEY_SAKKE_LOGE("Crypto: Ciphering algo (%d) is not supported", algo);
    }
    return ret;
}
