#ifndef MIKEYSAKKE4C_H
#define MIKEYSAKKE4C_H

#include <mikey_sakke_types.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#if __cplusplus
extern "C" {
#endif

// Key size for GMK, CSK, ...
#define MIKEY_SAKKE_DEFAULT_KEY_SIZE 16
#define MIKEY_SAKKE_DEFAULT_KEY_ID_SIZE 4

struct mikey_sakke_kms_response {
    char*  user_uri;
    char*  kms_uri;
    time_t time;
    char*  kms_req_url;
};

struct mikey_sakke_kms_response* mikey_sakke_kms_response_create();
void                             mikey_sakke_kms_response_destroy(struct mikey_sakke_kms_response* resp);

struct kms_key_material_init {
    struct mikey_sakke_kms_response* resp;
    char*                            KPAK;
    char*                            Z;
    uint8_t                          user_id_format;
    uint32_t                         user_key_period;
    uint32_t                         user_key_offset;
};

struct kms_key_material_init* kms_key_material_init_create();
void                          kms_key_material_init_destroy(struct kms_key_material_init* init);

// Getters to facilitate php bindings
char* kms_key_material_init_get_user_uri(struct kms_key_material_init* init);
char* kms_key_material_init_get_kms_uri(struct kms_key_material_init* init);
char* kms_key_material_init_get_kpak(struct kms_key_material_init* init);
char* kms_key_material_init_get_z(struct kms_key_material_init* init);
char* kms_key_material_init_get_user_id_format(struct kms_key_material_init* init);
char* kms_key_material_init_get_user_key_period(struct kms_key_material_init* init);
char* kms_key_material_init_get_user_key_offset(struct kms_key_material_init* init);

struct kms_key_material_key_prov {
    struct mikey_sakke_kms_response* resp;
    char*                            user_id;
    uint32_t                         key_period_no;
    char*                            RSK;
    char*                            SSK;
    char*                            PVT;
};

struct kms_key_material_key_prov* kms_key_material_key_prov_create();
void                              kms_key_material_key_prov_destroy(struct kms_key_material_key_prov* key_prov);

// Getters to facilitate PHP bindings
char* kms_key_material_key_prov_get_user_uri(struct kms_key_material_key_prov* key_prov);
char* kms_key_material_key_prov_get_kms_uri(struct kms_key_material_key_prov* key_prov);
char* kms_key_material_key_prov_get_user_id(struct kms_key_material_key_prov* key_prov);
char* kms_key_material_key_prov_get_key_period_no(struct kms_key_material_key_prov* key_prov);
char* kms_key_material_key_prov_get_rsk(struct kms_key_material_key_prov* key_prov);
char* kms_key_material_key_prov_get_ssk(struct kms_key_material_key_prov* key_prov);
char* kms_key_material_key_prov_get_pvt(struct kms_key_material_key_prov* key_prov);

typedef struct mikey_sakke_key_material mikey_sakke_key_material_t;
typedef struct mikey_sakke_user         mikey_sakke_user_t;
typedef struct mikey_sakke_call         mikey_sakke_call_t;
typedef struct km_client                km_client_t;
typedef struct key_material_params      key_material_params_t;
struct key_agreement_params;

struct mikey_sakke_key_data {
    uint8_t* key;
    size_t   key_size;
    uint8_t* key_id;
    size_t   key_id_size;
    uint8_t* rand;
    size_t   rand_size;
    uint8_t* csb_id;
    size_t   csb_id_size;
};

struct mikey_sakke_key_id {
    uint8_t* key_id;
    size_t   key_id_size;
};
typedef struct mikey_sakke_key_id      mikey_sakke_key_id_t;

struct mikey_sakke_key_data* mikey_sakke_key_data_create();
void                         mikey_sakke_key_data_destroy(struct mikey_sakke_key_data* data);

// Getters to facilitate PHP bindings
const char* mikey_sakke_key_data_get_key_b64(struct mikey_sakke_key_data* data);
const char* mikey_sakke_key_data_get_key_id_b64(struct mikey_sakke_key_data* data);
const char* mikey_sakke_key_data_get_rand_b64(struct mikey_sakke_key_data* data);

#define SRTP_KEYSALT_LEN_MAX 64
#define SRTP_MKI_LEN_MAX 128
struct mikey_sakke_srtp_master_key {
    mikey_sakke_crypto_suite_t suite;
    uint8_t                    key[SRTP_KEYSALT_LEN_MAX]; // max srtp key len + salt
    size_t                     tek_len;                   // key len
    size_t                     salt_len;                  // key salt len
    uint8_t                    mki[SRTP_MKI_LEN_MAX];     // Master Key Identifier
    size_t                     mki_len;                   // Actual MKI len
};

typedef struct mikey_key_mgmt_string {
    char*  ptr;
    size_t len;
} mikey_key_mgmt_string_t;

/*  Sample keystores preprovisioned with values from RFCs
 *  Use the sender one to generate and send i_messages
 *  Use the receiver one to receive, verify and decapsulate i_messages
 * */
mikey_sakke_key_material_t* mikey_sakke_alloc_sample_key_material_sender(const char* uri, const char* community);
mikey_sakke_key_material_t* mikey_sakke_alloc_sample_key_material_receiver(const char* uri, const char* community);

// keystore uri example: keydir:/var/run/some-key-dir
mikey_sakke_key_material_t* mikey_sakke_alloc_key_material(char const* keystore_uri);
void                        mikey_sakke_purge_key_material(mikey_sakke_key_material_t*);
void                        mikey_sakke_free_key_material(mikey_sakke_key_material_t*);

/**
 * Creates a key management client, that can send requests to a KMS
 * @param kms_uri     : URI of the KMS
 * @param is_secured  : whether to use xml security
 * @param keys        : keystore to store the keys
 * @param timeout_ms  : the timeout for the requests done by this client
 * @returns a client object structure
 **/
km_client_t* mikey_sakke_client_create(const char* kms_uri, bool is_secured, mikey_sakke_key_material_t* keys, uint32_t timeout_ms);
void         mikey_sakke_client_destroy(km_client_t*);
void         mikey_sakke_client_set_token(km_client_t* client, const char* token);
void         mikey_sakke_client_set_token2(km_client_t* client, const char* token, size_t token_len);

void  mikey_sakke_client_set_user_uri(km_client_t* client, const char* user_uri);
char* mikey_sakke_client_get_user_uri(km_client_t* client);
char* mikey_sakke_client_get_user_id(km_client_t* client);
void  mikey_sakke_client_set_kms_uri(km_client_t* client, const char* kms_uri);

void mikey_sakke_client_set_security(km_client_t* client, bool security);
void mikey_sakke_client_set_tls_security(km_client_t* client, bool verify_host, bool verify_peer);
void mikey_sakke_client_set_ca_cert_bundle(km_client_t* client, const char* ca_filepath);
void mikey_sakke_client_set_ca_cert_bundle_blob(km_client_t* client, const char* pem_blob);
void mikey_sakke_client_set_timeout(km_client_t* client, uint32_t timeout);

const mikey_sakke_key_material_t* mikey_sakke_client_get_key_store(km_client_t* client);

/**
 * Sends KMS Init request
 * @param client  : The client objet to use for the request
 * @returns a negative curl error code or 0 on success
 **/
int mikey_sakke_fetch_key_material_init(km_client_t* client);

struct kms_key_material_init* mikey_sakke_get_key_material_init(km_client_t* client);

/**
 * Sends KMS KeyProv request
 * @param client  : The client objet to use for the request
 * @returns a negative curl error code or 0 on success
 **/
int mikey_sakke_fetch_key_material_key_prov(km_client_t* client);
int mikey_sakke_fetch_key_material_key_prov_period(km_client_t* client, uint32_t key_period_timestamp_s);

struct kms_key_material_key_prov* mikey_sakke_get_key_material_key_prov(km_client_t* client);
void                              kms_key_material_key_prov_destroy(struct kms_key_material_key_prov* key_prov);

/**
 * Add a key to a keystore
 * @param keys : a keystore
 * @param identifier : an identifier
 * @param key_name : the key's name
 * @param key : the key, as a string
 * @param priv : whether it's a private or public key
 **/
void mikey_sakke_provision_key_material(mikey_sakke_key_material_t* keys, const char* identifier, const char* key_name, const char* key,
                                        bool is_private_key);

void mikey_sakke_set_public_parameter(mikey_sakke_key_material_t* keys, const char* identifier, const char* parameter, const char* value);
const char* mikey_sakke_get_public_parameter(mikey_sakke_key_material_t* keys, const char* community, const char* parameter);

void        mikey_sakke_add_community(mikey_sakke_key_material_t* keys, const char* community);
const char* mikey_sakke_get_community(mikey_sakke_key_material_t* keys);

/**
 * Add a key to a keystore
 * @param keys : a keystore
 * @param identifier : an identifier
 * @param key_name : the key's name
 * @param key : the key, as an array of bytes
 * @param key_len : the size of the byte array
 * @param priv : whether it's a private or public key
 **/
void mikey_sakke_provision_key_material_bytes(mikey_sakke_key_material_t* keys, const char* identifier, const char* key_name,
                                              const uint8_t* key, size_t key_len, bool is_private_key);

/**
 * Add a key to a keystore
 * @param keys : a keystore
 * @param identifier : an identifier
 * @param key_name : the key's name
 * @param key : the key, a b64 encoded string
 * @param priv : whether it's a private or public key
 **/
void mikey_sakke_provision_key_material_b64(mikey_sakke_key_material_t* keys, const char* identifier, const char* key_name,
                                            const char* key_b64, bool is_private_key);

bool mikey_sakke_validate_signing_keys(const char* identifier, mikey_sakke_key_material_t* keystore);
bool mikey_sakke_validate_signing_keys_old(const char* identifier, size_t identifier_size, mikey_sakke_key_material_t* keystore);

mikey_sakke_user_t* mikey_sakke_alloc_user(char const* uri, mikey_sakke_key_material_t*);
void                mikey_sakke_free_user(mikey_sakke_user_t*);

mikey_sakke_call_t* mikey_sakke_alloc_call(mikey_sakke_user_t*);
void                mikey_sakke_free_call(mikey_sakke_call_t*);

void mikey_sakke_free_key_mgmt_string(mikey_key_mgmt_string_t);

void mikey_sakke_add_sender_stream(mikey_sakke_call_t*, uint32_t ssrc);
void mikey_sakke_set_payload_signature_validation(mikey_sakke_user_t* call, bool valid);

/**
 * Initializes a group session with the provided URI as a target
 * Returns an I_message with group key transport
 * @param call : call context
 * @param to_uri : the receiver of the I-Message
 * @param params : parameters
 * @returns a struct containing the I-Message
 **/
mikey_key_mgmt_string_t mikey_sakke_group_init(mikey_sakke_call_t*, char const* to_uri, struct key_agreement_params* params);
char*                   mikey_sakke_group_init_str(mikey_sakke_call_t*, char const* to_uri, struct key_agreement_params* params);
mikey_key_mgmt_string_t mikey_sakke_uac_init(mikey_sakke_call_t*, char const* to_uri);

/**
 * Authenticates a received i message
 * @param call : the call context
 * @param init : the i message
 * @param URI of the sender
 * @returns true if the message was successfuly authenticated and decrypted, false otherwise
 **/
bool                    mikey_sakke_uas_auth(mikey_sakke_call_t*, mikey_key_mgmt_string_t init, const char* from_uri, const char* from_id);
bool                    mikey_sakke_uas_auth_str(mikey_sakke_call_t*, const char* init_str, const char* from_uri, const char* from_id);
mikey_key_mgmt_string_t mikey_sakke_uas_resp(mikey_sakke_call_t*);
bool                    mikey_sakke_uac_auth(mikey_sakke_call_t*, mikey_key_mgmt_string_t resp);

/**
 * Allocates and generates a key_agreement_params struct with the following parameters
 * @param is_group_call : whether it's a group call or not
 * @param rand_length : the size of the mikey rand
 * @param rand : the mikey rand (as a byte array) that needs to be set in the I_message. Set to NULL if you want a new rand to be used
 * @returns a pointer to a struct containing the specified params
 **/
struct key_agreement_params* key_agreement_params_create(int key_type, size_t key_len, const uint8_t* key, size_t key_id_len,
                                                         const uint8_t* key_id, size_t rand_length, const uint8_t* rand);
/**
 * Allocates and generates a key_agreement_params struct with the following parameters
 * @param is_group_call : whether it's a group call or not
 * @param rand_length : the size of the mikey rand
 * @param rand_b64 : the mikey rand (as a b64 string) that needs to be set in the I_message. Set to NULL if you want a new rand to be used
 * @returns a pointer to a struct containing the specified params
 **/
struct key_agreement_params* key_agreement_params_create_b64(int key_type, const char* key, const char* key_id, const char* rand);

void key_agreement_params_delete(struct key_agreement_params* params);

bool mikey_sakke_call_is_secured(mikey_sakke_call_t*);

uint8_t                      mikey_sakke_get_csid_for_stream(mikey_sakke_call_t*, uint32_t ssrc);
uint8_t*                     mikey_sakke_get_mikey_rand(mikey_sakke_call_t* call, unsigned int* length);
char*                        mikey_sakke_get_mikey_rand_b64(mikey_sakke_call_t* call, unsigned int* output_length);
struct mikey_sakke_key_data* mikey_sakke_get_key_data(mikey_sakke_call_t* call);
void                         mikey_sakke_deriv_dppk_to_dpck(uint8_t* dppk_id, uint8_t* dppk, uint32_t dppk_len, uint8_t* dpck);
void                         mikey_sakke_gen_tek(mikey_sakke_call_t*, uint8_t csid, uint8_t* tek, size_t tek_len);
void                         mikey_sakke_gen_salt(mikey_sakke_call_t*, uint8_t csid, uint8_t* salt, size_t salt_len);
void mikey_sakke_gen_tek2(uint8_t cs_id, uint8_t* csb_id, uint8_t* key, size_t key_len, uint8_t* master_key_out, size_t master_key_len,
                          uint8_t* rand, size_t rand_len);
void mikey_sakke_gen_salt2(uint8_t cs_id, uint8_t* csb_id, uint8_t* key, size_t key_len, uint8_t* master_salt_out, size_t master_salt_len,
                           uint8_t* rand, size_t rand_len);
/**
 * @brief Writes GMK-ID || GUK-ID into the mki variable and its length into mki_len
 * As per TS33.180 §7.4.2
 * @param mki the MKI output, needs to be previously allocated
 * @param mki_len MKI output length
 */
void mikey_sakke_gen_mki(mikey_sakke_call_t* call, uint8_t* mki, size_t* mki_len);

uint8_t* mikey_sakke_gen_guk_id(const char* sender_uri, uint8_t* gmk, size_t gmk_len, uint8_t* gmk_id, size_t gmk_id_len,
                                size_t* guk_id_size);

/* From TS 33.180 §G, the key types (purpose tags) are */
enum {
    GMK   = 0,
    PCK   = 1,
    CSK   = 2,
    SPK   = 3,
    MKFC  = 4,
    MSCCK = 5,
    MuSiK = 6,
    /* Not defined : 7 - 15 */
};

/* From TS 33.180 §E.1.3 the Crypto Session Identifiers (CS-ID) are as follows */
enum {
    INITIATOR_MCPTT_PRIVATE_CALL       = 0,
    RECEIVER_MCPTT_PRIVATE_CALL        = 1,
    INITIATOR_MCVIDEO_PRIVATE_CALL     = 2,
    RECEIVER_MCVIDEO_PRIVATE_CALL      = 3,
    MCPTT_GROUP_CALL                   = 4,
    MCVIDEO_GROUP_CALL                 = 5,
    CSK_SRTCP_PROTECTION_FOR_MCPTT     = 6,
    MuSiK_SRTCP_PROTECTION_FOR_MCPTT   = 7,
    CSK_SRTCP_PROTECTION_FOR_MCVIDEO   = 8,
    MuSiK_SRTCP_PROTECTION_FOR_MCVIDEO = 9,
};
/**
 * Generates a 4 bytes key id of specified type
 */
uint8_t* mikey_sakke_gen_key_id(uint8_t key_type);
char*    mikey_sakke_gen_key_id_b64(uint8_t key_type);

/**
 * Generates a 16 bytes key
 */
uint8_t* mikey_sakke_gen_key(int key_len);
char*    mikey_sakke_gen_key_b64(int key_len);

/**
 * Generates a UID in format 2 as specified in TS 33.180 §F.2.1
 **/
const char* mikey_sakke_gen_user_id_format_2_for_period(const char* uri, const char* kms_uri, uint32_t key_period,
                                                        uint32_t key_period_offset, const uint32_t key_period_no);
const char* mikey_sakke_gen_user_id_format_2(const char* uri, const char* kms_uri, uint32_t key_period, uint32_t key_period_offset);

/**
 * Sets log level
 * Acceptable strings are
 * "trace", "debug", "info", "warning", "error", "critical", "off"
 **/
void mikey_sakke_set_log_level(const char* level_str);
void mikey_sakke_set_log_sink(const char*, size_t);

#ifndef USE_SPDLOG
typedef void(mikey_sakke_log_func_t)(int log_level, const char* filename, unsigned line, const char* function, char* thread_name,
                                     long thread_id, const char* log);
void mikey_sakke_set_log_func(mikey_sakke_log_func_t* func);
#endif // USE_SPDLOG

bool mikey_sakke_is_keyprov_expired(struct kms_key_material_init* init, struct kms_key_material_key_prov* keyprov);
bool mikey_sakke_key_id_from_imessage(mikey_sakke_key_id_t* key_id_to_fill, mikey_key_mgmt_string_t* imessage);

#if __cplusplus
}
#endif

#endif // MIKEYSAKKE4C_H
