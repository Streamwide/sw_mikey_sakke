#include "c_casts.h"

#include <KMClient.h>
#include <libmcrypto/base64.h>
#include <libmcrypto/rand.h>
#include <libmikey/KeyAgreementSAKKE.h>
#include <libmikey/Mikey.h>
#include <libmutil/Logger.h>
#include <libmutil/Timestamp.h>

#include <map>
#include <memory>

#include <mikeysakke4c.h>
#include <mscrypto/eccsi.h>
#include <mscrypto/sakke.h>
#include <mskms/runtime-key-storage.inl>
#include <test_data.h>
#include <util/printable.inl>

using namespace MikeySakkeKMS;
using namespace MikeySakkeCrypto;

template <typename F, class T>
void kms_destroy(F f_free, T* data) {
    if(data) {
        f_free(data);
    }
}

struct mikey_sakke_kms_response* mikey_sakke_kms_response_create() {
    auto* resp = (struct mikey_sakke_kms_response*)malloc(sizeof(struct mikey_sakke_kms_response));
    if (!resp) {
        return nullptr;
    }
    memset(resp, 0, sizeof(struct mikey_sakke_kms_response));
    return resp;
}

void mikey_sakke_kms_response_destroy(struct mikey_sakke_kms_response* resp) {
    if (resp) {
        kms_destroy(free, resp->kms_req_url);
        kms_destroy(free, resp->kms_uri);
        kms_destroy(free, resp->user_uri);
        free(resp);
    }
}

struct kms_key_material_init* kms_key_material_init_create() {
    auto* init = (struct kms_key_material_init*)malloc(sizeof(struct kms_key_material_init));
    if (!init) {
        return nullptr;
    }
    memset(init, 0, sizeof(struct kms_key_material_init));
    return init;
}

void kms_key_material_init_destroy(struct kms_key_material_init* init) {
    if (init) {
        kms_destroy(free, init->KPAK);
        kms_destroy(free, init->Z);
        kms_destroy(mikey_sakke_kms_response_destroy, init->resp);
        free(init);
    }
}

char* kms_key_material_init_get_user_uri(struct kms_key_material_init* init) {
    if (init && init->resp) {
        return strdup(init->resp->user_uri);
    }
    return nullptr;
}
char* kms_key_material_init_get_kms_uri(struct kms_key_material_init* init) {
    if (init && init->resp) {
        return strdup(init->resp->kms_uri);
    }
    return nullptr;
}
char* kms_key_material_init_get_kpak(struct kms_key_material_init* init) {
    if (init) {
        return strdup(init->KPAK);
    }
    return nullptr;
}
char* kms_key_material_init_get_z(struct kms_key_material_init* init) {
    if (init) {
        return strdup(init->Z);
    }
    return nullptr;
}
char* kms_key_material_init_get_user_id_format(struct kms_key_material_init* init) {
    if (!init) {
        return nullptr;
    }
    int  n = snprintf(nullptr, 0, "%u", init->user_id_format);
    char* buf = (char*)calloc(1, n + 1);
    if (!buf) {
        return nullptr;
    }
    snprintf(buf, n + 1, "%u", init->user_id_format);
    return buf;
}
char* kms_key_material_init_get_user_key_period(struct kms_key_material_init* init) {
    if (!init) {
        return nullptr;
    }
    int  n = snprintf(nullptr, 0, "%u", init->user_key_period);
    char* buf = (char*)calloc(1, n + 1);
    if (!buf) {
        return nullptr;
    }
    snprintf(buf, n + 1, "%u", init->user_key_period);
    return buf;
}
char* kms_key_material_init_get_user_key_offset(struct kms_key_material_init* init) {
    if (!init) {
        return nullptr;
    }
    int  n = snprintf(nullptr, 0, "%u", init->user_key_offset);
    char* buf = (char*)calloc(1, n + 1);
    if (!buf) {
        return nullptr;
    }
    snprintf(buf, n + 1, "%u", init->user_key_offset);
    return buf;
}

struct kms_key_material_key_prov* kms_key_material_key_prov_create() {
    auto* key_prov = (struct kms_key_material_key_prov*)malloc(sizeof(struct kms_key_material_key_prov));
    if (!key_prov) {
        return nullptr;
    }
    memset(key_prov, 0, sizeof(struct kms_key_material_key_prov));
    return key_prov;
}

void kms_key_material_key_prov_destroy(struct kms_key_material_key_prov* key_prov) {
    if (key_prov) {
        kms_destroy(free, key_prov->user_id);
        kms_destroy(free, key_prov->RSK);
        kms_destroy(free, key_prov->SSK);
        kms_destroy(free, key_prov->PVT);
        kms_destroy(mikey_sakke_kms_response_destroy, key_prov->resp);
        free(key_prov);
    }
}

char* kms_key_material_key_prov_get_user_uri(struct kms_key_material_key_prov* key_prov) {
    if (key_prov && key_prov->resp) {
        return strdup(key_prov->resp->user_uri);
    }
    return nullptr;
}
char* kms_key_material_key_prov_get_kms_uri(struct kms_key_material_key_prov* key_prov) {
    if (key_prov && key_prov->resp) {
        return strdup(key_prov->resp->kms_uri);
    }
    return nullptr;
}

char* kms_key_material_key_prov_get_user_id(struct kms_key_material_key_prov* key_prov) {
    if (key_prov) {
        return strdup(key_prov->user_id);
    }
    return nullptr;
}
char* kms_key_material_key_prov_get_key_period_no(struct kms_key_material_key_prov* key_prov) {
    if (!key_prov) {
        return nullptr;
    }
    int  n = snprintf(nullptr, 0, "%u", key_prov->key_period_no);
    char* buf = (char*)calloc(1, n + 1);
    if (!buf) {
        return nullptr;
    }
    snprintf(buf, n + 1, "%u", key_prov->key_period_no);
    return buf;
}
char* kms_key_material_key_prov_get_rsk(struct kms_key_material_key_prov* key_prov) {
    if (key_prov) {
        return strdup(key_prov->RSK);
    }
    return nullptr;
}
char* kms_key_material_key_prov_get_ssk(struct kms_key_material_key_prov* key_prov) {
    if (key_prov) {
        return strdup(key_prov->SSK);
    }
    return nullptr;
}
char* kms_key_material_key_prov_get_pvt(struct kms_key_material_key_prov* key_prov) {
    if (key_prov) {
        return strdup(key_prov->PVT);
    }
    return nullptr;
}

struct mikey_sakke_key_data* mikey_sakke_key_data_create() {
    auto* data = (struct mikey_sakke_key_data*)malloc(sizeof(struct mikey_sakke_key_data));
    if (!data) {
        return nullptr;
    }
    memset(data, 0, sizeof(struct mikey_sakke_key_data));
    return data;
}

void mikey_sakke_key_data_destroy(struct mikey_sakke_key_data* data) {
    kms_destroy(free, data->key);
    kms_destroy(free, data->key_id);
    kms_destroy(free, data->rand);
    kms_destroy(free, data->csb_id);
    free(data);
}

const char* mikey_sakke_key_data_get_key_b64(struct mikey_sakke_key_data* data) {
    return strdup(base64_encode(data->key, data->key_size).c_str());
}
const char* mikey_sakke_key_data_get_key_id_b64(struct mikey_sakke_key_data* data) {
    return strdup(base64_encode(data->key_id, data->key_id_size).c_str());
}
const char* mikey_sakke_key_data_get_rand_b64(struct mikey_sakke_key_data* data) {
    return strdup(base64_encode(data->rand, data->rand_size).c_str());
}

mikey_sakke_key_material_t* mikey_sakke_alloc_sample_key_material_sender(const char* uri, const char* community) {
    return to_c(test_data::make_alice_key_store(std::string(uri), std::string(community)));
}

mikey_sakke_key_material_t* mikey_sakke_alloc_sample_key_material_receiver(const char* uri, const char* community) {
    return to_c(test_data::make_bob_key_store(std::string(uri), std::string(community)));
}

mikey_sakke_key_material_t* mikey_sakke_alloc_key_material(char const* keystore_uri) {
    std::string keystore_uri_str(keystore_uri);
    if (keystore_uri_str == "runtime:empty") {
        return to_c(new RuntimeKeyStorage);
    }
    MIKEY_SAKKE_LOGE("Unsupported keystore URI");
    return nullptr;
}

static void mikey_sakke_kms_request_callback(KMClient* client, mikey_sakke_key_material_t* keys, const struct kms_response* response,
                                             request_type_e type) {
    if (type == request_type_e::INIT) {
        auto resp = dynamic_cast<const init_response_t*>(response);
        if (resp == nullptr) {
            MIKEY_SAKKE_LOGE("Couldn't retrieve response object");
            return;
        }
        std::vector<std::string> const& communities = from_c(keys)->GetCommunityIdentifiers();
        if (communities.empty()) {
            MIKEY_SAKKE_LOGE("No community found, can't write keys");
            return;
        }

        auto keyStorage = from_c(keys);
        keyStorage->StorePublicKey(communities[0], "KPAK", resp->pub_auth_key);
        keyStorage->StorePublicKey(communities[0], "Z", resp->pub_enc_key);

        MIKEY_SAKKE_LOGD("KPAK = %s", resp->pub_auth_key.translate().c_str());

        keyStorage->StorePublicParameter(communities[0], "UserIdFormat", std::to_string(resp->user_id_format));
        keyStorage->StorePublicParameter(communities[0], "UserKeyPeriod", std::to_string(resp->user_key_period));
        keyStorage->StorePublicParameter(communities[0], "UserKeyOffset", std::to_string(resp->user_key_offset));

        // Only Supported Parameter Set
        keyStorage->StorePublicParameter(communities[0], "SakkeSet", "1");
        keyStorage->StorePublicParameter(communities[0], "KmsUri", resp->kms_uri);
        MIKEY_SAKKE_LOGD("Stored public keys for community %s", communities[0].c_str());
    } else if (type == request_type_e::KEY_PROV) {
        auto resp = dynamic_cast<const key_prov_response_t*>(response);
        if (resp == nullptr) {
            MIKEY_SAKKE_LOGE("Couldn't retrieve response object");
            return;
        }
        MIKEY_SAKKE_LOGI("Retrieving keys for KeyPeriodNo %d", resp->key_period_no)
        #ifdef SHOW_SECRETS_IN_LOGS_DEV_ONLY
        MIKEY_SAKKE_LOGD("RSK = %s", resp->user_decrypt_key.translate().c_str());
        MIKEY_SAKKE_LOGD("SSK = %s", resp->user_signing_key.translate().c_str());
        #endif /* SHOW_SECRETS_IN_LOGS_DEV_ONLY */
        MIKEY_SAKKE_LOGD("PVT = %s", resp->user_pub_token.translate().c_str());

        if (keys == nullptr) {
            MIKEY_SAKKE_LOGI("No keystore passed, nowhere to write keys to");
            return;
        }

        client->setUserId(OctetString(resp->user_id));
        auto keyStorage = from_c(keys);
        keyStorage->StorePrivateKey(client->getUserId().translate(), "RSK", resp->user_decrypt_key);
        keyStorage->StorePrivateKey(client->getUserId().translate(), "SSK", resp->user_signing_key);
        keyStorage->StorePublicKey(client->getUserId().translate(), "PVT", resp->user_pub_token);

        MIKEY_SAKKE_LOGD("Stored received keys for user %s", client->getUserId().translate().c_str());
    }
}

km_client_t* mikey_sakke_client_create(const char* kms_uri, bool is_secured, mikey_sakke_key_material_t* keys, uint32_t timeout_ms) {
    std::string uri = "";
    if (kms_uri) {
        uri = std::string {kms_uri};
    }
    auto client = new KMClient(uri, is_secured, keys, mikey_sakke_kms_request_callback, timeout_ms, "");
    return to_c(client);
}

void mikey_sakke_client_destroy(km_client_t* client) {
    delete (from_c(client));
}

void mikey_sakke_client_set_token(km_client_t* client, const char* token) {
    if (client) {
        from_c(client)->setToken(token);
    }
}
void mikey_sakke_client_set_token2(km_client_t* client, const char* token, size_t token_len) {
    if (client) {
        from_c(client)->setToken(std::string(token, token_len));
    }
}

void mikey_sakke_client_set_user_uri(km_client_t* client, const char* user_uri) {
    if (user_uri && client) {
        from_c(client)->setUserUri(user_uri);
    }
    MIKEY_SAKKE_LOGI("User URI set to %s", user_uri);
}

char* mikey_sakke_client_get_user_uri(km_client_t* client) {
    if (client) {
        return strdup(from_c(client)->getUserUri().c_str());
    }
    return nullptr;
}

void mikey_sakke_client_set_kms_uri(km_client_t* client, const char* kms_uri) {
    if (kms_uri && client) {
        from_c(client)->setKmsUri(kms_uri);
    }
}

void mikey_sakke_client_set_security(km_client_t* client, bool security) {
    if (client) {
        from_c(client)->setSecurity(security);
    }
}

void mikey_sakke_client_set_tls_security(km_client_t* client, bool verify_host, bool verify_peer) {
    if (client) {
        from_c(client)->setTlsSecurity(verify_host, verify_peer);
    }
}

void mikey_sakke_client_set_ca_cert_bundle(km_client_t* client, const char* ca_filepath) {
    std::string filepath = "";
    if (ca_filepath) {
        filepath = std::string {ca_filepath};
    }

    if (client) {
        from_c(client)->setCaCertBundle(filepath);
    }
}

void mikey_sakke_client_set_ca_cert_bundle_blob(km_client_t* client, const char* pem_blob) {
#ifdef CURL_BLOB_SUPPORT /* SmartMS 4.3 is based on REHL9 which is limited to libcurl-7.76 however BLOB has been introduced in 7.77 */
    std::string pemblob = "";
    if (pem_blob) {
        pemblob = std::string {pem_blob};
    }

    if (client) {
        from_c(client)->setCaCertBundleBlob(pemblob);
    }
#else
    MIKEY_SAKKE_LOGE("Lib was not compile with Bundle Blob support (lib curl too old), use set_ca_cert_bundle(client, ca_filepath) instead");
#endif
}

void mikey_sakke_client_set_timeout(km_client_t* client, uint32_t timeout) {
    if (client) {
        from_c(client)->setTimeout(timeout);
    }
}

const mikey_sakke_key_material_t* mikey_sakke_client_get_key_store(km_client_t* client) {
    if (client) {
        return from_c(client)->getKeyStore();
    }
    return nullptr;
}

char* mikey_sakke_client_get_user_id(km_client_t* client) {
    if (client) {
        return strdup(from_c(client)->getUserId().translate().c_str());
    }
    return nullptr;
}

int mikey_sakke_fetch_key_material_init(km_client_t* client) {
    if (client == nullptr) {
        return -1;
    }

    auto ret = from_c(client)->sendRequest(request_type_e::INIT, nullptr);
    if (ret == 0) {
        MIKEY_SAKKE_LOGI("KMS Init request sent successfully");
    } else {
        MIKEY_SAKKE_LOGE("KMS Init request could not be sent : curl error %d", ret);
    }
    return ret;
}

struct kms_key_material_init* mikey_sakke_get_key_material_init(km_client_t* client) {
    auto init = from_c(client)->getInitResponse();
    return to_c(init);
}

struct kms_key_material_key_prov* mikey_sakke_get_key_material_key_prov(km_client_t* client) {
    auto key_prov = from_c(client)->getKeyProvResponse();
    return to_c(key_prov);
}

int mikey_sakke_fetch_key_material_key_prov(km_client_t* client) {
    return mikey_sakke_fetch_key_material_key_prov_period(client, 0);
}

int mikey_sakke_fetch_key_material_key_prov_period(km_client_t* client, uint32_t key_period_timestamp_s) {
    if (client == nullptr) {
        return -1;
    }

    request_params_t params {};
    params.requested_key_timestamp = ((uint64_t)key_period_timestamp_s) << 32;

    auto ret = from_c(client)->sendRequest(request_type_e::KEY_PROV, (key_period_timestamp_s ? &params : nullptr));

    if (ret == 0) {
        MIKEY_SAKKE_LOGI("KMS KeyProv request sent successfully");
    } else {
        MIKEY_SAKKE_LOGE("KMS KeyProv request could not be sent : curl error %d", ret);
    }

    return ret;
}

void mikey_sakke_provision_key_material(mikey_sakke_key_material_t* keys, const char* identifier, const char* key_name, const char* key,
                                        bool is_private_key) {
    auto keyStorage = from_c(keys);
    if (is_private_key) {
        keyStorage->StorePrivateKey(identifier, key_name, OctetString::skipws(key));
    } else {
        keyStorage->StorePublicKey(identifier, key_name, OctetString::skipws(key));
    }
}

void mikey_sakke_set_public_parameter(mikey_sakke_key_material_t* keys, const char* identifier, const char* parameter, const char* value) {
    auto keyStorage = from_c(keys);
    keyStorage->StorePublicParameter(identifier, std::string(parameter), std::string(value));
}

const char* mikey_sakke_get_public_parameter(mikey_sakke_key_material_t* keys, const char* community, const char* parameter) {
    auto        keyStorage = from_c(keys);
    std::string value      = keyStorage->GetPublicParameter(community, parameter);
    return strdup(value.c_str());
}

void mikey_sakke_add_community(mikey_sakke_key_material_t* keys, const char* community) {
    if (!keys) {
        return;
    }
    auto keyStorage = from_c(keys);
    keyStorage->AddCommunity(std::string(community));
}

const char* mikey_sakke_get_community(mikey_sakke_key_material_t* keys) {
    if (!keys) {
        return nullptr;
    }
    auto keyStorage  = from_c(keys);
    auto communities = keyStorage->GetCommunityIdentifiers();
    if (communities.empty()) {
        return nullptr;
    }
    return strdup(communities[0].c_str());
}

void mikey_sakke_provision_key_material_bytes(mikey_sakke_key_material_t* keys, const char* identifier, const char* key_name,
                                              const uint8_t* key, size_t key_len, bool is_private_key) {
    auto keyStorage = from_c(keys);
    if (keyStorage == nullptr) {
        return;
    }
    if (is_private_key) {
        keyStorage->StorePrivateKey(identifier, key_name, OctetString(key_len, key));
    } else {
        keyStorage->StorePublicKey(identifier, key_name, OctetString(key_len, key));
    }
}

void mikey_sakke_provision_key_material_b64(mikey_sakke_key_material_t* keys, const char* identifier, const char* key_name,
                                            const char* key_b64, bool is_private_key) {
    MIKEY_SAKKE_LOGD("Storing key %s for %s", key_name, identifier);
    auto keyStorage = from_c(keys);
    if (keyStorage == nullptr) {
        return;
    }

    std::string key_base64(key_b64, strlen(key_b64));
    int         output_len = 0;
    uint8_t*    key        = base64_decode(key_base64, &output_len);

    if (is_private_key) {
        keyStorage->StorePrivateKey(identifier, key_name, OctetString(output_len, key));
    } else {
        keyStorage->StorePublicKey(identifier, key_name, OctetString(output_len, key));
    }
    MIKEY_SAKKE_LOGI("Stored key %s for %s", key_name, identifier);
}

void mikey_sakke_purge_key_material(mikey_sakke_key_material_t* keys) {
    if (keys)
        from_c(keys)->Purge();
}

void mikey_sakke_free_key_material(mikey_sakke_key_material_t* keys) {
    if (keys)
        delete from_c(keys).get();
}

bool mikey_sakke_validate_signing_keys(const char* identifier, mikey_sakke_key_material_t* keystore) {
    KeyStoragePtr keys = from_c(keystore);

    std::vector<std::string> communities = keys->GetCommunityIdentifiers();

    // FIXME: currently assuming only first community in use
    if (communities.empty()) {
        MIKEY_SAKKE_LOGE("Signing parameters incomplete for %s. No communities defined", identifier);
        return false;
    }

    OctetString id = OctetString::skipws(std::string(identifier));
    if (!ValidateSigningKeysAndCacheHS(id, communities[0], keys)) {
        MIKEY_SAKKE_LOGE("Signing keys invalid for %s, keys revoked", id.translate().c_str());
        return false;
    }
    MIKEY_SAKKE_LOGI("Successfuly validated signing keys for %s", id.translate().c_str());

    return true;
}

bool mikey_sakke_validate_signing_keys_old(const char* identifier, size_t identifier_size, mikey_sakke_key_material_t* keystore) {
    KeyStoragePtr keys = from_c(keystore);

    std::vector<std::string> communities = keys->GetCommunityIdentifiers();

    // FIXME: currently assuming only first community in use
    if (communities.empty()) {
        MIKEY_SAKKE_LOGE("Signing parameters incomplete for %s. No communities defined", identifier);
        return false;
    }

    auto id = OctetString(std::string(identifier, identifier_size), OctetString::Untranslated);
    if (!ValidateSigningKeysAndCacheHS(id, communities[0], keys)) {
        MIKEY_SAKKE_LOGE("Signing keys invalid for %s, keys revoked", id.translate().c_str());
        return false;
    }

    return true;
}

mikey_sakke_user_t* mikey_sakke_alloc_user(char const* uri, mikey_sakke_key_material_t* keys) {
    struct MikeyUserConfig : public IMikeyConfig {
        MikeyUserConfig(char const* uri, mikey_sakke_key_material_t* keys): uri(uri), keys(from_c(keys)) {}

        KeyAccessPtr getKeys() const override {
            return keys;
        }

        const std::string getUri() const override {
            return uri;
        }

        size_t getPskLength() const override {
            return 0;
        }
        const uint8_t* getPsk() const override {
            return nullptr;
        }

        bool isMethodEnabled(int method) const override {
            return method == KEY_AGREEMENT_TYPE_SAKKE;
        }

        bool isCertCheckEnabled() const override {
            return false;
        }

        std::string                 uri;
        MikeySakkeKMS::KeyAccessPtr keys;
    };
    MRef<IMikeyConfig*> rc(new MikeyUserConfig(uri, keys));
    rc->incRefCount();
    return to_c(rc);
}

void mikey_sakke_free_user(mikey_sakke_user_t* user) {
    if (user)
        from_c(user)->decRefCount();
}

mikey_sakke_call_t* mikey_sakke_alloc_call(mikey_sakke_user_t* user) {
    MRef<Mikey*> rc(new Mikey(from_c(user)));
    rc->incRefCount();
    return to_c(rc);
}

void mikey_sakke_free_call(mikey_sakke_call_t* call) {
    if (call)
        from_c(call)->decRefCount();
}

void mikey_sakke_free_key_mgmt_string(mikey_key_mgmt_string s) {
    free(s.ptr);
}

void mikey_sakke_add_sender_stream(mikey_sakke_call_t* call, uint32_t ssrc) {
    MIKEY_SAKKE_LOGD("Added sender stream %u", ssrc);
    from_c(call)->addSender(ssrc);
}

mikey_key_mgmt_string mikey_sakke_uac_init(mikey_sakke_call_t* call, char const* to_uri) {
    return to_key_mgmt_string(from_c(call)->initiatorCreate(KEY_AGREEMENT_TYPE_SAKKE, to_uri, nullptr));
}

mikey_key_mgmt_string mikey_sakke_group_init(mikey_sakke_call_t* call, char const* to_uri, struct key_agreement_params* params) {
    return to_key_mgmt_string(from_c(call)->initiatorCreate(KEY_AGREEMENT_TYPE_SAKKE, to_uri, params));
}

char* mikey_sakke_group_init_str(mikey_sakke_call_t* call, char const* to_uri, struct key_agreement_params* params) {
    return strdup(from_c(call)->initiatorCreate(KEY_AGREEMENT_TYPE_SAKKE, to_uri, params).c_str());
}

struct key_agreement_params* key_agreement_params_create(int key_type, size_t key_len, const uint8_t* key, size_t key_id_len,
                                                         const uint8_t* key_id, size_t rand_length, const uint8_t* rand) {
    MIKEY_SAKKE_LOGD("Generating Key params type:\t%d", key_type);
    MIKEY_SAKKE_LOGD("Key length:\t%d", key_len);
    MIKEY_SAKKE_LOGD("Key ID length:\t%d", key_id_len);
    MIKEY_SAKKE_LOGD("Rand length:\t%d", rand_length);
    auto* params = new struct key_agreement_params;

    if (!params) {
        return nullptr;
    }
    params->key_type = key_type;
    if (rand_length > 0 && rand) {
        params->rand_length = rand_length;
        params->rand        = new uint8_t[params->rand_length];
        memcpy(params->rand, rand, params->rand_length);
    } else {
        params->rand_length = 0;
        params->rand        = nullptr;
    }
    if (key_len > 0 && key_id_len > 0 && key && key_id) {
        params->key_len = key_len;
        params->key     = new uint8_t[params->key_len];
        memcpy(params->key, key, params->key_len);

        params->key_id_len = key_id_len;
        params->key_id     = new uint8_t[params->key_id_len];
        memcpy(params->key_id, key_id, params->key_id_len);
    } else {
        if (key_type == CSK) {
            MIKEY_SAKKE_LOGE("Invalid Key Params");
            if (key) {
                OctetString key_os {key_len, key};
                MIKEY_SAKKE_LOGD("Key : %s", key_os.translate().c_str());
            } else {
                MIKEY_SAKKE_LOGE("Invalid Key");
            }
            if (key_id) {
                OctetString key_id_os {key_id_len, key_id};
                MIKEY_SAKKE_LOGD("Key-ID : %s", key_id_os.translate().c_str());
            } else {
                MIKEY_SAKKE_LOGE("Invalid Key-ID");
            }
            if (rand) {
                OctetString rand_os {rand_length, rand};
                MIKEY_SAKKE_LOGD("Rand : %s", rand_os.translate().c_str());
            } else {
                MIKEY_SAKKE_LOGE("Invalid Rand");
            }
            delete params;
            return nullptr;
        }
        params->key_len    = 0;
        params->key        = nullptr;
        params->key_id_len = 0;
        params->key_id     = nullptr;
    }
    MIKEY_SAKKE_LOGD("Created params of type %d", key_type);

    return params;
}

struct key_agreement_params* key_agreement_params_create_b64(int key_type, const char* key, const char* key_id, const char* rand) {
    unsigned int decoded_key_len = 0;
    std::string  key_b64(key);
    auto         key_bytes = base64_decode(key_b64, (int*)&decoded_key_len);

    unsigned int decoded_key_id_len = 0;
    std::string  key_id_b64(key_id);
    auto         key_id_bytes = base64_decode(key_id_b64, (int*)&decoded_key_id_len);

    unsigned int decoded_rand_len = 0;
    std::string  rand_b64(rand);
    auto         rand_bytes = base64_decode(rand_b64, (int*)&decoded_rand_len);

    return key_agreement_params_create(key_type, decoded_key_len, key_bytes, decoded_key_id_len, key_id_bytes, decoded_rand_len,
                                       rand_bytes);
}

void key_agreement_params_delete(struct key_agreement_params* params) {
    delete[] params->rand;
    delete[] params->key;
    delete[] params->key_id;
    delete params;
}

bool mikey_sakke_uas_auth(mikey_sakke_call_t* call, mikey_key_mgmt_string init, char const* from_uri, const char* from_id) {
    MRef<Mikey*> mikey = from_c(call);
    OctetString  id;
    if (from_id) {
        id = OctetString::skipws(from_id);
    }
    if (mikey->responderAuthenticate(from_key_mgmt_string(init), from_uri, id)) {
        mikey->setMikeyOffer();
        return true;
    }

    MIKEY_SAKKE_LOGE("Responder authentication failed from %s", from_uri);
    return false;
}

bool mikey_sakke_uas_auth_str(mikey_sakke_call_t* call, const char* init_str, const char* from_uri, const char* from_id) {
    if (!init_str) {
        return false;
    }
    mikey_key_mgmt_string i_message;
    i_message.len = strlen(init_str);
    i_message.ptr = strdup(init_str);
    auto ret      = mikey_sakke_uas_auth(call, i_message, from_uri, from_id);
    mikey_sakke_free_key_mgmt_string(i_message);
    return ret;
}

mikey_key_mgmt_string mikey_sakke_uas_resp(mikey_sakke_call_t* call) {
    MRef<Mikey*> mikey        = from_c(call);
    std::string  resp_payload = mikey->responderParse();
    if (mikey->error()) {
        mikey_key_mgmt_string error = {nullptr, 0};
        return error;
    }
    return to_key_mgmt_string("mikey " + resp_payload);
}

bool mikey_sakke_uac_auth(mikey_sakke_call_t* call, mikey_key_mgmt_string resp) {
    MRef<Mikey*> mikey = from_c(call);
    if (mikey->initiatorAuthenticate(from_key_mgmt_string(resp))) {
        return mikey->initiatorParse().empty();
    }
    MIKEY_SAKKE_LOGE("Initiator authentication failed.");
    return false;
}

bool mikey_sakke_call_is_secured(mikey_sakke_call_t* call) {
    return from_c(call)->isSecured();
}

uint8_t mikey_sakke_get_csid_for_stream(mikey_sakke_call_t* call, uint32_t ssrc) {
    MRef<MikeyCsIdMap*> csIdMap = from_c(call)->getKeyAgreement()->csIdMap();
    if (auto* srtpMap = dynamic_cast<MikeyCsIdMapSrtp*>(*csIdMap))
        return srtpMap->findCsId(ssrc);
    return 0;
}

uint8_t* mikey_sakke_get_mikey_rand(mikey_sakke_call_t* call, unsigned int* length) {
    if (call == nullptr) {
        return nullptr;
    }
    *length    = from_c(call)->getKeyAgreement()->randLength();
    auto* rand = (uint8_t*)malloc(*length * sizeof(uint8_t));
    memcpy(rand, from_c(call)->getKeyAgreement()->rand(), *length);
    return rand;
}

char* mikey_sakke_get_mikey_rand_b64(mikey_sakke_call_t* call, unsigned int* output_length) {
    uint8_t* rand     = mikey_sakke_get_mikey_rand(call, output_length);
    auto     rand_b64 = base64_encode(rand, *output_length);

    *output_length = rand_b64.size();
    return strdup(rand_b64.c_str());
}

struct mikey_sakke_key_data* mikey_sakke_get_key_data(mikey_sakke_call_t* call) {
    if (call == nullptr) {
        MIKEY_SAKKE_LOGE("Invalid Call");
        return nullptr;
    }

    struct mikey_sakke_key_data* ret = mikey_sakke_key_data_create();
    if (ret == nullptr) {
        MIKEY_SAKKE_LOGE("struct init error");
        return nullptr;
    }

    uint32_t       key_id   = 0;
    const size_t   rand_len = from_c(call)->getKeyAgreement()->randLength();
    const uint8_t* rand     = from_c(call)->getKeyAgreement()->rand();
    const uint32_t csb_id   = from_c(call)->getKeyAgreement()->csbId();
    const int      key_type = ((csb_id>>24) & 0xF0) >> 4;

    ret->rand   = (uint8_t*)malloc(rand_len * sizeof(uint8_t));
    ret->key_id = (uint8_t*)malloc(MIKEY_SAKKE_DEFAULT_KEY_ID_SIZE * sizeof(uint8_t));
    ret->csb_id = (uint8_t*)malloc(MIKEY_SAKKE_DEFAULT_KEY_ID_SIZE * sizeof(uint8_t));
    switch (key_type) {
        case GMK:
            MIKEY_SAKKE_LOGI("Retrieve GMK-Data from key agreement");
            ret->key_size = from_c(call)->getKeyAgreement()->tgkLength();
            key_id        = from_c(call)->getKeyAgreement()->tgkId();
            ret->key      = (uint8_t*)malloc(ret->key_size * sizeof(uint8_t));
            memcpy(ret->key, from_c(call)->getKeyAgreement()->tgk(), ret->key_size);
            break;
        case CSK:
            MIKEY_SAKKE_LOGI("Retrieve CSK-Data from key agreement");
            ret->key_size = from_c(call)->getKeyAgreement()->kfcLength();
            key_id        = from_c(call)->getKeyAgreement()->kfcId();
            ret->key      = (uint8_t*)malloc(ret->key_size * sizeof(uint8_t));
            memcpy(ret->key, from_c(call)->getKeyAgreement()->kfc(), ret->key_size);
            break;
        case PCK:
            MIKEY_SAKKE_LOGI("Retrieve PCK-Data from key agreement");
            ret->key_size = from_c(call)->getKeyAgreement()->tgkLength();
            key_id        = from_c(call)->getKeyAgreement()->tgkId();
            ret->key      = (uint8_t*)malloc(ret->key_size * sizeof(uint8_t));
            memcpy(ret->key, from_c(call)->getKeyAgreement()->tgk(), ret->key_size);
            break;
        default:
            MIKEY_SAKKE_LOGE("Unsupported key type");
            return nullptr;
            break;
    }

    memcpy(ret->rand, rand, rand_len);
    ret->rand_size = rand_len;

    ret->key_id_size = MIKEY_SAKKE_DEFAULT_KEY_ID_SIZE;
    ret->csb_id_size = MIKEY_SAKKE_DEFAULT_KEY_ID_SIZE;

    ret->key_id[0] = (key_id >> 24) & 0xFF;
    ret->key_id[1] = (key_id >> 16) & 0xFF;
    ret->key_id[2] = (key_id >> 8) & 0xFF;
    ret->key_id[3] = (key_id)&0xFF;

    ret->csb_id[0] = (csb_id >> 24) & 0xFF;
    ret->csb_id[1] = (csb_id >> 16) & 0xFF;
    ret->csb_id[2] = (csb_id >> 8) & 0xFF;
    ret->csb_id[3] = csb_id & 0xFF;

    MIKEY_SAKKE_LOGD("Successfully retrieved key data");

    return ret;
}

/* Use to derivate a DPCK key (used to encrypt messaging/MCData ciphering) from a DPPK (can be a PCK or a GMK)
** WARNING: "dpck" must be pre-allocated with a size of "dppk_len"
*/
void mikey_sakke_deriv_dppk_to_dpck(uint8_t* dppk_id, uint8_t* dppk, uint32_t dppk_len, uint8_t* dpck) {
    //MIKEY_SAKKE_LOGD("Derivation dppk to dpck, pointer_id: %d -- pointer_key: %p, len_key: %d", dppk_id, dppk, dppk_len);
    OctetString os_dppk_id {MIKEY_SAKKE_DEFAULT_KEY_ID_SIZE, dppk_id};
    OctetString os_dppk {dppk_len, dppk};
    std::vector<uint8_t> ret = MikeySakkeCrypto::DerivateDppkToDpck(os_dppk_id, os_dppk);
    memcpy(dpck, ret.data(), ret.size());
}

void mikey_sakke_gen_tek(mikey_sakke_call_t* call, uint8_t csid, uint8_t* tek, size_t tek_len) {
    from_c(call)->getKeyAgreement()->genTek(csid, tek, tek_len);
}

void mikey_sakke_gen_salt(mikey_sakke_call_t* call, uint8_t csid, uint8_t* salt, size_t salt_len) {
    from_c(call)->getKeyAgreement()->genSalt(csid, salt, salt_len);
}

void mikey_sakke_gen_mki(mikey_sakke_call_t* call, uint8_t* mki, size_t* mki_len) {
    // GMK-ID
    uint32_t tgk_id = from_c(call)->getKeyAgreement()->tgkId();
    uint8_t  gmk_id[MIKEY_SAKKE_DEFAULT_KEY_ID_SIZE];
    gmk_id[0]       = tgk_id >> 24 & 0xFF;
    gmk_id[1]       = tgk_id >> 16 & 0xFF;
    gmk_id[2]       = tgk_id >> 8 & 0xFF;
    gmk_id[3]       = tgk_id & 0xFF;
    auto gmk_id_len = sizeof(from_c(call)->getKeyAgreement()->tgkId());
    memcpy(mki, gmk_id, gmk_id_len);

    // Concat GUK-ID
    uint32_t csb_id = from_c(call)->getKeyAgreement()->csbId();
    uint8_t  guk_id[MIKEY_SAKKE_DEFAULT_KEY_ID_SIZE];
    guk_id[0]       = csb_id >> 24 & 0xFF;
    guk_id[1]       = csb_id >> 16 & 0xFF;
    guk_id[2]       = csb_id >> 8 & 0xFF;
    guk_id[3]       = csb_id & 0xFF;
    auto guk_id_len = sizeof(from_c(call)->getKeyAgreement()->csbId());
    memcpy(mki + gmk_id_len, guk_id, guk_id_len);

    *mki_len = gmk_id_len + guk_id_len;
}

uint8_t* mikey_sakke_gen_guk_id(const char* sender_uri, uint8_t* gmk, size_t gmk_len, uint8_t* gmk_id, size_t gmk_id_len,
                                size_t* guk_id_size) {
    OctetString peerUri {sender_uri, OctetString::Untranslated};
    OctetString gmk_os {gmk_len, gmk};
    OctetString gmk_id_os {gmk_id_len, gmk_id};
    auto        guk_id = GenerateGukId(peerUri, gmk_os, gmk_id_os);

    *guk_id_size = guk_id.size();
    auto* ret    = (uint8_t*)malloc(guk_id.size() * sizeof(uint8_t));
    std::copy(guk_id.cbegin(), guk_id.cend(), ret);
    return ret;
}

void mikey_sakke_gen_tek2(uint8_t cs_id, uint8_t* csb_id, uint8_t* key, size_t key_len, uint8_t* master_key_out, size_t master_key_len,
                          uint8_t* rand, size_t rand_len) {
    KeyAgreement::keyDeriv2(cs_id, csb_id, key, key_len, master_key_out, master_key_len, KEY_DERIV_TEK, rand, rand_len);
}

void mikey_sakke_gen_salt2(uint8_t cs_id, uint8_t* csb_id, uint8_t* key, size_t key_len, uint8_t* master_salt_out, size_t master_salt_len,
                           uint8_t* rand, size_t rand_len) {
    KeyAgreement::keyDeriv2(cs_id, csb_id, key, key_len, master_salt_out, master_salt_len, KEY_DERIV_SALT, rand, rand_len);
}

uint8_t* mikey_sakke_gen_key(int len) {
    uint8_t* key = nullptr;
    key          = (uint8_t*)malloc(len);

    Rand::randomize(key, len);

    return key;
}

char* mikey_sakke_gen_key_b64(int len) {
    uint8_t*    key     = mikey_sakke_gen_key(len);
    std::string key_b64 = base64_encode(key, len);
    free(key);
    return strdup(key_b64.c_str());
}

uint8_t* mikey_sakke_gen_key_id(uint8_t key_type) {
    if (key_type > 15) {
        return nullptr;
    }
    uint8_t* id = nullptr;
    id          = (uint8_t*)malloc(MIKEY_SAKKE_DEFAULT_KEY_ID_SIZE);

    Rand::randomize(id, MIKEY_SAKKE_DEFAULT_KEY_ID_SIZE);
    id[0] &= 0x0F;
    id[0] |= (key_type << 4);

    return id;
}
char* mikey_sakke_gen_key_id_b64(uint8_t key_type) {
    uint8_t*    key_id     = mikey_sakke_gen_key_id(key_type);
    std::string key_id_b64 = base64_encode(key_id, MIKEY_SAKKE_DEFAULT_KEY_ID_SIZE);
    free(key_id);
    return strdup(key_id_b64.c_str());
}

const char* mikey_sakke_gen_user_id_format_2(const char* uri, const char* kms_uri, uint32_t key_period, uint32_t key_period_offset) {
    OctetString uid;
    uid = genMikeySakkeUid(std::string(uri), std::string(kms_uri), key_period, key_period_offset);

    char* output = strdup(uid.translate().c_str());
    return output;
}

const char* mikey_sakke_gen_user_id_format_2_for_period(const char* uri, const char* kms_uri, uint32_t key_period,
                                                        uint32_t key_period_offset, const uint32_t key_period_no) {
    OctetString uid;
    uid = genMikeySakkeUid(std::string(uri), std::string(kms_uri), key_period, key_period_offset, key_period_no);

    char* output = strdup(uid.translate().c_str());
    return output;
}

void mikey_sakke_set_log_sink([[maybe_unused]] const char* path, [[maybe_unused]] size_t path_len) {
    MIKEY_SAKKE_LOG_SET_SINK(path, path_len);
}

void mikey_sakke_set_log_level(const char* level_str) {
    if (level_str == nullptr) {
        return;
    }
    MIKEY_SAKKE_LOG_SET_LEVEL(level_str);
    MIKEY_SAKKE_LOGI("Set mikey-sakke log level to %s", level_str);
}

#ifndef USE_SPDLOG
void mikey_sakke_set_log_func(mikey_sakke_log_func_t* func) {
    libmutil::mikey_sakke_log_set_func(func);
}
#endif

bool mikey_sakke_is_keyprov_expired(struct kms_key_material_init* init, struct kms_key_material_key_prov* keyprov) {
    if (!init || !keyprov) {
        MIKEY_SAKKE_LOGE("Invalid keys");
        return true;
    }

    auto     now                = libmutil::Timestamp::Get3GPPSecondsNow64();
    uint64_t key_validity_limit = 0;

    key_validity_limit = (keyprov->key_period_no + 1) * init->user_key_period - init->user_key_offset;

    return now >= key_validity_limit;
}

/* Warning: the KEY-ID (which is stored in CSB-ID of the HEADER_PAYLOAD) is only store in clear text
            for the PCK & CSK. Regarding the GMK, the CSB-ID is used to stored the GUK-ID (see 
            end point diversity section in TS-33.180)
*/
bool mikey_sakke_key_id_from_imessage(mikey_sakke_key_id_t* key_id_to_fill, mikey_key_mgmt_string_t* input) {
    /* TODO RBY + ERROR CATCHING*/
    mikey_clear_info_t  ret;


    //input = input;
    key_id_to_fill->key_id_size = 4;
    key_id_to_fill->key_id = (uint8_t*)malloc(key_id_to_fill->key_id_size*sizeof(*key_id_to_fill->key_id));
    Mikey mikey;

    mikey.getClearInfo(from_key_mgmt_string(*input), ret);
    *(key_id_to_fill->key_id) = ret.key_id;
    key_id_to_fill->key_id[0] = ret.key_id >> 24;
    key_id_to_fill->key_id[1] = (ret.key_id & 0xFF0000) >> 16;
    key_id_to_fill->key_id[2] = (ret.key_id & 0xFF00) >> 8;
    key_id_to_fill->key_id[3] = (ret.key_id & 0xFF);

    return true;
}
