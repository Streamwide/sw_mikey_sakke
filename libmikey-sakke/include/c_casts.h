#ifndef C_CASTS_H
#define C_CASTS_H

#include <KMClient.h>
#include <libmikey/KeyAgreementSAKKE.h>
#include <libmikey/Mikey.h>
#include <mikeysakke4c.h>

using namespace MikeySakkeKMS;

struct null_deleter {
    void operator()(void const*) const {}
};

inline KeyStoragePtr from_c(mikey_sakke_key_material_t* p) {
    return {reinterpret_cast<KeyStorage*>(p), null_deleter()};
}
inline MRef<IMikeyConfig*> from_c(mikey_sakke_user_t* p) {
    return {reinterpret_cast<IMikeyConfig*>(p)};
}
inline MRef<Mikey*> from_c(mikey_sakke_call_t* p) {
    return {reinterpret_cast<Mikey*>(p)};
}

inline KMClient* from_c(km_client_t* p) {
    return reinterpret_cast<KMClient*>(p);
}

inline mikey_sakke_key_material_t* to_c(KeyStorage* p) {
    return reinterpret_cast<mikey_sakke_key_material_t*>(p);
}
inline mikey_sakke_user_t* to_c(MRef<IMikeyConfig*> const& p) {
    return reinterpret_cast<mikey_sakke_user_t*>(*p);
}
inline mikey_sakke_call_t* to_c(MRef<Mikey*> const& p) {
    return reinterpret_cast<mikey_sakke_call_t*>(*p);
}

inline km_client_t* to_c(KMClient* p) {
    return reinterpret_cast<km_client_t*>(p);
}

inline struct kms_key_material_init* to_c(sw_kms_response_parser::init_response* p) {
    if (!p) {
        return nullptr;
    }

    struct kms_key_material_init* init = nullptr;
    init                               = (struct kms_key_material_init*)malloc(sizeof(struct kms_key_material_init));
    if (!init) {
        return nullptr;
    }

    init->resp = mikey_sakke_kms_response_create();
    if (!init->resp) {
        free(init);
        return nullptr;
    }

    init->resp->user_uri    = strdup(p->user_uri.c_str());
    init->resp->kms_uri     = strdup(p->kms_uri.c_str());
    init->resp->time        = p->time;
    init->resp->kms_req_url = strdup(p->kms_req_url.c_str());
    init->KPAK              = strndup(p->pub_auth_key.translate().c_str(), p->pub_auth_key.translate().size());
    init->Z                 = strndup(p->pub_enc_key.translate().c_str(), p->pub_enc_key.translate().size());
    init->user_id_format    = p->user_id_format;
    init->user_key_period   = p->user_key_period;
    init->user_key_offset   = p->user_key_offset;

    return init;
}

inline struct kms_key_material_key_prov* to_c(sw_kms_response_parser::key_prov_response_t* p) {
    if (!p) {
        return nullptr;
    }

    struct kms_key_material_key_prov* key_prov = nullptr;
    key_prov                                   = (struct kms_key_material_key_prov*)malloc(sizeof(struct kms_key_material_key_prov));
    if (!key_prov) {
        return nullptr;
    }

    key_prov->resp = mikey_sakke_kms_response_create();
    if (!key_prov->resp) {
        free(key_prov);
        return nullptr;
    }

    key_prov->resp->user_uri    = strdup(p->user_uri.c_str());
    key_prov->resp->kms_uri     = strdup(p->kms_uri.c_str());
    key_prov->resp->time        = p->time;
    key_prov->resp->kms_req_url = strdup(p->kms_req_url.c_str());

    key_prov->user_id       = strndup(p->user_id.translate().c_str(), p->user_id.translate().size());
    key_prov->key_period_no = p->key_period_no;
    key_prov->RSK           = strndup(p->user_decrypt_key.translate().c_str(), p->user_decrypt_key.translate().size());
    key_prov->SSK           = strndup(p->user_signing_key.translate().c_str(), p->user_signing_key.translate().size());
    key_prov->PVT           = strndup(p->user_pub_token.translate().c_str(), p->user_pub_token.translate().size());

    return key_prov;
}

inline mikey_key_mgmt_string to_key_mgmt_string(std::string const& s) {
    mikey_key_mgmt_string rc = {(char*)std::malloc(s.length() + 1), s.length()};
    std::memcpy(rc.ptr, s.data(), rc.len);
    rc.ptr[rc.len] = 0;
    return rc;
}

inline std::string from_key_mgmt_string(mikey_key_mgmt_string const& s) {
    return std::string(s.ptr, s.ptr + s.len);
}

#endif