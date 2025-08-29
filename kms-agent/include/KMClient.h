#ifndef KMCLIENT_HXX
#define KMCLIENT_HXX

#include "KMSResponseParser.h"
#include <condition_variable>
#include <curl/curl.h>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <util/octet-string.h>
#include <vector>

class KMClient;
typedef struct mikey_sakke_key_material mikey_sakke_key_material_t;

using sw_kms_response_parser::init_response_t;
using sw_kms_response_parser::key_prov_response_t;
using sw_kms_response_parser::kms_response;
using sw_kms_response_parser::request_type_e;

typedef std::function<void(KMClient*, mikey_sakke_key_material_t*, const struct kms_response*, request_type_e)> listener_cb_t;

struct received_data {
    char*  response;
    size_t size;
};

struct i_msg {
    std::string i_msg_b64;
    std::string sender_id;
};

struct gmk_data {
    OctetString gmk;
    OctetString gmk_id;
    OctetString rand;
    OctetString guk_id;
};

typedef struct {
    mikey_sakke_key_material_t* keyStore;
    listener_cb_t               callback;
} kms_response_listener_t;

typedef struct req_params {
    std::string user_uri;
    uint64_t    group_id;
    // As specified in §D.2.4 (requested period no * UserKeyPeriod - offset)
    uint64_t requested_key_timestamp;
    // req_params(const std::string& uri, uint64_t g_id): user_uri(uri), group_id(g_id) {}
} request_params_t;

class KMClient {
  public:
    KMClient(std::string server, bool extra_security, mikey_sakke_key_material_t* keys, listener_cb_t cb, uint32_t timeout,
             std::string tok = "");
    ~KMClient();

    bool genSecureRequest(request_type_e type, request_params_t* params);
    int  sendRequest(request_type_e type, request_params_t* params);

    void        setRequestId(const std::string& id);
    void        setClientId(const std::string& id);
    void        setDeviceId(const std::string& id);
    void        setUserUri(const std::string& uri);
    std::string getUserUri() const;
    void        setKmsUri(const std::string& uri);
    std::string getKmsUri() const;
    void        setUserId(const OctetString& os);
    OctetString getUserId() const;
    void        setToken(const std::string& tok);
    void        setSecurity(bool sec);
    void        setTlsSecurity(bool verify_host, bool verify_peer);
    void        setCaCertBundle(const std::string& ca_bundle_filepath);
    void        setCaCertBundleBlob(const std::string& pem_blob);
    void        setTimeout(uint32_t to);

    inline std::string get_xml_request() const {
        return kms_request_xml;
    }

    init_response_t*     getInitResponse() const;
    key_prov_response_t* getKeyProvResponse() const;

    const mikey_sakke_key_material_t* getKeyStore() const;

  private:
    std::string kms_uri;
    long        kms_port;
    bool        enable_tls;
    bool        tls_verify_peer;
    bool        tls_verify_host;
    std::string ca_filepath;
    std::string ca_blob;
    CURL*       curl_handle;
    bool        security;
    uint32_t    timeout_ms;

    std::string kms_request_xml;

    bool        signRequest();
    std::string request_type_to_path_str(request_type_e type);

    kms_response_listener_t kms_response_listener;

    std::string request_id;
    std::string client_id;
    std::string device_id;
    std::string user_uri;
    std::string last_response;
    std::string token;
    OctetString user_id;

    init_response_t*     init_response;
    key_prov_response_t* key_prov_response;

    struct received_data curl_rx_data;

    static size_t curl_callback(char* ptr, size_t size, size_t nmemb, void* userdata);

    bool kms_request_user_callback(request_type_e type, request_params_t* params);
    void inferDataFromUri();
};

#endif