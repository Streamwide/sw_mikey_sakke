#ifndef KMSRESPONSEPARSER_HXX
#define KMSRESPONSEPARSER_HXX
#include <libmcrypto/base64.h>
#include <libxml/encoding.h>
#include <map>
#include <memory>
#include <string>
#include <util/octet-string.h>

namespace sw_kms_response_parser {

struct kms_response {
    virtual ~kms_response() = default;
    std::string user_uri;
    std::string kms_uri;
    time_t      time;
    std::string kms_req_url;
};

typedef struct init_response : kms_response {
    uint8_t  user_id_format;
    uint32_t user_key_period;
    uint32_t user_key_offset;

    /* KMS Public encryption key (Zt) */
    OctetString pub_enc_key;
    /* KMS Public Authentication Key (KPAK) */
    OctetString pub_auth_key;
} init_response_t;

/* KMS Key set content : TS 33180 § D.3.3.2 */
typedef struct key_prov_response : kms_response {
    OctetString user_id;
    /* See F.2.2.1 for more information about keyPeriodNo */
    uint32_t key_period_no;
    /* RSK */
    OctetString user_decrypt_key;
    /* SSK */
    OctetString user_signing_key;
    /* PVT */
    OctetString user_pub_token;
} key_prov_response_t;

enum class request_type_e { INIT, KEY_PROV };

std::string request_type_to_string(request_type_e type);

/**
 * Creates an OctetString from a String
 * @param key  : base64 or hex key
 * @returns a non b64-encoded octetstring
 **/
OctetString readKeyToOctetString(std::string key);

/**
 * Attempts to convert the response to a keyprov or a init response according to the type passed as argument and then calls the appropriate parsing function
 * @param type the type of response to parse
 * @param ptr the xml as a string
 * @param size the size of the xml string
 * @param resp the output response object
 * @param is_secured whether the request was secured
 * @returns bool. true on success, false otherwise
 **/
bool kmsParseRequestResponse(request_type_e type, const char* ptr, size_t size, struct kms_response* resp, bool is_secured);
bool kmsInitParseResponse(const char* ptr, size_t size, init_response_t* resp, bool is_secured);
bool kmsKeyProvParseResponse(const char* ptr, size_t size, key_prov_response_t* resp, bool is_secured);

} // namespace sw_kms_response_parser
#endif