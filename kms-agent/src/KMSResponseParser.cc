#include "KMSResponseParser.h"
#include <algorithm>
#include <cctype>
#include <libmutil/Logger.h>
#include <libxml/parser.h>

namespace sw_kms_response_parser {

std::string request_type_to_string(request_type_e type) {
    switch (type) {
        case request_type_e::INIT:
            return "KMS Init";
        case request_type_e::KEY_PROV:
            return "KMS KeyProv";
        default:
            break;
    }
    return "Unsupported request type";
}

OctetString readKeyToOctetString(std::string key) {
    int         len;
    OctetString os;

    // Verify if key is a valid octet string
    if (std::all_of(key.cbegin(), key.cend(), isxdigit)) {
        os = std::move(OctetString::skipws(key));
        return os;
    } else {
        uint8_t* decoded_key = base64_decode(key, &len);
        if (!decoded_key) {
            return {};
        }
        os = OctetString(len, decoded_key);
        delete[] decoded_key;
        return os;
    }
}

bool kmsParseRequestResponse(request_type_e type, const char* ptr, size_t size, struct kms_response* resp, bool is_secured) {
    if (type == request_type_e::INIT) {
        init_response_t* init = dynamic_cast<init_response_t*>(resp);
        if (init != nullptr) {
            return kmsInitParseResponse(ptr, size, init, is_secured);
        }
    } else if (type == request_type_e::KEY_PROV) {
        key_prov_response_t* keyprov = dynamic_cast<key_prov_response_t*>(resp);
        if (keyprov != nullptr) {
            return kmsKeyProvParseResponse(ptr, size, keyprov, is_secured);
        }
    }
    return false;
}

bool kmsParseResponse(xmlNodePtr root_element, struct kms_response* response, bool is_secured) {
    xmlNodePtr chld_resp = nullptr;

    if (is_secured) {
        if (!xmlStrcmp(root_element->name, (const xmlChar*)"SignedKmsResponse")) {
            chld_resp = root_element->xmlChildrenNode;
        } else {
            MIKEY_SAKKE_LOGE("Response parsed as secured but \"SignedKmsResponse\" node not found");
            return false;
        }
    } else {
        chld_resp = root_element;
    }

    if (!xmlStrcmp(chld_resp->name, (const xmlChar*)"KmsResponse")) {
        xmlNodePtr chld = nullptr;
        for (chld = chld_resp->xmlChildrenNode; chld; chld = chld->next) {
            if (chld->type != XML_ELEMENT_NODE) {
                continue;
            }

            if (!xmlStrcmp(chld->name, (const xmlChar*)"UserUri")) {
                response->user_uri = (const char*)chld->xmlChildrenNode->content;
                continue;
            }

            if (!xmlStrcmp(chld->name, (const xmlChar*)"KmsUri")) {
                response->kms_uri = (const char*)chld->xmlChildrenNode->content;
                continue;
            }

            if (!xmlStrcmp(chld->name, (const xmlChar*)"ClientReqUrl")) {
                response->kms_req_url = (const char*)chld->xmlChildrenNode->content;
                continue;
            }

            if (!xmlStrcmp(chld->name, (const xmlChar*)"Time")) {

                std::string time_str = (const char*)chld->xmlChildrenNode->content;
                int         y, M, d, h, m;
                float       s;
                sscanf(time_str.c_str(), "%d-%d-%dT%d:%d:%f", &y, &M, &d, &h, &m, &s);
                tm time;
                memset(&time, 0, sizeof(tm));
                time.tm_year = y - 1900; // Year since 1900
                time.tm_mon  = M - 1;    // 0-11
                time.tm_mday = d;        // 1-31
                time.tm_hour = h;        // 0-23
                time.tm_min  = m;        // 0-59
                time.tm_sec  = (int)s;   // 0-61 (0-60 in C++11)

                response->time = mktime(&time);
                continue;
            }
        }
    }

    if (is_secured) {
        // Parse signature payload
        // Not supported yet
    }

    return true;
}

bool kmsInitParseResponse(const char* ptr, size_t size, init_response_t* resp, bool is_secured) {
    std::string resp_str(ptr, size);
#ifdef SHOW_SECRETS_IN_LOGS_DEV_ONLY
    MIKEY_SAKKE_LOGD("Parsing following as init response : \n%s", resp_str.c_str());
#endif /* SHOW_SECRETS_IN_LOGS_DEV_ONLY */

    xmlDocPtr doc = xmlParseMemory(resp_str.c_str(), resp_str.length());
    if (!doc) {
        MIKEY_SAKKE_LOGE("Could not parse incoming data");
        return false;
    }

    // Parse the common KmsResponse element
    xmlNodePtr root = xmlDocGetRootElement(doc);
    kmsParseResponse(root, resp, is_secured);

    xmlNodePtr chld_resp = nullptr;
    if (is_secured) {
        if (!xmlStrcmp(root->name, (const xmlChar*)"SignedKmsResponse")) {
            chld_resp = root->xmlChildrenNode;
        } else {
            MIKEY_SAKKE_LOGE("Response parsed as secured but \"SignedKmsResponse\" node not found");
            return false;
        }
    } else {
        chld_resp = root;
    }

    if (!xmlStrcmp(chld_resp->name, (const xmlChar*)"KmsResponse")) {
        xmlNodePtr chld = nullptr;
        for (chld = chld_resp->xmlChildrenNode; chld; chld = chld->next) {
            if (chld->type != XML_ELEMENT_NODE) {
                continue;
            }

            if (!xmlStrcmp(chld->name, (const xmlChar*)"KmsMessage")) {
                xmlNodePtr chld_msg = nullptr;
                for (chld_msg = chld->xmlChildrenNode; chld_msg; chld_msg = chld_msg->next) {
                    if (chld_msg->type != XML_ELEMENT_NODE) {
                        continue;
                    }
                    if (!xmlStrcmp(chld_msg->name, (const xmlChar*)"KmsInit")) {
                        xmlNodePtr chld_init = nullptr;
                        for (chld_init = chld_msg->xmlChildrenNode; chld_init; chld_init = chld_init->next) {
                            if (chld_init->type != XML_ELEMENT_NODE) {
                                continue;
                            }
                            if (!xmlStrcmp(chld_init->name, (const xmlChar*)"KmsCertificate")) {
                                xmlNodePtr chld_cert = nullptr;
                                for (chld_cert = chld_init->xmlChildrenNode; chld_cert; chld_cert = chld_cert->next) {
                                    if (chld_cert->type != XML_ELEMENT_NODE) {
                                        continue;
                                    }
                                    if (!xmlStrcmp(chld_cert->name, (const xmlChar*)"UserIdFormat")) {
                                        resp->user_id_format = atoi((const char*)chld_cert->xmlChildrenNode->content);
                                        continue;
                                    }
                                    if (!xmlStrcmp(chld_cert->name, (const xmlChar*)"UserKeyPeriod")) {
                                        resp->user_key_period = atoi((const char*)chld_cert->xmlChildrenNode->content);
                                        continue;
                                    }
                                    if (!xmlStrcmp(chld_cert->name, (const xmlChar*)"UserKeyOffset")) {
                                        resp->user_key_offset = atoi((const char*)chld_cert->xmlChildrenNode->content);
                                        continue;
                                    }
                                    if (!xmlStrcmp(chld_cert->name, (const xmlChar*)"PubEncKey")) {
                                        std::stringstream ss((const char*)chld_cert->xmlChildrenNode->content);
                                        std::string       s;
                                        ss >> s;
                                        resp->pub_enc_key = readKeyToOctetString(s);

                                        continue;
                                    }
                                    if (!xmlStrcmp(chld_cert->name, (const xmlChar*)"PubAuthKey")) {
                                        std::stringstream ss((const char*)chld_cert->xmlChildrenNode->content);
                                        std::string       s;
                                        ss >> s;
                                        resp->pub_auth_key = readKeyToOctetString(s);
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (is_secured) {
        // Parse signature payload
        // Not supported yet
    }

    xmlFreeDoc(doc);
    return true;
}

bool kmsKeyProvParseResponse(const char* ptr, size_t size, key_prov_response_t* resp, bool is_secured) {
    std::string resp_str(ptr, size);
#ifdef SHOW_SECRETS_IN_LOGS_DEV_ONLY
    MIKEY_SAKKE_LOGD("Parsing following as key prov response : \n%s", resp_str.c_str());
#endif /* SHOW_SECRETS_IN_LOGS_DEV_ONLY */

    xmlDocPtr doc = xmlParseMemory(resp_str.c_str(), resp_str.length());
    if (!doc) {
        MIKEY_SAKKE_LOGE("Could not parse incoming data");
        return false;
    }

    // Parse the common KmsResponse element
    xmlNodePtr root = xmlDocGetRootElement(doc);
    kmsParseResponse(root, resp, is_secured);

    xmlNodePtr chld_resp = nullptr;
    if (is_secured) {
        if (!xmlStrcmp(root->name, (const xmlChar*)"SignedKmsResponse")) {
            chld_resp = root->xmlChildrenNode;
        } else {
            MIKEY_SAKKE_LOGE("Response parsed as secured but \"SignedKmsResponse\" node not found");
            return false;
        }
    } else {
        chld_resp = root;
    }

    if (!xmlStrcmp(chld_resp->name, (const xmlChar*)"KmsResponse")) {
        xmlNodePtr chld = nullptr;
        for (chld = chld_resp->xmlChildrenNode; chld; chld = chld->next) {
            if (chld->type != XML_ELEMENT_NODE) {
                continue;
            }

            if (!xmlStrcmp(chld->name, (const xmlChar*)"KmsMessage")) {
                xmlNodePtr chld_msg = nullptr;
                for (chld_msg = chld->xmlChildrenNode; chld_msg; chld_msg = chld_msg->next) {
                    if (chld_msg->type != XML_ELEMENT_NODE) {
                        continue;
                    }
                    if (!xmlStrcmp(chld_msg->name, (const xmlChar*)"KmsKeyProv")) {
                        xmlNodePtr chld_init = nullptr;
                        for (chld_init = chld_msg->xmlChildrenNode; chld_init; chld_init = chld_init->next) {
                            if (chld_init->type != XML_ELEMENT_NODE) {
                                continue;
                            }
                            if (!xmlStrcmp(chld_init->name, (const xmlChar*)"KmsKeySet")) {
                                xmlNodePtr chld_keyset = nullptr;
                                for (chld_keyset = chld_init->xmlChildrenNode; chld_keyset; chld_keyset = chld_keyset->next) {
                                    if (chld_keyset->type != XML_ELEMENT_NODE) {
                                        continue;
                                    }
                                    if (!xmlStrcmp(chld_keyset->name, (const xmlChar*)"UserID")) {
                                        std::stringstream ss((const char*)chld_keyset->xmlChildrenNode->content);
                                        std::string       s;
                                        ss >> s;
                                        resp->user_id = readKeyToOctetString(s);

                                        continue;
                                    }
                                    if (!xmlStrcmp(chld_keyset->name, (const xmlChar*)"KeyPeriodNo")) {
                                        resp->key_period_no = atoi((const char*)chld_keyset->xmlChildrenNode->content);
                                        continue;
                                    }
                                    if (!xmlStrcmp(chld_keyset->name, (const xmlChar*)"UserDecryptKey")) {
                                        std::stringstream ss((const char*)chld_keyset->xmlChildrenNode->content);
                                        std::string       s;
                                        ss >> s;
                                        resp->user_decrypt_key = readKeyToOctetString(s);

                                        continue;
                                    }
                                    if (!xmlStrcmp(chld_keyset->name, (const xmlChar*)"UserSigningKeySSK")) {
                                        std::stringstream ss((const char*)chld_keyset->xmlChildrenNode->content);
                                        std::string       s;
                                        ss >> s;
                                        resp->user_signing_key = readKeyToOctetString(s);
                                        continue;
                                    }
                                    if (!xmlStrcmp(chld_keyset->name, (const xmlChar*)"UserPubTokenPVT")) {
                                        std::stringstream ss((const char*)chld_keyset->xmlChildrenNode->content);
                                        std::string       s;
                                        ss >> s;
                                        resp->user_pub_token = readKeyToOctetString(s);

                                        continue;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (is_secured) {
        // Parse signature payload
        // Not supported yet
    }

    xmlFreeDoc(doc);
    return true;
}

} // namespace sw_kms_response_parser