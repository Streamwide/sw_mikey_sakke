#include "KMClient.h"
#include <algorithm>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <libmutil/Logger.h>
#include <libxml/encoding.h>
#include <libxml/xmlwriter.h>
#include <sstream>
#include <thread>
#include <utility>
#ifndef NO_XMLSEC
#include <xmlsec/crypto.h>
#include <xmlsec/xmldsig.h>
#include <xmlsec/xmlsec.h>
#include <xmlsec/xmltree.h>
#endif

static constexpr const char KMS_INIT_PATH[]    = "/keymanagement/identity/v1/init";
static constexpr const char KMS_KEYPROV_PATH[] = "/keymanagement/identity/v1/keyprov";

[[maybe_unused]] static constexpr const char XML_ENCODING[]               = "UTF-8";
[[maybe_unused]] static constexpr const char CANONICALIZATION_ALGORITHM[] = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
[[maybe_unused]] static constexpr const char SIGNATURE_ALGORITHM[]        = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
[[maybe_unused]] static constexpr const char DIGEST_ALGORITHM[]           = "http://www.w3.org/2001/04/xmlenc#sha256";

std::once_flag once;

KMClient::KMClient(std::string server, bool extra_security, mikey_sakke_key_material* keys, listener_cb_t cb, uint32_t timeout,
                   std::string tok)
    : kms_uri(std::move(server)), security(extra_security), timeout_ms(timeout), token(std::move(tok)) {
    curl_handle = curl_easy_init();
    request_id  = "kmsRequest";

    kms_response_listener.callback = cb;
    kms_response_listener.keyStore = keys;

    curl_rx_data = {nullptr, 0};

#ifndef NO_XMLSEC
    if (extra_security) {
        std::call_once(once, []() {
            int err = xmlSecInit();
            if (err < 0) {
                MIKEY_SAKKE_LOGE("Error: xmlsec initialization failed. error code %d", err);
            }
            err = xmlSecCryptoAppInit(nullptr);
            if (err < 0) {
                MIKEY_SAKKE_LOGE("Error: xmlsec initialization failed. error code %d", err);
            }
            err = xmlSecCryptoInit();
            if (err < 0) {
                MIKEY_SAKKE_LOGE("Error: xmlsec initialization failed. error code %d", err);
            }
        });
    }
#endif
    init_response     = nullptr;
    key_prov_response = nullptr;
}

KMClient::~KMClient() {
    free(curl_rx_data.response);
    curl_easy_cleanup(curl_handle);

    // xmlSec is left initialized because if it has been used once,
    // it is very likely to be used again

    if (init_response) {
        delete init_response;
    }
    if (key_prov_response) {
        delete key_prov_response;
    }
}

bool KMClient::genSecureRequest(request_type_e type, [[maybe_unused]] request_params_t* params) {
    int              rc;
    xmlTextWriterPtr writer;
    xmlBufferPtr     buf;

    buf = xmlBufferCreate();
    if (buf == nullptr) {
        return false;
    }

    writer = xmlNewTextWriterMemory(buf, 0);
    if (writer == nullptr) {
        return false;
    }

    rc = xmlTextWriterStartDocument(writer, nullptr, XML_ENCODING, nullptr);
    if (rc < 0) {
        return false;
    }

    {
        // /* Start an element named "SignedKmsRequest" */
        // rc = xmlTextWriterStartElement(writer, BAD_CAST "SignedKmsRequest");
        // if (rc < 0) {
        //     return false;
        // }

        /* Start an element named "KmsRequest" */
        rc = xmlTextWriterStartElement(writer, BAD_CAST "KmsRequest");
        if (rc < 0) {
            return false;
        }

        {
            /* KmsRequest attributes. */
            rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "Id", BAD_CAST request_id.c_str());
            if (rc < 0) {
                return false;
            }
            rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "Version", BAD_CAST "1.0.0");
            if (rc < 0) {
                return false;
            }
            rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "xmlns", BAD_CAST "urn:3gpp:ns:mcsecKMSInterface:1.0");
            if (rc < 0) {
                return false;
            }
            rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "xmlns:ns2", BAD_CAST "urn:3gpp:ns:mcsecKMSKRR:1.0");
            if (rc < 0) {
                return false;
            }
            rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "xmlns:ns3", BAD_CAST "http://www.w3.org/2000/09/xmldsig#");
            if (rc < 0) {
                return false;
            }

            /* UserUri. */
            rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "UserUri", "%s", user_uri.c_str());
            if (rc < 0) {
                return false;
            }

            /* KmsUri. */
            rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "KmsUri", "%s", kms_uri.c_str());
            if (rc < 0) {
                return false;
            }

            /* Time.
               Format is xsd:dateTime (ISO 8601) */
            auto              now  = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            auto              date = std::put_time(std::localtime(&now), "%FT%T");
            std::stringstream ss;
            ss << date;
            rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "Time", "%s", ss.str().c_str());
            if (rc < 0) {
                return false;
            }

            /* ClientId. (optional)*/
            if (!client_id.empty()) {
                rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "ClientId", "%s", client_id.c_str());
                if (rc < 0) {
                    return false;
                }
            }

            /* DeviceId. (optional)*/
            if (!device_id.empty()) {
                rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "DeviceId", "%s", device_id.c_str());
                if (rc < 0) {
                    return false;
                }
            }

            /* ClientReqUrl. */
            std::string tmp = kms_uri + request_type_to_path_str(type);
            rc              = xmlTextWriterWriteFormatElement(writer, BAD_CAST "ClientReqUrl", "%s", tmp.c_str());
            if (rc < 0) {
                return false;
            }

            /* Close KmsRequest */
            rc = xmlTextWriterEndElement(writer);
            if (rc < 0) {
                return false;
            }
        }

        /* Signature payload template
           See : TS 33.180 §9.3.5 Integrity protection using XML signature (xmlsig) */
        /* Start an element named "Signature" */
        // rc = xmlTextWriterStartElement(writer, BAD_CAST "Signature");
        // if (rc < 0) {
        //     return false;
        // }
        // rc = xmlTextWriterWriteAttribute(writer, BAD_CAST "xmlns", BAD_CAST "http://www.w3.org/2000/09/xmldsig#");
        // if (rc < 0) {
        //     return false;
        // }

        // {
        //     /* Start an element named "SignedInfo" */
        //     rc = xmlTextWriterStartElement(writer, BAD_CAST "SignedInfo");
        //     if (rc < 0) {
        //         return false;
        //     }

        //     {
        //         /* CanonicalizationMethod */
        //         rc = xmlTextWriterStartElement(writer, BAD_CAST "CanonicalizationMethod");
        //         if (rc < 0) {
        //             return false;
        //         }

        //         rc = xmlTextWriterWriteFormatAttribute(writer, BAD_CAST "Algorithm", "%s", CANONICALIZATION_ALGORITHM);
        //         if (rc < 0) {
        //             return false;
        //         }

        //         /* Close CanonicalizationMethod */
        //         rc = xmlTextWriterEndElement(writer);
        //         if (rc < 0) {
        //             return false;
        //         }
        //     }

        //     {
        //         /* SignatureMethod */
        //         rc = xmlTextWriterStartElement(writer, BAD_CAST "SignatureMethod");
        //         if (rc < 0) {
        //             return false;
        //         }

        //         rc = xmlTextWriterWriteFormatAttribute(writer, BAD_CAST "Algorithm", "%s", SIGNATURE_ALGORITHM);
        //         if (rc < 0) {
        //             return false;
        //         }

        //         /* Close SignatureMethod */
        //         rc = xmlTextWriterEndElement(writer);
        //         if (rc < 0) {
        //             return false;
        //         }
        //     }

        //     {
        //         /* Reference */
        //         rc = xmlTextWriterStartElement(writer, BAD_CAST "Reference");
        //         if (rc < 0) {
        //             return false;
        //         }

        //         rc = xmlTextWriterWriteFormatAttribute(writer, BAD_CAST "URI", "#%s", request_id.c_str());
        //         if (rc < 0) {
        //             return false;
        //         }

        //         {
        //             /* DigestMethod */
        //             rc = xmlTextWriterStartElement(writer, BAD_CAST "DigestMethod");
        //             if (rc < 0) {
        //                 return false;
        //             }

        //             rc = xmlTextWriterWriteFormatAttribute(writer, BAD_CAST "Algorithm", "%s", DIGEST_ALGORITHM);
        //             if (rc < 0) {
        //                 return false;
        //             }

        //             /* Close DigestMethod */
        //             rc = xmlTextWriterEndElement(writer);
        //             if (rc < 0) {
        //                 return false;
        //             }

        //             // /* DigestValue */
        //             // rc = xmlTextWriterStartElement(writer, BAD_CAST "DigestValue");
        //             // if (rc < 0) {
        //             //     return false;
        //             // }
        //             // /* Close DigestValue */
        //             // rc = xmlTextWriterEndElement(writer);
        //             // if (rc < 0) {
        //             //     return false;
        //             // }

        //             /* Stub digest value */
        //             rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "DigestValue", "nnnn");
        //             if (rc < 0) {
        //                 return false;
        //             }
        //         }

        //         /* Close Reference */
        //         rc = xmlTextWriterEndElement(writer);
        //         if (rc < 0) {
        //             return false;
        //         }
        //     }

        //     /* Close SignedInfo */
        //     rc = xmlTextWriterEndElement(writer);
        //     if (rc < 0) {
        //         return false;
        //     }
        // }

        // // /* SignatureValue */
        // // rc = xmlTextWriterStartElement(writer, BAD_CAST "SignatureValue");
        // // if (rc < 0) {
        // //     return false;
        // // }

        // // /* Close SignatureValue */
        // // rc = xmlTextWriterEndElement(writer);
        // // if (rc < 0) {
        // //     return false;
        // // }

        // /* Stub SignatureValue */
        // rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "SignatureValue", "DEADBEEF");
        // if (rc < 0) {
        //     return false;
        // }

        // {
        //     /* KeyInfo */
        //     rc = xmlTextWriterStartElement(writer, BAD_CAST "KeyInfo");
        //     if (rc < 0) {
        //         return false;
        //     }

        //     // /* KeyName */
        //     // rc = xmlTextWriterStartElement(writer, BAD_CAST "KeyName");
        //     // if (rc < 0) {
        //     //     return false;
        //     // }

        //     // /* Close KeyName */
        //     // rc = xmlTextWriterEndElement(writer);
        //     // if (rc < 0) {
        //     //     return false;
        //     // }

        //     /* Stub KeyName */
        //     rc = xmlTextWriterWriteFormatElement(writer, BAD_CAST "KeyName", "ink.12.user@example.org");
        //     if (rc < 0) {
        //         return false;
        //     }

        //     /* Close KeyInfo */
        //     rc = xmlTextWriterEndElement(writer);
        //     if (rc < 0) {
        //         return false;
        //     }
        // }

        // /* Close Signature */
        // rc = xmlTextWriterEndElement(writer);
        // if (rc < 0) {
        //     return false;
        // }

        // /* Close SignedKmsRequest */
        // rc = xmlTextWriterEndElement(writer);
        // if (rc < 0) {
        //     return false;
        // }
    }

    /* Close Document */
    rc = xmlTextWriterEndDocument(writer);
    if (rc < 0) {
        return false;
    }

    xmlFreeTextWriter(writer);
    kms_request_xml = (const char*)buf->content;
    xmlBufferFree(buf);
    MIKEY_SAKKE_LOGD("Generated the following request \n%s", kms_request_xml.c_str());
    return true;
}

int KMClient::sendRequest(request_type_e type, request_params_t* params) {
    curl_easy_reset(curl_handle);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, &KMClient::curl_callback);

    std::string resource_uri = kms_uri + request_type_to_path_str(type);
    // §D.2.4
    if (type == request_type_e::KEY_PROV) {
        resource_uri += '/' + user_uri;
        if (params && params->requested_key_timestamp != 0) {
            std::stringstream ss;
            ss << std::setfill('0') << std::setw(16) << std::hex << params->requested_key_timestamp;
            resource_uri += "/" + ss.str();
        }
    }
    curl_easy_setopt(curl_handle, CURLOPT_URL, resource_uri.c_str());
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &this->curl_rx_data);
    curl_easy_setopt(curl_handle, CURLOPT_POST, 1);
    curl_easy_setopt(curl_handle, CURLOPT_PORT, 8080L);
    if (!token.empty()) {
        curl_easy_setopt(curl_handle, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);
        curl_easy_setopt(curl_handle, CURLOPT_XOAUTH2_BEARER, token.c_str());
    }
    curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT_MS, timeout_ms);

    // Headers that are sometimes needed
    struct curl_slist* list = nullptr;
    list                    = curl_slist_append(list, "Content-Type: application/xml");
    list                    = curl_slist_append(list, "Accept: application/xml");
    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, list);

    if (!security) {
        curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, 0);
    } else {
        // Add request security TS33180 § D.2.2
        if (!genSecureRequest(type, params)) {
            MIKEY_SAKKE_LOGE("Error during signedkmsrequest update");
            return -1;
        } else {
            if (signRequest()) {
                curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, kms_request_xml.length());
                curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, kms_request_xml.c_str());
                MIKEY_SAKKE_LOGD("Sending request :");
                MIKEY_SAKKE_LOGD("%s", kms_request_xml.c_str());
            } else {
                MIKEY_SAKKE_LOGE("Error during payload signature");
                return -1;
            }
        }
    }

    CURLcode res = curl_easy_perform(curl_handle);
    curl_slist_free_all(list);
    if (res != CURLE_OK) {
        MIKEY_SAKKE_LOGE("Failed to send request to %s: cURL error %d : %s", resource_uri.c_str(), res, curl_easy_strerror(res));
        return (int)res;
    } else {
        MIKEY_SAKKE_LOGI("Request sent successfuly to %s", resource_uri.c_str());
    }

    kms_request_user_callback(type, params);

    return (int)res;
}

bool KMClient::signRequest() {
#ifndef NO_XMLSEC
    xmlDocPtr        doc     = nullptr;
    xmlNodePtr       node    = nullptr;
    xmlSecDSigCtxPtr sig_ctx = nullptr;
    // xmlSecKeyPtr     sec_key_ptr = NULL;

    // load
    doc = xmlParseDoc(BAD_CAST kms_request_xml.c_str());
    if ((doc == nullptr) || (xmlDocGetRootElement(doc) == nullptr)) {
        return false;
    }

    // find signature node
    node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
    if (node == nullptr) {
        return false;
    }

    // create signature context
    sig_ctx = xmlSecDSigCtxCreate(nullptr);
    if (sig_ctx == nullptr) {
        return false;
    }

    // sec_key_ptr = xmlSecKeyCreate();
    // load key
    // sig_ctx->signKey = xmlSecCryptoAppKeyLoadMemory(xpk, 4, xmlSecKeyDataFormatUnknown, NULL, NULL, NULL);
    if (sig_ctx->signKey == nullptr) {
        return false;
    }

    // set keyname
    if (xmlSecKeySetName(sig_ctx->signKey, BAD_CAST "xpk_name_placeholder") < 0) {
        return false;
    }

    // sign
    if (xmlSecDSigCtxSign(sig_ctx, node) < 0) {
        return false;
    }

    /* print signed document to stdout */
    xmlDocDump(stdout, doc);

    /* cleanup */
    if (sig_ctx != nullptr) {
        xmlSecDSigCtxDestroy(sig_ctx);
    }

    if (doc != nullptr) {
        xmlFreeDoc(doc);
    }
#endif
    return true;
}

void KMClient::setRequestId(const std::string& id) {
    request_id = id;
}
void KMClient::setClientId(const std::string& id) {
    client_id = id;
}
void KMClient::setDeviceId(const std::string& id) {
    device_id = id;
}
void KMClient::setUserUri(const std::string& uri) {
    user_uri = uri;
}

std::string KMClient::getUserUri() const {
    return user_uri;
}

void KMClient::setKmsUri(const std::string& uri) {
    kms_uri = uri;
}

std::string KMClient::getKmsUri() const {
    return kms_uri;
}

void KMClient::setUserId(const OctetString& os) {
    user_id.clear();
    user_id.concat(os);
}

OctetString KMClient::getUserId() const {
    return user_id;
}

void KMClient::setToken(const std::string& tok) {
    this->token = tok;
}

void KMClient::setSecurity(bool sec) {
    security = sec;
}

void KMClient::setTimeout(uint32_t to) {
    timeout_ms = to;
}

void KMClient::kms_request_user_callback(request_type_e type, request_params_t* params) {
    MIKEY_SAKKE_LOGI("Received %s response", request_type_to_string(type).c_str());

    long                        http_code = 0;
    mikey_sakke_key_material_t* keys      = kms_response_listener.keyStore;

    curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);

    struct kms_response** response = nullptr;
    if (type == request_type_e::INIT) {
        response = (struct kms_response**)&this->init_response;
    } else if (type == request_type_e::KEY_PROV) {
        response = (struct kms_response**)&this->key_prov_response;
        if (params && params->requested_key_timestamp != 0) {
            // Keys requested for future periods should not be written in keystore
            keys = nullptr;
        }
    }

    if (http_code == 200) {
        if (*response == nullptr) {
            *response = (type == request_type_e::INIT) ? (struct kms_response*)new init_response_t()
                                                       : (struct kms_response*)new key_prov_response_t();
        }
        auto ret = kmsParseRequestResponse(type, curl_rx_data.response, curl_rx_data.size, *response, this->security);
        free(curl_rx_data.response);
        curl_rx_data.response = nullptr;
        curl_rx_data.size     = 0;
        if (!ret) {
            MIKEY_SAKKE_LOGE("Could not parse request response of type %s", request_type_to_string(type).c_str());
            return;
        }
        if (kms_response_listener.callback != nullptr) {
            kms_response_listener.callback(this, keys, *response, type);
        }
    } else {
        MIKEY_SAKKE_LOGE("%s failed, error code %ld", request_type_to_string(type).c_str(), http_code);
        if (*response) {
            delete *response;
            *response = nullptr;
        }
    }
}

size_t KMClient::curl_callback(char* rx_data, size_t size, size_t nmemb, void* userdata) {
    size_t realsize = size * nmemb;
    auto*  rx       = (struct received_data*)userdata;

    char* ptr = (char*)realloc(rx->response, rx->size + realsize + 1);
    if (ptr == nullptr) {
        return 0;
    }
    rx->response = ptr;
    memcpy(&(rx->response[rx->size]), rx_data, realsize);
    rx->size += realsize;
    rx->response[rx->size] = 0;

    return realsize;
}

std::string KMClient::request_type_to_path_str(request_type_e type) {
    switch (type) {
        case request_type_e::INIT:
            return KMS_INIT_PATH;
        case request_type_e::KEY_PROV:
            return KMS_KEYPROV_PATH;
        default:
            return "Unsupported";
    }
}

init_response_t* KMClient::getInitResponse() const {
    return init_response;
}

key_prov_response_t* KMClient::getKeyProvResponse() const {
    return key_prov_response;
}

const mikey_sakke_key_material_t* KMClient::getKeyStore() const {
    return kms_response_listener.keyStore;
}
