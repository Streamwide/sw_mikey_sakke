#include <cstdint>
#include <libmcrypto/rand.h>
#include <libmikey/KeyAgreementSAKKE.h>
#include <libmikey/MikeyException.h>
#include <libmikey/MikeyPayloadGeneralExtension.h>
#include <libmikey/MikeyPayloadHDR.h>
#include <libmikey/MikeyPayloadID.h>
#include <libmikey/MikeyPayloadRAND.h>
#include <libmikey/MikeyPayloadSAKKE.h>
#include <libmikey/MikeyPayloadSIGN.h>
#include <libmikey/MikeyPayloadSP.h>
#include <libmikey/MikeyPayloadT.h>
#include <libmutil/Logger.h>
#include <libmutil/Timestamp.h>

#include <mscrypto/eccsi.h>
#include <mscrypto/hash/sha256.h>
#include <mscrypto/parameter-set.h>
#include <mscrypto/sakke.h>
#include <util/printable.inl>

#include <mskms/key-storage.h>

#include <chrono>
#include <cstring>
#include <utility>

using libmutil::itoa;

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
    Undefined = 99,
};

std::string CanonicalizeUri(std::string const& uri) {
    MIKEY_SAKKE_LOGI("CanonicalizeUri(%s)", uri.c_str());

    char const  e164[] = "+0123456789";
    char const* curi   = uri.c_str();

    // TODO: proper parsing routing here;
    // XXX: for now just find a span of E164 characters preceding an @.
    for (;;) {
        char const* span_begin = curi + std::strcspn(curi, e164);
        if (*span_begin == 0) // no span found
            return uri;
        char const* span_end = span_begin + std::strspn(span_begin, e164);
        if (*span_end == '@')
            return "tel:" + std::string(span_begin, span_end);
        curi = span_end;
    }
    throw MikeyException("CanonicalizeUri: Should not get here.");
    return uri;
}

enum SakkeIdentifierScheme : uint8_t {
    UndefinedSakkeIdentifierScheme        = 0,
    TelURIWithMonthlyKeys                 = 1,
    MikeySakkeUid                         = 2,
    PrivateEndPointAddressWithMonthlyKeys = 240,
};

int getMinimalByteSize(uint64_t number) {
    int i;

    for (i=0; number >> (8*i); i++);

    return i;
}

OctetString genMikeySakkeUid(std::string uri, std::string kms_uri, uint32_t key_period, uint32_t key_period_offset,
                             std::optional<uint32_t> current_key_period_no) {
    MIKEY_SAKKE_LOGD("Generating MikeySakkeUID with the following parameters");
    MIKEY_SAKKE_LOGD("uri:                      %s", uri.c_str());
    MIKEY_SAKKE_LOGD("kms_uri:                  %s", kms_uri.c_str());
    MIKEY_SAKKE_LOGD("key_period:               %zu", key_period);
    MIKEY_SAKKE_LOGD("key_period_offset:        %zu", key_period_offset);
    if (current_key_period_no != std::nullopt) {
        MIKEY_SAKKE_LOGD("current_key_period_no :   %zu", current_key_period_no.value());
    }
    /* As defined in TS 33.180 § F.2.1 */
    OctetString S;
    S.concat(0x00);

    /* P0*/
    const std::string P0 = "MIKEY-SAKKE-UID";
    S.concat(P0, OctetString::Untranslated);
    uint16_t L0 = P0.size();
    S.concat((uint8_t)(L0 >> 8));
    S.concat((uint8_t)(L0 & 0xFF));

    /* P1 */
    S.concat(uri, OctetString::Untranslated);
    uint16_t L1 = uri.size();
    S.concat((uint8_t)(L1 >> 8));
    S.concat((uint8_t)(L1 & 0xFF));

    /* P2 */
    S.concat(kms_uri, OctetString::Untranslated);
    uint16_t L2 = kms_uri.size();
    S.concat((uint8_t)(L2 >> 8));
    S.concat((uint8_t)(L2 & 0xFF));

    /* P3 */
    OctetString P3;
    unsigned    key_period_bytes = getMinimalByteSize((uint64_t)key_period);

    for (unsigned i = 0; i < key_period_bytes; ++i) {
        P3.concat((key_period >> ((key_period_bytes - 1 - i) * 8)) & 0xFF);
    }
    S.concat(P3);

    uint16_t L3 = P3.size();
    S.concat((uint8_t)(L3 >> 8));
    S.concat((uint8_t)(L3 & 0xFF));

    /* P4 */
    /* Find out how many bytes needed to hold P4 */
    unsigned    key_period_offset_bytes = getMinimalByteSize((uint64_t)key_period_offset);
    OctetString P4;
    if (key_period_offset != 0) {
        for (unsigned i = 0; i < key_period_offset_bytes; ++i) {
            P4.concat((key_period_offset >> ((key_period_offset_bytes - 1 - i) * 8)) & 0xFF);
        }
    } else {
        P4.concat(0);
    }

    S.concat(P4);
    uint16_t L4 = P4.size();
    S.concat((uint8_t)(L4 >> 8));
    S.concat((uint8_t)(L4 & 0xFF));

    /* P5
     * if a current_key_period_no was provided, use it
     * if not, use current time to compute current period
     */
    OctetString P5;
    unsigned    P5_bytes = 0;
    uint64_t    P5_int   = 0;
    if (current_key_period_no == std::nullopt) {
        uint64_t now   = libmutil::Timestamp::Get3GPPSecondsNow64();
        P5_int         = (now - key_period_offset) / key_period;
        P5_bytes       = getMinimalByteSize(P5_int);
    } else {
        P5_int   = current_key_period_no.value();
        P5_bytes = 0;

        auto x = P5_int;
        do {
            x >>= 8;
            ++P5_bytes;
        } while (x);
    }

    for (unsigned i = 0; i < P5_bytes; ++i) {
        P5.concat((P5_int >> ((P5_bytes - 1 - i) * 8)) & 0xFF);
    }

    S.concat(P5);
    uint16_t L5 = P5.size();
    S.concat((uint8_t)(L5 >> 8));
    S.concat((uint8_t)(L5 & 0xFF));

    MikeySakkeCrypto::SHA256Digest uid;
    uid.digest(S);
    uid.complete();

    return uid;
}

using namespace MikeySakkeCrypto;
using namespace MikeySakkeKMS;

bool KeyAgreementSAKKE::ValidateKeyMaterial(KeyStoragePtr const& keys, std::string const& identifier, std::string* error_text) {
    bool signing_keys_okay = false;
    bool rsk_okay          = false;

    std::vector<std::string> communities = keys->GetCommunityIdentifiers();

    error_text->clear();

    // FIXME: currently assuming only first community in use
    if (!communities.empty()) {
        try {
            signing_keys_okay = ValidateSigningKeysAndCacheHS(identifier, communities[0], keys);
        } catch (std::exception& e) {
            (*error_text) = e.what();
            (*error_text) += ", ";
            MIKEY_SAKKE_LOGE("ValidateSigningKeysAndCacheHS error: %s", e.what());
        }
        if (signing_keys_okay) {
            MIKEY_SAKKE_LOGI("VALIDATED SIGNING KEYS");
        } else {
            (*error_text) += "Failed validation of signing keys";
            MIKEY_SAKKE_LOGE("FAILED VALIDATION OF SIGNING KEYS");
        }

        try {
            rsk_okay = ValidateReceiverSecretKey(identifier, communities[0], keys);
        } catch (std::exception& e) {
            if (!error_text->empty()) {
                (*error_text) += ", ";
            }
            (*error_text) += e.what();
            MIKEY_SAKKE_LOGE("ValidateReceiverSecretKey error: %s", e.what());
        }

        if (rsk_okay) {
            MIKEY_SAKKE_LOGI("VALIDATED TRANSPORT KEYS");
        } else {
            if (!error_text->empty())
                (*error_text) += ", ";
            (*error_text) += "Failed validation of RSK";
            MIKEY_SAKKE_LOGE("FAILED VALIDATION OF TRANSPORT KEYS");
        }
    }

    MIKEY_SAKKE_LOGI("Communities known to KMS:");

    for (auto& communitie : communities) {
        MIKEY_SAKKE_LOGI("Community:    '%s'", communitie.c_str());
        MIKEY_SAKKE_LOGI("SakkeSet:     %s", keys->GetPublicParameter(communitie, "SakkeSet").c_str());
        MIKEY_SAKKE_LOGI("KPAK:         %s", keys->GetPublicKey(communitie, "KPAK").translate().c_str());
        MIKEY_SAKKE_LOGI("Z:            %s", keys->GetPublicKey(communitie, "Z").translate().c_str());
    }

    return signing_keys_okay && rsk_okay;
}

void KeyAgreementSAKKE::autoDownloadKeys(uint32_t timestampPeriod, OctetString& user_id, uint32_t retries) {
    bool needRetry = false;
    if (kmsClient == nullptr) {
        return;
    }
    if (retries == 0) {
        MIKEY_SAKKE_LOGE("[autoDownloadKeys] Failed to autoDownload keys");
        return;
    }

    kmsClient->resetKeyIndicator();
    std::vector<std::string> const& communities = this->getKeyMaterial()->GetCommunityIdentifiers();
    if (communities.empty()) {
        throw MikeyException("No MIKEY-SAKKE user communities configured.");
    }
    std::string const community = communities[0];

    if (this->getKeyMaterial()->GetPublicParameter(community, "UserKeyPeriod").empty() || this->getKeyMaterial()->GetPublicParameter(community, "UserKeyPeriodOffset").empty()) {
        // Special case where KeyStore was empty at begining (no init)
#ifdef HTTP_REQUEST_BY_CALLBACK
        auto ret = kmsClient->sendRequest(request_type_e::INIT, NULL, NULL, NULL);
#else
        auto ret = kmsClient->sendRequest(request_type_e::INIT, NULL);
#endif
        if (ret == 0) {
            // Check
            MIKEY_SAKKE_LOGD("[autoDownloadKeys] Analyse INIT results...");
            if (kmsClient->getInitResponse() == nullptr) {
                MIKEY_SAKKE_LOGW("[autoDownloadKeys] Failing to parse INIT response ? go retry");
                needRetry = true;
            }
        } else {
            needRetry = true;
        }
    }
    if (this->getKeyMaterial()->GetPrivateKey(user_id.translate(), "SSK").empty() || this->getKeyMaterial()->GetPrivateKey(user_id.translate(), "RSK").empty()) {
        // Execute request to KMS server only if correspond key is not already in KeyStore

        request_params_t params {};
        params.requested_key_timestamp = ((uint64_t)timestampPeriod) << 32;

#ifdef HTTP_REQUEST_BY_CALLBACK
        auto ret = kmsClient->sendRequest(request_type_e::KEY_PROV, &params, NULL, NULL);
#else
        auto ret = kmsClient->sendRequest(request_type_e::KEY_PROV, &params);
#endif
        if (ret == 0) {
            // Check
            MIKEY_SAKKE_LOGD("[autoDownloadKeys] Analyse KEYPROV results...");
            if (kmsClient->getKeyProvResponse() == nullptr) {
                MIKEY_SAKKE_LOGW("[autoDownloadKeys] Failing to parse KEYPROV response ? go retry");
                needRetry = true;
            } else {
                kmsClient->setKeyIndicator();
            }
        } else {
            needRetry = true;
        }
    }
    if (needRetry) {
        return autoDownloadKeys(timestampPeriod, user_id, retries - 1);
    }
}

class MikeyPayloadSAKKE : public MikeyPayload {
  public:
    OctetString           SED;
    OctetString           GUK_ID;
    uint8_t               iana_sakke_params_value;
    SakkeIdentifierScheme id_scheme {MikeySakkeUid};
    int                   key_type;

    std::string debugDump() override {
        std::string ret = "MikeyPayloadSAKKE: next_payload=<" + itoa(nextPayloadType()) + "> ParamsValue=<";
        switch (iana_sakke_params_value) {
            case 1:
                ret += "Parameter Set 1";
                break;
            default:
                ret += "UNKNOWN("+itoa(iana_sakke_params_value)+")";
        }
        ret += "> ID-Scheme=<";
        switch (id_scheme) {
            case TelURIWithMonthlyKeys:
                ret += "TelURIWithMonthlyKeys";
                break;
            case MikeySakkeUid:
                ret += "MikeySakkeUid";
                break;
            case PrivateEndPointAddressWithMonthlyKeys:
                ret += "PrivateEndPointAddressWithMonthlyKeys";
                break;
            default:
                ret += "UNKNOWN("+itoa(id_scheme)+")";
        }
        ret += "> (keyType="+ (key_type==Undefined ? "UNDEFINED" : itoa(key_type)) + ") SED: \n" + std::string(SED.translate().c_str());

        return ret;
    }

    MikeyPayloadSAKKE(KeyAgreementSAKKE* ka, SakkeParameterSet const* params, OctetString const& peerId, std::string const& peerCommunity,
                      KeyAccessPtr const& keyStore, int key_type, OctetString key)
        : iana_sakke_params_value(params->iana_sakke_params_value), key_type(key_type) {
        this->payloadTypeValue = MIKEYPAYLOAD_SAKKE_PAYLOAD_TYPE;

        GenerateSharedSecretAndSED(SED, peerId, peerCommunity, keyStore, key);

        if (key_type == GMK || key_type == PCK) {
            // TGK = Traffic Generating Key (that's why PCK needs to be set as Tgk, even though it is stored in same place)
            ka->setTgk(key.raw(), key.size());
        } else if (key_type == CSK) {
            // KFC = Key For Control signaling
            ka->setKfc(key.raw(), key.size());
        }
        MIKEY_SAKKE_LOGI("Created Sakke payload with SED = %s", SED.translate().c_str());
    }
    MikeyPayloadSAKKE(uint8_t* payload, int limit): MikeyPayload(payload) {
        key_type               = Undefined;
        this->payloadTypeValue = MIKEYPAYLOAD_SAKKE_PAYLOAD_TYPE;

        if (limit < 5)
            throw MikeyExceptionMessageLengthException("Insufficient data in SAKKE payload");

        setNextPayloadType(*payload++);
        iana_sakke_params_value = *payload++;
        id_scheme               = SakkeIdentifierScheme(*payload++);

        size_t SED_len = (+payload[0] << 8) | payload[1];
        payload += 2;
        SED.assign(SED_len, payload);

        endPtr = payload + SED_len;

        MIKEY_SAKKE_LOGD("Read Sakke payload with SED = %s", SED.translate().c_str());
    }

    int length() const override {
        return 5 + SED.size();
    }
    void writeData(uint8_t* data, int len) override {
        if (len != length()) {
            throw MikeyException("MikeyPayloadSAKKE: write unexpected length of bytes");
        }
        std::memset(data, 0, len);

        size_t SED_len = SED.size();

        *data++ = nextPayloadType();
        *data++ = iana_sakke_params_value;
        *data++ = id_scheme;
        *data++ = (uint8_t)((SED_len & 0xFF00) >> 8);
        *data++ = (uint8_t)(SED_len & 0xFF);

        std::memcpy(data, SED.raw(), SED_len);
    }
};

MikeyPayload* CreateIncomingPayloadSAKKE(uint8_t* payload, int limit) {
    return new MikeyPayloadSAKKE(payload, limit);
}

class MikeyMessageSAKKE : public MikeyMessage {
  public:
    MikeyMessageSAKKE() = default;

    MikeyMessageSAKKE(KeyAgreementSAKKE* ka, struct key_agreement_params* params) {
        MIKEY_SAKKE_LOGD("MikeyMessageSAKKE::(ctor) -- outgoing");

        KeyAccessPtr keyStore = ka->getKeyMaterial();

        auto*             tPayload = new MikeyPayloadT();
        MikeyPayloadRAND* randPayload;
        uint32_t          tsNtp = (tPayload->ts() >> 32);

        std::vector<std::string> const& communities = keyStore->GetCommunityIdentifiers();

        if (communities.empty()) {
            throw MikeyException("No MIKEY-SAKKE user communities configured.");
        }

        // TODO: choose community ids appropriately
        std::string const senderCommunity = communities[0];
        std::string const peerCommunity   = senderCommunity;

        if (keyStore->GetPublicParameter(senderCommunity, "UserKeyPeriod").empty()) {
            throw MikeyExceptionKeyStoreEmpty("Keystore not initialized");
        }

        uint32_t    userKeyPeriod = std::stoi(keyStore->GetPublicParameter(senderCommunity, "UserKeyPeriod"));
        uint32_t    userKeyOffset = std::stoi(keyStore->GetPublicParameter(senderCommunity, "UserKeyOffset"));
        std::string kmsUri        = keyStore->GetPublicParameter(senderCommunity, "KmsUri");

        OctetString senderId, peerId;

        // Hack of keyStore to be able to use a key that is not of the current period
        auto keyPeriodNoStr = keyStore->GetPublicParameter(senderCommunity, "UserKeyPeriodNoSet");

        if (keyPeriodNoStr.empty()) {
            // If no particular period number was specified, let it compute the current period no (from )
            senderId = genMikeySakkeUid(ka->uri(), kmsUri, userKeyPeriod, userKeyOffset, (tsNtp - userKeyOffset) / userKeyPeriod);
            peerId   = genMikeySakkeUid(ka->peerUri(), kmsUri, userKeyPeriod, userKeyOffset, (tsNtp - userKeyOffset) / userKeyPeriod);
        } else {
            // Otherwise, use the specified period no
            uint32_t keyPeriodNo = std::stoi(keyPeriodNoStr);
            if (keyPeriodNo != ((tsNtp - userKeyOffset) / userKeyPeriod)) {
                MIKEY_SAKKE_LOGW("UserKeyPeriodNo(%zu) of KeyMaterial does not match creation date of PayloadT calculated PeriodNo(%zu), continuing at your own risk...", keyPeriodNo, (tsNtp - userKeyOffset) / userKeyPeriod);
            }
            senderId             = genMikeySakkeUid(ka->uri(), kmsUri, userKeyPeriod, userKeyOffset, keyPeriodNo);
            peerId               = genMikeySakkeUid(ka->peerUri(), kmsUri, userKeyPeriod, userKeyOffset, keyPeriodNo);
        }

        MIKEY_SAKKE_LOGD("Sender URI : %s", ka->uri().c_str());
        MIKEY_SAKKE_LOGD("Sender ID : %s", senderId.translate().c_str());
        MIKEY_SAKKE_LOGD("Peer URI : %s", ka->peerUri().c_str());
        MIKEY_SAKKE_LOGD("Peer ID : %s", peerId.translate().c_str());

        uint32_t csbId = 0;
        OctetString mki;
        libmutil::MRef<MikeyCsIdMap*> csIdMap;
        if (params && params->key_type == GMK) {
            OctetString gmk {params->key_len, params->key};
            OctetString gmkId {params->key_id_len, params->key_id};
            auto        gukId = GenerateGukId(OctetString(ka->peerUri(), OctetString::Untranslated), gmk, gmkId);
            if (gukId.empty()) {
                MIKEY_SAKKE_LOGE("Error : could not generate GUK-ID");
            } else {
                csbId = gukId[0] << 24 | gukId[1] << 16 | gukId[2] << 8 | gukId[3];
                ka->setCsbId(csbId);
                MIKEY_SAKKE_LOGI("Setting CsbID = GUK-ID = %u", csbId);
            }

            // GMK TS-33.180 $E.2.2 & $E.1.2
            // -> CS-ID=(4 | 5), CS#=1 or 2, ProtType=0, GENERIC-ID #P=1, SessionData=0, SPI=MKI=CsbId
            ka->setCsIdMapType(HDR_CS_ID_MAP_TYPE_GENERIC_ID);
            mki = gmkId;
            mki.concat(gukId);
            uint8_t policyNumberInSP = 0;
            csIdMap = new MikeyCsIdMapGenericId(CS_ID_MCPTT_GROUP_CALL, MIKEY_PROTO_SRTP, false, 1, policyNumberInSP, mki.size(), mki.raw());
            ka->setCsIdMap(csIdMap);
        } else if (params && (params->key_type == CSK || params->key_type == PCK)) {
            csbId |= params->key_id[0] << 24;
            csbId |= (params->key_id[1] << 16) & 0xFF0000;
            csbId |= (params->key_id[2] << 8) & 0xFF00;
            csbId |= (params->key_id[3]) & 0xFF;
            ka->setCsbId(csbId);
            MIKEY_SAKKE_LOGD("Set csbId as 0x%08X", ka->csbId());
            if (params->key_type == CSK) {
                // CSK TS-33.180 $E.4.3 & $E.1.2
                // -> CS-ID=(6 | 8), CS#=1 or 2, ProtType=0, GENERIC-ID #P=1, SessionData=(0 or len for SSRCs not supported yet), SPI=MKI=CsbId
                ka->setCsIdMapType(HDR_CS_ID_MAP_TYPE_GENERIC_ID);
                uint8_t policyNumberInSP = 0;
                csIdMap = new MikeyCsIdMapGenericId(CS_ID_CSK_SRTCP_FOR_MCPTT, MIKEY_PROTO_SRTP, false, 1, policyNumberInSP, params->key_id_len, params->key_id);
                ka->setCsIdMap(csIdMap);
            } else {
                // For PCK: TS-33.180 $E.3.1 & $E.1.2
                // -> CS-ID=0, CS#=0 (no Crypto-Sessions), CS-ID map type=1, CS ID Map Info=0 length
                ka->setCsIdMapType(HDR_CS_ID_MAP_TYPE_EMPTY);
                ka->setCsIdMap(nullptr);
            }
        } else {
            csbId = ka->csbId();
            if (!csbId) {
                Rand::randomize(&csbId, sizeof(csbId));
            }
            ka->setCsIdMapType(HDR_CS_ID_MAP_TYPE_EMPTY);
            ka->setCsIdMap(nullptr);
        }
        ka->setnCs(ka->csIdMap().isNull() ? 0 : ka->csIdMap()->getNumberCs());

        // adding header payload v=0 (TS.33-180  E-1.2)
        addPayload(
            new MikeyPayloadHDR(HDR_DATA_TYPE_SAKKE_INIT, 0, HDR_PRF_MIKEY_256, csbId, ka->nCs(), ka->getCsIdMapType(), ka->csIdMap()));

        // adding timestamp payload
        addPayload(tPayload);

        // adding random payload
        if (params && params->rand) {
            randPayload = new MikeyPayloadRAND(params->rand_length, params->rand);
        } else {
            randPayload = new MikeyPayloadRAND();
        }
        addPayload(randPayload);

        // keep a copy of the random value
        ka->setRand(randPayload->randData(), randPayload->randLength());

        // TODO: support anonymous sender via config
        static constexpr bool anonymousSender = false;

        // for now, include all identifiers
        if (!anonymousSender) {
            addPayload(new MikeyPayloadID(MIKEYPAYLOAD_ID_TYPE_URI, senderId.size(), senderId.raw(), MIKEYPAYLOAD_ID_ROLE_UID_INITIATOR));
        }
        addPayload(new MikeyPayloadID(MIKEYPAYLOAD_ID_TYPE_URI, peerId.size(), peerId.raw(), MIKEYPAYLOAD_ID_ROLE_UID_RESPONDER));
        if (!anonymousSender) {
            addPayload(
                new MikeyPayloadID(MIKEYPAYLOAD_ID_TYPE_URI, kmsUri.size(), (uint8_t*)(kmsUri.c_str()), MIKEYPAYLOAD_ID_ROLE_INITIATOR_KMS));
        }
        addPayload(new MikeyPayloadID(MIKEYPAYLOAD_ID_TYPE_URI, kmsUri.size(), (uint8_t*)(kmsUri.c_str()), MIKEYPAYLOAD_ID_ROLE_RESPONDER_KMS));

        // adding security policy
        addPolicyToPayload(ka);

        // determine sakke parameter set being used
        std::string              sakkeSet    = keyStore->GetPublicParameter(peerCommunity, "SakkeSet");
        SakkeParameterSet const* sakkeParams = &MikeySakkeCrypto::sakke_param_set_1();
        if (sakkeSet != "1")
            throw MikeyException("Currently only SAKKE parameter set '1' is supported.");

        // add SAKKE payload
        if (params) {
            OctetString key {params->key_len, params->key};
            addPayload(new MikeyPayloadSAKKE(ka, sakkeParams, peerId, peerCommunity, keyStore, params->key_type, key));
            KeyParametersPayload::KeyType kt = KeyParametersPayload::KeyType::GMK;

            if (params->key_type == GMK) {
                kt = KeyParametersPayload::KeyType::GMK;
            } else if (params->key_type == CSK) {
                // TODO-RBY: Why the CSK does have a special General Extensions ? Does the TS plan that ?
                kt = KeyParametersPayload::KeyType::CSK;
            } else if (params->key_type == PCK) {
                // TODO-RBY: added for debug purpose (parsing of I_MESSAGE fail on key_size retrieval if not present), but TS does not say
                // we need it
                kt = KeyParametersPayload::KeyType::PCK;
            }

            // Generate the full PayloadGeneralExtensions as 3GPP stands for it: GeneralExtension( MCDataPayload (Encrypted[KeyParams]) )
            auto     keyParam = KeyParametersPayload(kt, KeyParametersPayload::NOT_REVOKED, 0, 0, "");
            uint8_t* keyParamPayload = keyParam.bytes();
            auto     mcData = MikeyMcDataProtected(keyParamPayload, keyParam.length(), key.raw(), csbId);
            uint8_t* mcDataPayload = mcData.bytes();
            addPayload(new MikeyPayloadGeneralExtensions(MIKEYPAYLOAD_GENERALEXTENSIONS_PAYLOAD_TYPE_KEY_PARAMETERS, mcData.length(),
                                                            mcDataPayload));
            delete[] keyParamPayload;
            delete[] mcDataPayload;
        } else {
            throw MikeyException("Invalid Key agreement params");
        }

        if (!anonymousSender) {
            const size_t sig_len = 1 + 4 * eccsi_6509_param_set().hash_len;

            // add SIGN payload
            MikeyPayloadSIGN* sign;
            addPayload(sign = new MikeyPayloadSIGN(sig_len, MIKEYPAYLOAD_SIGN_TYPE_ECCSI));

            bool sign_ok = false;
            try {
                // See RFC-3830 $5.2 Paragraph 3 -> Signature does cover all payload including SIGN minus the signature itself
                // Alea & Softil in their current version does not respect this standard. To sign without SIGN, include:
                // sign_ok = Sign(rawMessageData(), rawMessageLengthAsOutput() - sign->sigLength(), sign->sigData(), sign->sigLength(), senderId,
                sign_ok = Sign(rawMessageData(), rawMessageLengthAsOutput() - sig_len, sign->sigData(), sign->sigLength(), senderId,
                               (bool (*)(void*, size_t))Rand::randomize, keyStore);
            } catch (std::exception& e) {
                MIKEY_SAKKE_LOGE("Sign error : %s", e.what());
            }

            if (sign_ok) {
                MIKEY_SAKKE_LOGI("ECCSI signing SUCCESS");
            } else {
                MIKEY_SAKKE_LOGE("ECCSI signing FAILED");
                throw MikeyException("ECCSI signing failed.");
            }
        }
    }

    bool authenticate(KeyAgreement* kaBase) override {
        MIKEY_SAKKE_LOGD("MikeyMessageSAKKE::authenticate");

        auto* ka = dynamic_cast<KeyAgreementSAKKE*>(kaBase);
        if (!ka) {
            throw MikeyExceptionMessageContent("Not a SAKKE key agreement");
        }

        auto keys = ka->getKeyMaterial();

        std::vector<std::string> const& communities = keys->GetCommunityIdentifiers();

        if (communities.empty()) {
            ka->setAuthError("No MIKEY-SAKKE user communities are known.");
            return false;
        }

        // TODO: choose community ids appropriately

        std::string const responderCommunity = communities[0];
        std::string const senderCommunity    = responderCommunity;
        std::string       UserKeyPeriodStr   = keys->GetPublicParameter(senderCommunity, "UserKeyPeriod");
        std::string       UserKeyOffsetStr   = keys->GetPublicParameter(senderCommunity, "UserKeyOffset");

        if (UserKeyPeriodStr.empty() || UserKeyOffsetStr.empty()) {
            MIKEY_SAKKE_LOGE("Parameters not set, can't proceed with message auth.")
            MIKEY_SAKKE_LOGE("UserKeyPeriod : %s", UserKeyPeriodStr.c_str());
            MIKEY_SAKKE_LOGE("UserKeyOffset : %s", UserKeyOffsetStr.c_str());
            ka->setAuthError("Parameters not set");
            return false;
        }

        uint32_t    userKeyPeriod = std::stoi(UserKeyPeriodStr);
        uint32_t    userKeyOffset = std::stoi(UserKeyOffsetStr);
        std::string kmsUri        = keys->GetPublicParameter(senderCommunity, "KmsUri");

        // keyPeriodNo is infered at KeyAgreement creation & stored in private properties
        OctetString senderId    = genMikeySakkeUid(ka->peerUri(), kmsUri, userKeyPeriod, userKeyOffset, ka->getKeyPeriodNo());
        OctetString responderId = genMikeySakkeUid(ka->uri(), kmsUri, userKeyPeriod, userKeyOffset, ka->getKeyPeriodNo());

        MIKEY_SAKKE_LOGD("Sender URI    : %s", ka->peerUri().c_str());
        MIKEY_SAKKE_LOGD("Sender ID     : %s", senderId.translate().c_str());
        MIKEY_SAKKE_LOGD("Peer URI      : %s", ka->uri().c_str());
        MIKEY_SAKKE_LOGD("Peer ID       : %s", responderId.translate().c_str());
        MIKEY_SAKKE_LOGD("keyPeriodNo   : %d", ka->getKeyPeriodNo());

        ka->autoDownloadKeys(ka->getKeyPeriodNo()*userKeyPeriod+userKeyOffset, responderId, 10);
        if (keys->GetPrivateKey(responderId.translate(), "SSK").empty() || keys->GetPrivateKey(responderId.translate(), "RSK").empty()) {
            MIKEY_SAKKE_LOGE("No KeyMaterial set for keyperiodNo/id: %d/%s", ka->getKeyPeriodNo(), responderId.translate().c_str());
            ka->setAuthError("Wrong KeyMaterials set");
            return false;
        }

        MRef<MikeyPayload*> hdrpl = extractPayload(MIKEYPAYLOAD_HDR_PAYLOAD_TYPE);
        auto*               hdr   = static_cast<MikeyPayloadHDR*>(*hdrpl);

        // SAKKE does not require a verification message.  The response,
        // parsed in parseResponse() below, is purely to update the CS Id map
        // with the SSRCs of the responder's streams.
        if (hdr->dataType() == HDR_DATA_TYPE_SAKKE_RESP)
            return true;

        ka->setnCs(hdr->nCs());
        ka->setCsbId(hdr->csbId());

        if (hdr->csIdMapType() == HDR_CS_ID_MAP_TYPE_SRTP_ID || hdr->csIdMapType() == HDR_CS_ID_MAP_TYPE_GENERIC_ID) {
            ka->setCsIdMap(hdr->csIdMap());
            ka->setCsIdMapType(hdr->csIdMapType());
        }
        // else
        // throw MikeyExceptionMessageContent("SAKKE crypto session id map is not SRTP");

        MRef<MikeyPayload*> randpl = extractPayload(MIKEYPAYLOAD_RAND_PAYLOAD_TYPE);
        if (auto* rand = static_cast<MikeyPayloadRAND*>(*randpl))
            ka->setRand(rand->randData(), rand->randLength());

        MRef<MikeyPayload*> signpl = *lastPayload();
        MikeyPayloadSIGN*   sign   = signpl.isNull() ? nullptr : dynamic_cast<MikeyPayloadSIGN*>(*signpl);

        if (!sign || sign->payloadType() != MIKEYPAYLOAD_SIGN_PAYLOAD_TYPE) {
            // TODO: notify user that SAKKE payload is
            // TODO: not signed by the sender.
            ka->setAuthError("Anonymous sender for MIKEY-SAKKE key agreement is currently unsupported.");
            return false;
        }

        MRef<MikeyPayload*> tpl = extractPayload(MIKEYPAYLOAD_T_PAYLOAD_TYPE);

        if (!tpl)
            throw MikeyExceptionMessageContent("MIKEY-SAKKE message contains no Timestamp payload.");

        // TODO: process any IDR* payloads

        bool verify_ok = false;

        try {
            // In respect of RFC 3380 Sectin 5.2, remove only the signature field, not the full SIGN payload
            verify_ok = Verify(rawMessageData(), rawMessageLength() - sign->sigLength(), sign->sigData(), sign->sigLength(), senderId,
                            senderCommunity, keys);
            if (!verify_ok) {
                // Some implementation (Alea / Softil) sign without the full SIGN payload, let's try again this compat mode
                MIKEY_SAKKE_LOGE("ECCSI signature failed, trying the compatibility mode for third-party implementation...");
                verify_ok = Verify(rawMessageData(), rawMessageLength() - sign->length(), sign->sigData(), sign->sigLength(), senderId,
                    senderCommunity, keys);
            }
        } catch (std::exception& e) {
            MIKEY_SAKKE_LOGE("ECCSI Verify error: %s", e.what());
        }

        if (verify_ok) {
            MIKEY_SAKKE_LOGI("ECCSI signing VERIFIED");
        } else {
            MIKEY_SAKKE_LOGE("ECCSI signing VERIFICATION FAILED");
            ka->setAuthError("MIKEY-SAKKE message signature verification failed.");
            if (kaBase->eccsiSignatureValidation()) {
                return false;
            } else {
                MIKEY_SAKKE_LOGE("[WARNING DANGEROUS] ECCSI signature verification disabled, continuing...");
            }
        }

        sign = nullptr;

        MRef<MikeyPayload*> encrypted = extractPayload(MIKEYPAYLOAD_SAKKE_PAYLOAD_TYPE);
        MikeyPayloadSAKKE*  sakke     = encrypted.isNull() ? nullptr : dynamic_cast<MikeyPayloadSAKKE*>(*encrypted);

        if (!sakke) {
            ka->setAuthError("SAKKE payload not found in MIKEY-SAKKE message.");
            return false;
        }

        OctetString                   SSV;
        OctetString                   KID;
        KeyParametersPayload::KeyType type = KeyParametersPayload::KeyType::GMK;
        try {
            // Use the RAND previously parsed as it must be the same length as SSV output
            SSV = ExtractSharedSecret(sakke->SED, responderId, responderCommunity, keys, ka->randLength());

            if (!SSV.empty()) {
                #ifdef SHOW_SECRETS_IN_LOGS_DEV_ONLY
                MIKEY_SAKKE_LOGD("SAKKE encapsulated data decrypted ; SSV = %s", SSV.translate().c_str());
                #else
                MIKEY_SAKKE_LOGD("SAKKE encapsulated data decrypted");
                #endif /* SHOW_SECRETS_IN_LOGS_DEV_ONLY */
            } else {
                MIKEY_SAKKE_LOGE("SAKKE encapsulated data could not be decrypted");
                ka->setAuthError("Failed to extract TGK from SAKKE payload.");
                return false;
            }


            if (hdr->csbId() && (SSV.size() != 16 && SSV.size() != 32)) {
                MIKEY_SAKKE_LOGE("ERROR: csbID cannot be 0 && SSV size MUST be 16/32B long");
                ka->setAuthError("Failed derivate SSV into DPCK to get keyParameters");
                return false;
            }
            uint8_t csbIdData[4];
            csbIdData[0] = (hdr->csbId() & 0xFF000000) >> 24;
            csbIdData[1] = (hdr->csbId() & 0xFF0000) >> 16;
            csbIdData[2] = (hdr->csbId() & 0xFF00) >> 8;
            csbIdData[3] = (hdr->csbId() & 0xFF);

            OctetString dppkIdOs {4, csbIdData};
            OctetString dppkOs {SSV.size(), SSV.raw()};
            std::vector<uint8_t> dpck = MikeySakkeCrypto::DerivateDppkToDpck(dppkIdOs, dppkOs);
            std::shared_ptr<KeyParametersPayload> param = keyParameters(dpck.data());

            if (param == nullptr) {
                MIKEY_SAKKE_LOGD("No extension, KeyType extracted: 0x%x", ((csbId()>>24) & 0xF0) >> 4);
            }

            // type is by default GMK however KeyType in GeneralExtensions was wrongly encoded in the past
            // so do not trust it until "legacy format" is no more in use
            // Instead, csbId does contains the Key-ID (or GUK-ID) from which we can infer the type

            // Key Properties' payload is optional by TS 33.180 E.4.1 for CSK, then let's determine it through the Key-ID
            if (((csbId()>>24) & 0xF0) >> 4 == CSK) {
                type = KeyParametersPayload::KeyType::CSK;
            }
            if (((csbId()>>24) & 0xF0) >> 4 == PCK) {
                type = KeyParametersPayload::KeyType::PCK;
            }

            if (type == KeyParametersPayload::KeyType::GMK) {
                std::vector<uint8_t> gukId;
                gukId.reserve(4);
                gukId.push_back(csbId() >> 24);
                gukId.push_back((csbId() & 0xFF0000) >> 16);
                gukId.push_back((csbId() & 0xFF00) >> 8);
                gukId.push_back(csbId() & 0xFF);
                OctetString sID(ka->peerUri(), OctetString::Untranslated);
                OctetString pID(ka->uri(), OctetString::Untranslated);
                KID = ExtractGmkId(gukId, pID, SSV);
                MIKEY_SAKKE_LOGI("Extracted GMK-ID = %s", KID.translate().c_str());
                ka->setTgkId(KID);
            } else if (type == KeyParametersPayload::KeyType::CSK) {
                [[maybe_unused]] uint32_t kfc_id = csbId();
                ka->setKfcId(csbId());
            } else if (type == KeyParametersPayload::KeyType::PCK) {
                ka->setTgkId(csbId());
            }

        } catch (std::exception& e) {
            MIKEY_SAKKE_LOGE("ExtractSharedSecret error : %s", e.what());
        }

        if (type == KeyParametersPayload::KeyType::GMK || type == KeyParametersPayload::KeyType::PCK) {
            ka->setTgk(SSV.raw(), SSV.size());
        } else if (type == KeyParametersPayload::KeyType::CSK) {
            ka->setKfc(SSV.raw(), SSV.size());
        }

        return true;
    }

    MRef<MikeyMessage*> buildResponse(KeyAgreement* ka) override {
        MIKEY_SAKKE_LOGD("MikeyMessageSAKKE::buildResponse");

        unsigned int csbId = ka->csbId();
        if (!csbId)
            throw MikeyExceptionUnacceptable("SAKKE response requires that CSB Id is initialized");

        MRef<MikeyMessage*> result = new MikeyMessage();

        result->addPayload(
            new MikeyPayloadHDR(HDR_DATA_TYPE_SAKKE_RESP, 0, HDR_PRF_MIKEY_1, csbId, ka->nCs(), ka->getCsIdMapType(), ka->csIdMap()));

        return result;
    }

    MRef<MikeyMessage*> parseResponse(KeyAgreement* ka) override {
        MIKEY_SAKKE_LOGD("MikeyMessageSAKKE::parseResponse");

        MRef<MikeyPayload*> hdrpl = extractPayload(MIKEYPAYLOAD_HDR_PAYLOAD_TYPE);
        auto*               hdr   = static_cast<MikeyPayloadHDR*>(*hdrpl);

        if (hdr->csbId() != ka->csbId())
            throw MikeyExceptionUnacceptable("SAKKE response header must agree with initiator on CSB Id");

        ka->setnCs(hdr->nCs());

        if (hdr->csIdMapType() == HDR_CS_ID_MAP_TYPE_SRTP_ID) {
            ka->setCsIdMap(hdr->csIdMap());
            ka->setCsIdMapType(hdr->csIdMapType());
        } else
            throw MikeyExceptionMessageContent("SAKKE crypto session id map is not SRTP");

        return 0;
    }

    void setOffer(KeyAgreement* ka) override {
        MIKEY_SAKKE_LOGD("MikeyMessageSAKKE::setOffer");
        addPolicyTo_ka(ka);
    }

    bool isInitiatorMessage() const override {
        return type() == MIKEY_TYPE_SAKKE_INIT;
    }
    bool isResponderMessage() const override {
        return type() == MIKEY_TYPE_SAKKE_RESP;
    }

    int32_t keyAgreementType() const override {
        return KEY_AGREEMENT_TYPE_SAKKE;
    }

    std::shared_ptr<KeyParametersPayload> keyParameters(uint8_t* key) const override {
        auto payload = extractPayload(MIKEYPAYLOAD_GENERALEXTENSIONS_PAYLOAD_TYPE);
        if (payload == nullptr) {
            MIKEY_SAKKE_LOGI("MikeyMessageSAKKE::keyParameters: No GeneralExtension payload, going default");
            return nullptr;
        }

        auto extensionPayload = dynamic_cast<const MikeyPayloadGeneralExtensions*>(*payload);
        if (extensionPayload == nullptr) {
            MIKEY_SAKKE_LOGE("MikeyMessageSAKKE::keyParameters: Impossible cast of GeneralExtension payload, going default");
            return nullptr;
        }
        if (extensionPayload->type != MIKEYPAYLOAD_GENERALEXTENSIONS_PAYLOAD_TYPE_KEY_PARAMETERS) {
            MIKEY_SAKKE_LOGE("MikeyMessageSAKKE::keyParameters: PayloadType is not 3GPP KeyParam, going default");
            return nullptr;
        }
        if (extensionPayload->mcDataProtected == nullptr) {
            MIKEY_SAKKE_LOGI("MikeyMessageSAKKE::keyParameters: MCDataProtectectedPayload is null, going default");
            return nullptr;
        }
        if (key == NULL && extensionPayload->mcDataProtected->isPayloadEncrypted()) {
            MIKEY_SAKKE_LOGI("MikeyMessageSAKKE::keyParameters: KeyParam payload is encrypted, retry once SAKKE is unciphered");
            return nullptr;
        }

        return extensionPayload->mcDataProtected->getKeyParams(key);
    }
};

MikeyMessage* CreateIncomingMessageSAKKE() {
    return new MikeyMessageSAKKE();
}

KeyAgreementSAKKE::KeyAgreementSAKKE(MikeySakkeKMS::KeyAccessPtr keys, KMClient* kmsClientIn, uint32_t keyPeriodNoIn): KeyAgreement(), keys(std::move(keys)) {
    keyPeriodNo = keyPeriodNoIn;
    kmsClient = kmsClientIn;
}

MikeyMessage* KeyAgreementSAKKE::createMessage(struct key_agreement_params* params) {
    return new MikeyMessageSAKKE(this, params);
}

uint32_t KeyAgreementSAKKE::getKeyPeriodNo() {
    return keyPeriodNo;
}

/** sets the TEK Generating Key*/
void KeyAgreementSAKKE::setTgk(uint8_t* tgk, unsigned int tgkLength) {
    OctetString ssv(tgkLength, tgk);
    #ifdef SHOW_SECRETS_IN_LOGS_DEV_ONLY
    MIKEY_SAKKE_LOGD("Using TGK : %s", ssv.translate().c_str());
    #endif /* SHOW_SECRETS_IN_LOGS_DEV_ONLY */
    return KeyAgreement::setTgk(tgk, tgkLength);
}

// Sets the Key for control signalling (KFC)
void KeyAgreementSAKKE::setKfc(uint8_t* kfc, unsigned int kfcLength) {
    OctetString ssv(kfcLength, kfc);
    #ifdef SHOW_SECRETS_IN_LOGS_DEV_ONLY
    MIKEY_SAKKE_LOGD("Using KFC : %s", ssv.translate().c_str());
    #endif /* SHOW_SECRETS_IN_LOGS_DEV_ONLY */
    return KeyAgreement::setKfc(kfc, kfcLength);
}