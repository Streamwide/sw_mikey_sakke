/*
 Copyright (C) 2004-2007 the Minisip Team

 This library is free software; you can redistribute it and/or
 modify it under the terms of the GNU Lesser General Public
 License as published by the Free Software Foundation; either
 version 2.1 of the License, or (at your option) any later version.

 This library is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 Lesser General Public License for more details.

 You should have received a copy of the GNU Lesser General Public
 License along with this library; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

/* Copyright (C) 2004 - 2007
 *
 * Authors: Erik Eliasson <eliasson@it.kth.se>
 *          Johan Bilien <jobi@via.ecp.fr>
 *	    Joachim Orrblad <joachim@orrblad.com>
 *          Mikael Magnusson <mikma@users.sourceforge.net>
 */

#include <config.h>

#include <libmikey/Mikey.h>

#include <libmutil/Timestamp.h>

#include <libmutil/Logger.h>

#include <libmikey/KeyAgreement.h>
#include <libmikey/KeyAgreementSAKKE.h>
#include <libmikey/MikeyException.h>
#include <libmikey/MikeyMessage.h>
#include <libmikey/MikeyPayloadHDR.h>
#include <libmikey/MikeyPayloadT.h>
#include <libmikey/MikeyPayloadID.h>
#include <mskms/key-storage.h>

#include <inttypes.h>

#ifdef _WIN32_WCE
#include "../include/minisip_wce_extra_includes.h"
#endif

#define MIKEY_PROTO_SRTP 0

/*
 * TODO
 * Cache D-H
 * Add support for initiating Public-Key method
 */

using namespace std;

IMikeyConfig::~IMikeyConfig() = default;

Mikey::Mikey(MRef<IMikeyConfig*> aConfig):  config(aConfig) {
    kmsClient = 0;
}
Mikey::Mikey(): config(nullptr) {
    kmsClient = 0;
}

Mikey::~Mikey() = default;

//DEBUG RBY
//DEBUG RBY
bool Mikey::displayIMessageInfo(const string& message) {
    bool ret = false;

    if (message.substr(0, 6) == "mikey ") {
        string b64Message = message.substr(6, message.length() - 6);

        if (message == "")
            throw MikeyException("No MIKEY message received");
        else {
            try {
                MRef<MikeyMessage*> init_mes = MikeyMessage::parse(b64Message);

                /*  In the future: Re-used the KeyAgreementSAKKE::authenticate() method
                    with a "no key provided" method
                ka->setInitiatorData(init_mes);
                if (init_mes->authenticate(*ka)) {
                    string msg = "Authentication of the MIKEY init message failed: " + ka->authError();
                    throw MikeyExceptionAuthentication(msg.c_str());
                }*/
               string dbgInfo = init_mes->debugDump();
               MIKEY_SAKKE_LOGI("Debug info: %s", dbgInfo.c_str());

                ret = true;
            } catch (MikeyException& exc) {
                MIKEY_SAKKE_LOGE("MikeyException caught: %s", exc.what());
                setState(STATE_ERROR);
            }
        }
    } else {
        MIKEY_SAKKE_LOGE("Unknown type of key agreement");
    }
    return ret;
}

uint32_t Mikey::inferKeyPeriodNo(mikey_clear_info_t* clearInfo, const char* from_uri) {
    MikeySakkeKMS::KeyAccessPtr keyStore = config->getKeys();
    uint32_t periodNoInKeys = 0;
    uint32_t ret = 0;

    // 1. Gather all inputs
    std::vector<std::string> const& communities = keyStore->GetCommunityIdentifiers();

    if (communities.empty()) {
        MIKEY_SAKKE_LOGE("community not configured, cannot validate infer keyPeriodNo");
    }
    std::string const community = (communities.empty() ? "" : communities[0]);

    if (keyStore->GetPublicParameter(community, "UserKeyPeriod").empty()) {
        throw MikeyExceptionKeyStoreEmpty("Keystore not initialized: UserKeyPeriod empty");
    }
    if (keyStore->GetPublicParameter(community, "UserKeyOffset").empty()) {
        throw MikeyExceptionKeyStoreEmpty("Keystore not initialized: UserKeyOffset empty");
    }

    auto periodNoInKeysStr = keyStore->GetPublicParameter(community, "UserKeyPeriodNoSet");
    if (!periodNoInKeysStr.empty()) {
        periodNoInKeys = std::stoi(periodNoInKeysStr);
    }

    uint32_t    userKeyPeriod = std::stoi(keyStore->GetPublicParameter(community, "UserKeyPeriod"));
    uint32_t    userKeyOffset = std::stoi(keyStore->GetPublicParameter(community, "UserKeyOffset"));
    std::string kmsUri        = keyStore->GetPublicParameter(community, "KmsUri");
    if (kmsUri.empty()) {
        throw MikeyException("Keystore not initialized: KmsUri empty");
    }

    // XXX Potential int32 overflow ?
    uint32_t keyPeriodNoFromTimestamp = ((uint64_t)clearInfo->creationTimeNtp + (uint64_t)userKeyOffset) / userKeyPeriod;

    MIKEY_SAKKE_LOGD("[inferKeyPeriodNo] Input are from_uri[%s], to_uri[%s], kms[%s], userKeyPeriod[%d], userKeyPeriodOffset[%d], keyPeriodNoFromTimestamp[%d], periodNoInKeys[%d],\ninitiatorId[%s]\nresponderId[%s]"
        , from_uri, config->getUri().c_str(), kmsUri.c_str(), userKeyPeriod, userKeyOffset, keyPeriodNoFromTimestamp, periodNoInKeys, clearInfo->initiatorId, clearInfo->responderId);
    OctetString initiatorIdCalculated, responderIdCalculated;

    uint32_t periodNoGap = 0;
    for (periodNoGap = 0; periodNoGap < FIND_PERIOD_MAX_GAP; periodNoGap++) {

        for (int sense = 1; sense > -2; sense -= 2) {

            MIKEY_SAKKE_LOGV("[inferKeyPeriodNo] KeyPeriodNoFromTimestamp %d, %d, %d", keyPeriodNoFromTimestamp, periodNoGap, sense);
            if ((sense > 0 || keyPeriodNoFromTimestamp >= periodNoGap) && !(periodNoGap == 0 && sense==-1)) {
                // Verify -x / +x based on the I-MESSAGE creation date
                initiatorIdCalculated   = genMikeySakkeUid(from_uri, kmsUri, userKeyPeriod, userKeyOffset, keyPeriodNoFromTimestamp + periodNoGap * sense);
                responderIdCalculated   = genMikeySakkeUid(config->getUri(), kmsUri, userKeyPeriod, userKeyOffset, keyPeriodNoFromTimestamp + periodNoGap * sense);

                if (strncmp(initiatorIdCalculated.translate().c_str(), clearInfo->initiatorId, MIKEY_SAKKE_UID_LEN) == 0) {
                    MIKEY_SAKKE_LOGD("[inferKeyPeriodNo] Initiator-UID matched with gap=%d and periodNo=%d (current configured one is %d)", periodNoGap, keyPeriodNoFromTimestamp+periodNoGap*sense, periodNoInKeys);
                    if (strncmp(responderIdCalculated.translate().c_str(), clearInfo->responderId, MIKEY_SAKKE_UID_LEN) == 0) {
                        MIKEY_SAKKE_LOGD("[inferKeyPeriodNo] Responder-UID matched with gap=%d and periodNo=%d (current configured one is %d)", periodNoGap, keyPeriodNoFromTimestamp+periodNoGap*sense, periodNoInKeys);
                        ret = keyPeriodNoFromTimestamp+periodNoGap*sense;
                        periodNoGap = FIND_PERIOD_MAX_GAP;
                        break;
                    } else {
                        MIKEY_SAKKE_LOGE("[inferKeyPeriodNo] Unexpected match (initiator-uid does match but not responder-uid) with gap=%d and periodNo=%d (current configured one is %d)", periodNoGap, keyPeriodNoFromTimestamp+periodNoGap, periodNoInKeys);
                    }
                }
            }

            MIKEY_SAKKE_LOGV("[inferKeyPeriodNo] periodNoInKeys %d, %d, %d", periodNoInKeys, periodNoGap, sense);
            if (periodNoInKeys + periodNoGap * sense < keyPeriodNoFromTimestamp - FIND_PERIOD_MAX_GAP || periodNoInKeys + periodNoGap * sense > keyPeriodNoFromTimestamp + FIND_PERIOD_MAX_GAP) {
                // No need to redo the same check when keyPeriodNoFromTimestamp +/- gap already cover the periodNos
                if (periodNoGap < FIND_PERIOD_MAX_GAP && (sense > 0 || periodNoInKeys >= periodNoGap) && !(periodNoGap == 0 && sense==-1)) {
                    // Verify -x / +x based on the I-MESSAGE periodNo set in keyStore
                    initiatorIdCalculated   = genMikeySakkeUid(from_uri, kmsUri, userKeyPeriod, userKeyOffset, periodNoInKeys + periodNoGap * sense);
                    responderIdCalculated   = genMikeySakkeUid(config->getUri(), kmsUri, userKeyPeriod, userKeyOffset, periodNoInKeys + periodNoGap * sense);

                    if (strncmp(initiatorIdCalculated.translate().c_str(), clearInfo->initiatorId, MIKEY_SAKKE_UID_LEN) == 0) {
                        MIKEY_SAKKE_LOGD("[inferKeyPeriodNo] Initiator-UID matched with gap=%d and periodNo=%d (current configured one is %d)", periodNoGap, periodNoInKeys+periodNoGap*sense, periodNoInKeys);
                        if (strncmp(responderIdCalculated.translate().c_str(), clearInfo->responderId, MIKEY_SAKKE_UID_LEN) == 0) {
                            MIKEY_SAKKE_LOGD("[inferKeyPeriodNo] Responder-UID matched with gap=%d and periodNo=%d (current configured one is %d)", periodNoGap, periodNoInKeys+periodNoGap*sense, periodNoInKeys);
                            ret = periodNoInKeys+periodNoGap*sense;
                            periodNoGap = FIND_PERIOD_MAX_GAP;
                            break;
                        } else {
                            MIKEY_SAKKE_LOGE("[inferKeyPeriodNo] Unexpected match (initiator-uid does match but not responder-uid) with gap=%d and periodNo=%d (current configured one is %d)", periodNoGap, periodNoInKeys+periodNoGap, periodNoInKeys);
                        }
                    }
                }
            }
        }
    }
    if (ret == 0 && periodNoGap >= FIND_PERIOD_MAX_GAP) {
        MIKEY_SAKKE_LOGE("[inferKeyPeriodNo] Could not infer correctly keyPeriodNo, back to default (user entry)");
        ret = periodNoInKeys ? periodNoInKeys : keyPeriodNoFromTimestamp;
    }

    return ret;
}

void Mikey::getClearInfo(MRef<MikeyMessage*>& message, mikey_clear_info_t& info) {
    info.initiatorId[0] = '\0';
    info.responderId[0] = '\0';

    // Gather the important informations
    MRef<MikeyPayload*> hdrpl = message->extractPayload(MIKEYPAYLOAD_HDR_PAYLOAD_TYPE);
    auto*               hdr   = static_cast<MikeyPayloadHDR*>(*hdrpl);
    info.key_id               = hdr->csbId(); // This is a GUK-ID in case of a GMK
    MRef<MikeyPayload*> tpl = message->extractPayload(MIKEYPAYLOAD_T_PAYLOAD_TYPE);
    auto*               timestamp   = static_cast<MikeyPayloadT*>(*tpl);
    if (timestamp->tsType() != T_TYPE_NTP_UTC) {
        MIKEY_SAKKE_LOGE("ClearInfo: ERROR on PayloadT, time is not provided in NTP_UTC, periodNo might be affected (but continuing...)");
    }
    info.creationTimeNtp = (timestamp->ts() >> 32);
    if (info.creationTimeNtp < NTP_EPOCH_OFFSET) {
        MIKEY_SAKKE_LOGE("ClearInfo: ERROR on PayloadT, time seems not in NTP format, resetting");
    }

    MRef<MikeyPayload*> initiatorpl = message->extractPayloadIdr(MIKEYPAYLOAD_ID_ROLE_UID_INITIATOR);
    if (initiatorpl.isNull()) {
        initiatorpl = message->extractPayloadIdr(MIKEYPAYLOAD_ID_ROLE_INITIATOR);
    }
    auto*               initiator   = static_cast<MikeyPayloadID*>(*initiatorpl);
    if (initiator->idLength() == 32) {
        OctetString tmp = OctetString {(uint32_t)(initiator->idLength()), initiator->idData()};
        memcpy(info.initiatorId, tmp.translate().c_str(), tmp.size()*2);
        info.initiatorId[64] = '\0';
    }
    MRef<MikeyPayload*> responderpl = message->extractPayloadIdr(MIKEYPAYLOAD_ID_ROLE_UID_RESPONDER);
    if (responderpl.isNull()) {
        responderpl = message->extractPayloadIdr(MIKEYPAYLOAD_ID_ROLE_RESPONDER);
    }
    auto*               responder   = static_cast<MikeyPayloadID*>(*responderpl);
    if (responder->idLength() == 32) {
        OctetString tmp = OctetString {(uint32_t)(responder->idLength()), responder->idData()};
        memcpy(info.responderId, tmp.translate().c_str(), tmp.size()*2);
        info.responderId[64] = '\0';
    }

    // Display for log
    long int seconds = info.creationTimeNtp - NTP_EPOCH_OFFSET;
    char timestr_sec[] = "YYYY-mm-ddTHH:MM:ss.SSSZ";
    std::strftime(timestr_sec, sizeof(timestr_sec) - 1,
                "%Y-%m-%dT%H:%M:%S.000Z", std::gmtime(&seconds) ) ;
    MIKEY_SAKKE_LOGI("ClearInfo: creationTime[%" PRIu64 "] => UNIX [%u], => ISO 8601[%s]", timestamp->ts(), info.creationTimeNtp - NTP_EPOCH_OFFSET, timestr_sec);
}

bool Mikey::getClearInfo(const string& message, mikey_clear_info_t& info) {
    bool ret = false;

    info.initiatorId[0] = '\0';
    info.responderId[0] = '\0';
    if (message.substr(0, 6) == "mikey ") {
        string b64Message = message.substr(6, message.length() - 6);

        if (message == "")
            throw MikeyException("No MIKEY message received");
        else {
            try {
                MRef<MikeyMessage*> init_mes = MikeyMessage::parse(b64Message);
                getClearInfo(init_mes, info);

                ret = true;
            } catch (MikeyException& exc) {
                MIKEY_SAKKE_LOGE("MikeyException caught: %s", exc.what());
                setState(STATE_ERROR);
            }
        }
    } else {
        MIKEY_SAKKE_LOGE("Unknown type of key agreement");
    }
    return ret;
}

bool Mikey::responderAuthenticate(const string& message, const string& peerUri, const OctetString& peerId) {

    setState(STATE_RESPONDER);

    if (message.substr(0, 6) == "mikey ") {

        string b64Message = message.substr(6, message.length() - 6);

        if (message == "")
            throw MikeyException("No MIKEY message received");
        else {
            try {
                MRef<MikeyMessage*> init_mes = MikeyMessage::parse(b64Message);
                uint32_t keyPeriodNo = 0;
                if (init_mes->keyAgreementType() == KEY_AGREEMENT_TYPE_SAKKE) {
                    mikey_clear_info_t info;
                    Mikey::getClearInfo(init_mes, info);
                    try {
                        keyPeriodNo = inferKeyPeriodNo(&info, peerUri.c_str());
                    } catch(MikeyExceptionKeyStoreEmpty& exc) {
                        MIKEY_SAKKE_LOGW("MikeyExceptionKeyStoreEmpty caught: %s", exc.what());
                        // Handle case when no KeyMaterial was set, then UID cannot be calculated
                        KeyAgreementSAKKE* tmp = new KeyAgreementSAKKE(config->getKeys(), kmsClient, keyPeriodNo);
                        OctetString none = OctetString{0, (uint8_t const*)""};
                        MIKEY_SAKKE_LOGW("Try to autoDownload keys as KeyStore is empty...");
                        tmp->autoDownloadKeys(0, none, 10);
                        // HACK but required, as Mikey must be created, normally, only when KMClient->userUri is set, but not always the case
                        config->setUri(kmsClient->getUserUri());
                        keyPeriodNo = inferKeyPeriodNo(&info, peerUri.c_str());
                        MIKEY_SAKKE_LOGW("Last chance of getting KeyPeriodNo right: %d", keyPeriodNo);
                        delete(tmp);
                    }
                }
                createKeyAgreement(init_mes->keyAgreementType(), keyPeriodNo);
                if (!ka) {
                    throw MikeyException("Can't handle key agreement");
                }

                ka->setPeerUri(peerUri);
                ka->setPeerId(peerId);
                ka->setInitiatorData(init_mes);
                // Works only if MCData Payload is not ciphered, else decryption
                // is performed later within authenticate() method
                init_mes->keyParameters(NULL);

                if (init_mes->authenticate(*ka) == false) {
                    string msg = "Authentication of the MIKEY init message failed: " + ka->authError();
                    throw MikeyExceptionAuthentication(msg.c_str());
                }

                secured = true;
                setState(STATE_AUTHENTICATED);
            } catch (MikeyExceptionUnacceptable& exc) {
                MIKEY_SAKKE_LOGE("MikeyException caught: %s", exc.what());
                // FIXME! send SIP Unacceptable with Mikey Error message
                setState(STATE_ERROR);
            }
            // Authentication failed
            catch (MikeyExceptionAuthentication& exc) {
                MIKEY_SAKKE_LOGE("MikeyExceptionAuthentication caught: %s", exc.what());
                // FIXME! send SIP Authorization failed with Mikey Error message
                setState(STATE_ERROR);
            }
            // Message was invalid
            catch (MikeyExceptionMessageContent& exc) {
                MRef<MikeyMessage*> error_mes;
                MIKEY_SAKKE_LOGE("MikeyExceptionMesageContent caught: %s", exc.what());
                error_mes = exc.errorMessage();
                if (!error_mes.isNull()) {
                    // FIXME: send the error message!
                }
                setState(STATE_ERROR);
            } catch (MikeyException& exc) {
                MIKEY_SAKKE_LOGE("MikeyException caught: %s", exc.what());
                setState(STATE_ERROR);
            }
        }
    } else {
        MIKEY_SAKKE_LOGE("Unknown type of key agreement");
        secured = false;
        setState(STATE_AUTHENTICATED);
    }

    return state == STATE_AUTHENTICATED;
}

string Mikey::responderParse() {

    if (!ka) {
        MIKEY_SAKKE_LOGE("Unknown type of key agreement");
        setState(STATE_ERROR);
        return "";
    }

    MRef<MikeyMessage*> responseMessage = NULL;
    MRef<MikeyMessage*> initMessage     = ka->initiatorData();

    if (initMessage.isNull()) {
        MIKEY_SAKKE_LOGE("Uninitialized message, this is a bug");
        setState(STATE_ERROR);
        return "";
    }

    try {
#ifdef ENABLE_TS
        ts.save(MIKEY_PARSE_START);
#endif

        addStreamsToKa();

        responseMessage = initMessage->buildResponse(*ka);
#ifdef ENABLE_TS
        ts.save(MIKEY_PARSE_END);
#endif
    } catch (MikeyExceptionUnacceptable& exc) {
        MIKEY_SAKKE_LOGE("MikeyException caught: %s", exc.what());

        // FIXME! send SIP Unacceptable with Mikey Error message
        setState(STATE_ERROR);
    }
    // Message was invalid
    catch (MikeyExceptionMessageContent& exc) {
        MRef<MikeyMessage*> error_mes;
        MIKEY_SAKKE_LOGE("MikeyExceptionMesageContent caught: %s", exc.what());
        error_mes = exc.errorMessage();
        if (!error_mes.isNull()) {
            responseMessage = error_mes;
        }
        setState(STATE_ERROR);
    } catch (MikeyException& exc) {
        MIKEY_SAKKE_LOGE("MikeyException caught: %s", exc.what());
        setState(STATE_ERROR);
    }

    if (!responseMessage.isNull()) {
        return responseMessage->b64Message();
    } else {
        return string("");
    }
}

string Mikey::initiatorCreate(int type, const string& peerUri, struct key_agreement_params* params) {
    MIKEY_SAKKE_LOGD("Create Key Agreement message for %s", peerUri.c_str());
    MRef<MikeyMessage*> message;
    setState(STATE_INITIATOR);

    try {
        createKeyAgreement(type, 0);
        if (!ka) {
            throw MikeyException("Can't create key agreement");
        }

        ka->setPeerUri(peerUri);
        message = ka->createMessage(params);
        string b64Message = message->b64Message();
        MIKEY_SAKKE_LOGD("Created I-Message : %s", b64Message.c_str());
        return "mikey " + b64Message;
    } catch (MikeyException& exc) {
        MIKEY_SAKKE_LOGE("MikeyException caught: %s", exc.what());
        setState(STATE_ERROR);
        return "";
    }
}

bool Mikey::initiatorAuthenticate(string message) {

    if (message.substr(0, 6) == "mikey ") {

        // get rid of the "mikey "
        message = message.substr(6, message.length() - 6);
        if (message == "") {
            MIKEY_SAKKE_LOGE("No MIKEY message received");
            return false;
        } else {
            try {
                MRef<MikeyMessage*> resp_mes = MikeyMessage::parse(message);
                ka->setResponderData(resp_mes);

                if (resp_mes->authenticate(*ka) == false) {
                    throw MikeyExceptionAuthentication("Authentication of the response message failed");
                }

                secured = true;
                setState(STATE_AUTHENTICATED);
            } catch (MikeyExceptionAuthentication& exc) {
                MIKEY_SAKKE_LOGE("MikeyException caught: %s", exc.what());
                // FIXME! send SIP Authorization failed with Mikey Error message
                setState(STATE_ERROR);
            } catch (MikeyExceptionMessageContent& exc) {
                MRef<MikeyMessage*> error_mes;
                MIKEY_SAKKE_LOGE("MikeyExceptionMessageContent caught: %s", exc.what());
                error_mes = exc.errorMessage();
                if (!error_mes.isNull()) {
                    // FIXME: send the error message!
                }
                setState(STATE_ERROR);
            }

            catch (MikeyException& exc) {
                MIKEY_SAKKE_LOGE("MikeyException caught: %s", exc.what());
                setState(STATE_ERROR);
            }
        }
    } else if (ka->type() == KEY_AGREEMENT_TYPE_SAKKE) {
        // no response necessary in SAKKE
        setState(STATE_AUTHENTICATED);
        secured = true;
    } else {
        MIKEY_SAKKE_LOGE("Unknown key management method");
        setState(STATE_ERROR);
    }

    return state == STATE_AUTHENTICATED;
}

string Mikey::initiatorParse() {

    if (!ka) {
        MIKEY_SAKKE_LOGE("Unknown type of key agreement");
        setState(STATE_ERROR);
        return "";
    }

    MRef<MikeyMessage*> responseMessage = NULL;

    try {
        MRef<MikeyMessage*> initMessage = ka->responderData();

        if (initMessage.isNull()) {
            MIKEY_SAKKE_LOGE("Uninitialized MIKEY init message, this is a bug");
            setState(STATE_ERROR);
            return "";
        }

#ifdef ENABLE_TS
        ts.save(MIKEY_PARSE_START);
#endif
        responseMessage = initMessage->parseResponse(*ka);
#ifdef ENABLE_TS
        ts.save(MIKEY_PARSE_END);
#endif

    } catch (MikeyExceptionUnacceptable& exc) {
        MIKEY_SAKKE_LOGE("MikeyException caught: %s", exc.what());
        // FIXME! send SIP Unacceptable with Mikey Error message
        setState(STATE_ERROR);
    }
    // Message was invalid
    catch (MikeyExceptionMessageContent& exc) {
        MRef<MikeyMessage*> error_mes;
        MIKEY_SAKKE_LOGE("MikeyExceptionMesageContent caught: %s", exc.what());
        error_mes = exc.errorMessage();
        if (!error_mes.isNull()) {
            responseMessage = error_mes;
        }
        setState(STATE_ERROR);
    } catch (MikeyException& exc) {
        MIKEY_SAKKE_LOGE("MikeyException caught: %s", exc.what());
        setState(STATE_ERROR);
    }

    if (!responseMessage.isNull()) {
        return responseMessage->b64Message();
    } else
        return string("");
}

void Mikey::addStreamsToKa() {
    Streams::iterator iSender;
    ka->setCsIdMapType(HDR_CS_ID_MAP_TYPE_SRTP_ID);
    uint8_t j = 1;
    for (iSender = mediaStreamSenders.begin(); iSender != mediaStreamSenders.end(); ++iSender, ++j) {

        uint32_t ssrc = *iSender;

        if (isInitiator()) {
            uint8_t policyNo = ka->setdefaultPolicy(MIKEY_PROTO_SRTP);
            ka->addSrtpStream(ssrc, 0 /*ROC*/, policyNo);
            /* Placeholder for the receiver to place his SSRC */
            ka->addSrtpStream(0, 0 /*ROC*/, policyNo);
        } else {
            ka->setSrtpStreamSsrc(ssrc, 2 * j);
            ka->setSrtpStreamRoc(0, 2 * j);
        }
    }
}

void Mikey::setMikeyOffer() {
    if (ka)
        if (MRef<MikeyMessage*> initMessage = ka->initiatorData())
            initMessage->setOffer(*ka);
}

bool Mikey::error() const {
    return state == STATE_ERROR;
}

bool Mikey::isSecured() const {
    return secured && !error();
}

bool Mikey::isInitiator() const {
    return state == STATE_INITIATOR;
}

MRef<KeyAgreement*> Mikey::getKeyAgreement() const {
    return ka;
}

void Mikey::addSender(uint32_t ssrc) {
    mediaStreamSenders.push_back(ssrc);
}

string Mikey::authError() const {
    return ka ? ka->authError() : "";
}

const std::string& Mikey::peerUri() const {
    static string empty;

    if (state != STATE_AUTHENTICATED)
        return empty;

    return ka->peerUri();
}

void Mikey::setState(State newState) {
    state = newState;
}

void Mikey::createKeyAgreement(int type, uint32_t keyPeriodNo) {
    ka = NULL;

    if (!config->isMethodEnabled(type)) {
        throw MikeyException("Cannot handle key agreement method");
    }

    switch (type) {
        case KEY_AGREEMENT_TYPE_SAKKE:
            ka = new KeyAgreementSAKKE(config->getKeys(), kmsClient, keyPeriodNo);
            break;
        default:
            throw MikeyExceptionUnimplemented("Unsupported type of KA");
    }

    ka->setUri(config->getUri());
    ka->setEccsiSignatureValidation(config->payloadSignatureValidation());

    if (isInitiator()) {
        addStreamsToKa();
    }
}

void Mikey::enableKeyMatAutoDownload(KMClient* client) {
    kmsClient = client;
}
void Mikey::disableKeyMatAutoDownload() {
    kmsClient = nullptr;
}