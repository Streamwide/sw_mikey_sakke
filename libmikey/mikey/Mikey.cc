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

Mikey::Mikey(MRef<IMikeyConfig*> aConfig):  config(aConfig) {}
Mikey::Mikey(): config(nullptr) {}

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
               printf("Debug info: %s", dbgInfo.c_str());

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

bool Mikey::getClearInfo(const string& message, mikey_clear_info_t& info) {
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
                MRef<MikeyPayload*> hdrpl = init_mes->extractPayload(MIKEYPAYLOAD_HDR_PAYLOAD_TYPE);
                auto*               hdr   = static_cast<MikeyPayloadHDR*>(*hdrpl);
                info.key_id = hdr->csbId();

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
                createKeyAgreement(init_mes->keyAgreementType());
                if (!ka) {
                    throw MikeyException("Can't handle key agreement");
                }

                ka->setPeerUri(peerUri);
                ka->setPeerId(peerId);
                ka->setInitiatorData(init_mes);
                init_mes->keyParameters();

                if (init_mes->authenticate(*ka)) {
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
        createKeyAgreement(type);
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

                if (resp_mes->authenticate(*ka)) {
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

void Mikey::createKeyAgreement(int type) {
    ka = NULL;

    if (!config->isMethodEnabled(type)) {
        throw MikeyException("Cannot handle key agreement method");
    }

    switch (type) {
        case KEY_AGREEMENT_TYPE_SAKKE:
            ka = new KeyAgreementSAKKE(config->getKeys());
            break;
        default:
            throw MikeyExceptionUnimplemented("Unsupported type of KA");
    }

    ka->setUri(config->getUri());

    if (isInitiator()) {
        addStreamsToKa();
    }
}
