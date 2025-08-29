/*
  Copyright (C) 2005, 2004 Erik Eliasson, Johan Bilien, Joachim Orrblad

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
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 * Authors: Erik Eliasson <eliasson@it.kth.se>
 *          Johan Bilien <jobi@via.ecp.fr>
 *	    Joachim Orrblad <joachim@orrblad.com>
 */

#include <config.h>

#include <libmikey/MikeyException.h>
#include <libmikey/MikeyMessage.h>
#include <libmikey/MikeyPayload.h>
#include <libmikey/MikeyPayloadCHASH.h>
#include <libmikey/MikeyPayloadDH.h>
#include <libmikey/MikeyPayloadERR.h>
#include <libmikey/MikeyPayloadGeneralExtension.h>
#include <libmikey/MikeyPayloadHDR.h>
#include <libmikey/MikeyPayloadID.h>
#include <libmikey/MikeyPayloadKEMAC.h>
#include <libmikey/MikeyPayloadKeyData.h>
#include <libmikey/MikeyPayloadPKE.h>
#include <libmikey/MikeyPayloadRAND.h>
#include <libmikey/MikeyPayloadSAKKE.h>
#include <libmikey/MikeyPayloadSIGN.h>
#include <libmikey/MikeyPayloadSP.h>
#include <libmikey/MikeyPayloadT.h>
#include <libmikey/MikeyPayloadV.h>

#include <libmcrypto/aes.h>
#include <libmcrypto/base64.h>

#include <cstring>
#include <map>

#include "MikeyMessageSAKKE.h"

/// The signature calculation will be factor two faster if this
/// guess is correct (128 bytes == 1024 bits)
#define GUESSED_SIGNATURE_LENGTH 128

using namespace std;
using libmutil::itoa;

MikeyPayloads::MikeyPayloads(): compiled(false), rawData(nullptr) {}

MikeyPayloads::MikeyPayloads(int firstPayloadType, uint8_t* message, int lengthLimit): compiled(true), rawData(message) {
    parse(firstPayloadType, message, lengthLimit, payloads);
}

const char* MikeyPayloads::payloadTypeToString(int e) {
    switch (e)
    {
        case MIKEYPAYLOAD_HDR_PAYLOAD_TYPE:     return "HDR";
        case MIKEYPAYLOAD_KEMAC_PAYLOAD_TYPE:   return "KEMAC";
        case MIKEYPAYLOAD_PKE_PAYLOAD_TYPE:     return "PKE";
        case MIKEYPAYLOAD_DH_PAYLOAD_TYPE:      return "DH";
        case MIKEYPAYLOAD_SIGN_PAYLOAD_TYPE:    return "SIGN";
        case MIKEYPAYLOAD_T_PAYLOAD_TYPE:       return "T";
        case MIKEYPAYLOAD_ID_PAYLOAD_TYPE:      return "ID";
        case MIKEYPAYLOAD_IDR_PAYLOAD_TYPE:     return "IDR";
        case MIKEYPAYLOAD_CHASH_PAYLOAD_TYPE:   return "CHASH";
        case MIKEYPAYLOAD_V_PAYLOAD_TYPE:       return "V";
        case MIKEYPAYLOAD_SP_PAYLOAD_TYPE:      return "SP";
        case MIKEYPAYLOAD_RAND_PAYLOAD_TYPE:    return "RAND";
        case MIKEYPAYLOAD_ERR_PAYLOAD_TYPE:     return "ERR";
        case MIKEYPAYLOAD_KEYDATA_PAYLOAD_TYPE: return "KEYDATA";
        case MIKEYPAYLOAD_GENERALEXTENSIONS_PAYLOAD_TYPE:   return "GE";
        case MIKEYPAYLOAD_SAKKE_PAYLOAD_TYPE:   return "SAKKE";
        case MIKEYPAYLOAD_LAST_PAYLOAD:         return "LAST";
        default:                                return "Unknown";
    }
}

/*
 * Alg.
 *  1. Parse HDR payload
 *  2. While not end of packet
 *    2.1 Parse payload (choose right class) and store next payload type.
 *    2.2 Add payload to list of all payloads in message.
 */

MikeyMessage* MikeyMessage::parse(uint8_t* message, int lengthLimit) {
    std::list<MRef<MikeyPayload*>> payloads;

    MikeyPayloads::parse(MIKEYPAYLOAD_HDR_PAYLOAD_TYPE, message, lengthLimit, payloads);

    if (payloads.size() == 0) {
        throw MikeyExceptionMessageContent("No payloads");
    }

    MikeyPayloadHDR* hdr = dynamic_cast<MikeyPayloadHDR*>(**payloads.begin());

    if (!hdr) {
        throw MikeyExceptionMessageContent("No header in the payload");
    }

    MikeyMessage* msg = nullptr;

    switch (hdr->dataType()) {
        case MIKEY_TYPE_SAKKE_INIT:
        case MIKEY_TYPE_SAKKE_RESP: // or CSID_RESP; alternative 'more general' spelling for SAKKE_RESP
            msg = CreateIncomingMessageSAKKE();
            break;
        case MIKEY_TYPE_ERROR:
            msg = new MikeyMessage();
            break;
        default:
            throw MikeyExceptionUnimplemented("Unimplemented type of message in INVITE");
    }

    msg->setRawMessageData(message);
    msg->payloads = payloads;

    return msg;
}

MikeyMessage* MikeyMessage::parse(const string& b64Message) {

    int     messageLength;
    uint8_t* messageData;

    messageData = base64_decode(b64Message, &messageLength);

    if (messageData == nullptr) {
        throw MikeyExceptionMessageContent("Invalid B64 input message");
    }

    return parse(messageData, messageLength);
}

MikeyMessage::~MikeyMessage() = default;

MikeyPayloads::~MikeyPayloads() {

    if (rawData) {
        delete[] rawData;
    }

    rawData = nullptr;
}

static MRef<MikeyPayload*> parsePayload(int payloadType, uint8_t* msgpos, int limit) {
    MRef<MikeyPayload*> payload = NULL;
    switch (payloadType) {
        case MIKEYPAYLOAD_HDR_PAYLOAD_TYPE:
            payload = new MikeyPayloadHDR(msgpos, limit);
            break;
        case MIKEYPAYLOAD_KEMAC_PAYLOAD_TYPE:
            payload = new MikeyPayloadKEMAC(msgpos, limit);
            break;
        case MIKEYPAYLOAD_PKE_PAYLOAD_TYPE:
            payload = new MikeyPayloadPKE(msgpos, limit);
            break;
        case MIKEYPAYLOAD_DH_PAYLOAD_TYPE:
            payload = new MikeyPayloadDH(msgpos, limit);
            break;
        case MIKEYPAYLOAD_SIGN_PAYLOAD_TYPE:
            payload = new MikeyPayloadSIGN(msgpos, limit);
            break;
        case MIKEYPAYLOAD_T_PAYLOAD_TYPE:
            payload = new MikeyPayloadT(msgpos, limit);
            break;
        case MIKEYPAYLOAD_ID_PAYLOAD_TYPE:
            payload = new MikeyPayloadID(msgpos, limit);
            break;
        case MIKEYPAYLOAD_IDR_PAYLOAD_TYPE:
            payload = new MikeyPayloadID(msgpos, limit, /*expectIDR=*/true);
            break;
        case MIKEYPAYLOAD_CHASH_PAYLOAD_TYPE:
            payload = new MikeyPayloadCHASH(msgpos, limit);
            break;
        case MIKEYPAYLOAD_V_PAYLOAD_TYPE:
            payload = new MikeyPayloadV(msgpos, limit);
            break;
        case MIKEYPAYLOAD_SP_PAYLOAD_TYPE:
            payload = new MikeyPayloadSP(msgpos, limit);
            break;
        case MIKEYPAYLOAD_RAND_PAYLOAD_TYPE:
            payload = new MikeyPayloadRAND(msgpos, limit);
            break;
        case MIKEYPAYLOAD_ERR_PAYLOAD_TYPE:
            payload = new MikeyPayloadERR(msgpos, limit);
            break;
        case MIKEYPAYLOAD_KEYDATA_PAYLOAD_TYPE:
            payload = new MikeyPayloadKeyData(msgpos, limit);
            break;
        case MIKEYPAYLOAD_GENERALEXTENSIONS_PAYLOAD_TYPE:
            payload = new MikeyPayloadGeneralExtensions(msgpos, limit);
            break;
        case MIKEYPAYLOAD_SAKKE_PAYLOAD_TYPE:
            payload = CreateIncomingPayloadSAKKE(msgpos, limit);
            break;

        case MIKEYPAYLOAD_LAST_PAYLOAD:
            break;
        default:
            throw MikeyExceptionMessageContent("Payload of unrecognized type.");
    }

    return payload;
}

void MikeyPayloads::parse(int firstPayloadType, uint8_t* message, int lengthLimit, std::list<MRef<MikeyPayload*>>& payloads) {
    MRef<MikeyPayload*> hdr;
    uint8_t*             msgpos = message;
    int                 limit  = lengthLimit;

    hdr = parsePayload(firstPayloadType, message, limit);

    payloads.push_back(hdr);

    limit -= (int)(hdr->end() - msgpos);
    msgpos = hdr->end();

    int nextPayloadType = hdr->nextPayloadType();

    while (!(msgpos >= message + lengthLimit) && nextPayloadType != MikeyPayload::LastPayload) {

        MRef<MikeyPayload*> payload = parsePayload(nextPayloadType, msgpos, limit);

        nextPayloadType = payload->nextPayloadType();
        payloads.push_back(payload);

        assert((payload->end() - msgpos) == (payload->length()));
        limit -= (int)(payload->end() - msgpos);
        msgpos = payload->end();
    }

    if (!(msgpos == message + lengthLimit && nextPayloadType == MIKEYPAYLOAD_LAST_PAYLOAD))
        throw MikeyExceptionMessageLengthException("The length of the message did not match"
                                                   "the total length of payloads.");
}

void MikeyPayloads::addPayload(MRef<MikeyPayload*> payload) {

    compiled = false;
    // Put the nextPayloadType in the previous payload */
    if (payload->payloadType() != MIKEYPAYLOAD_HDR_PAYLOAD_TYPE) {
        auto i = payloads.rbegin();

        if (i != payloads.rend()) {
            (*i)->setNextPayloadType(payload->payloadType());
        }
    }

    payloads.push_back(payload);
}

void MikeyPayloads::operator+=(MRef<MikeyPayload*> payload) {
    addPayload(payload);
}

static vector<uint8_t> tsToVec(uint64_t ts) {
    vector<uint8_t> vec;

    vec.resize(8);
    for (int i = 0; i < 8; ++i) {
        vec[8 - i - 1] = (uint8_t)((ts >> (i * 8)) & 0xFF);
    }

    return vec;
}

vector<uint8_t> MikeyPayloads::buildSignData(size_t sigLength, bool useIdsT) {
    vector<uint8_t> signData;

    uint8_t* start = rawMessageData();
    uint8_t* end   = start;
    int     diff  = rawMessageLength() - (int)sigLength;
    assert(diff >= 0);
    end += diff;

    signData.insert(signData.end(), start, end);

    if (useIdsT) {
        vector<uint8_t>      vecIDi = extractIdVec(0);
        vector<uint8_t>      vecIDr = extractIdVec(1);
        MRef<MikeyPayload*> i;

        i = extractPayload(MIKEYPAYLOAD_T_PAYLOAD_TYPE);
        if (!i) {
            throw MikeyException("Could not perform digital signature of the message, no T");
        }

        MRef<MikeyPayloadT*> plT   = dynamic_cast<MikeyPayloadT*>(*i);
        vector<uint8_t>       vecTs = tsToVec(plT->ts());

        signData.insert(signData.end(), vecIDi.begin(), vecIDi.end());
        signData.insert(signData.end(), vecIDr.begin(), vecIDr.end());
        signData.insert(signData.end(), vecTs.begin(), vecTs.end());
    }

    return signData;
}

void MikeyPayloads::compile() {
    if (compiled) {
        throw MikeyExceptionMessageContent("BUG: trying to compile already compiled message.");
    }
    if (rawData)
        delete[] rawData;

    rawData = new uint8_t[rawMessageLength()];

    list<MRef<MikeyPayload*>>::iterator i;
    uint8_t*                             pos = rawData;
    for (i = payloads.begin(); i != payloads.end(); ++i) {
        int len = (*i)->length();
        (*i)->writeData(pos, len);
        pos += len;
    }
}

uint8_t* MikeyPayloads::rawMessageData() {

    if (!compiled)
        compile();
    return rawData;
}

int MikeyPayloads::rawMessageLength() const {
    int length = 0;
    for (const auto & payload : payloads) {
        length += payload->length();
    }

    return length;
}

void MikeyPayloads::setRawMessageData(uint8_t* data) {
    if (rawData) {
        delete[] rawData;
        rawData = nullptr;
    }

    rawData  = data;
    compiled = true;
}

string MikeyPayloads::debugDump() {
    string                              ret = "\n== BEGIN MikeyPayloads ==\n";
    list<MRef<MikeyPayload*>>::iterator i;

    for (i = payloads.begin(); i != payloads.end(); ++i) {
        ret = ret + "\n\n["+payloadTypeToString((*i)->payloadType())+":(" + itoa((*i)->payloadType()) + ")]" + (*i)->debugDump();
    }
    ret += "\n== BEGIN MikeyPayloads ==\n";

    return ret;
}

list<MRef<MikeyPayload*>>::const_iterator MikeyPayloads::firstPayload() const {
    return payloads.begin();
}

list<MRef<MikeyPayload*>>::const_iterator MikeyPayloads::lastPayload() const {
    return --payloads.end();
}

list<MRef<MikeyPayload*>>::iterator MikeyPayloads::firstPayload() {
    return payloads.begin();
}

list<MRef<MikeyPayload*>>::iterator MikeyPayloads::lastPayload() {
    return --payloads.end();
}

string MikeyPayloads::b64Message() {
    return base64_encode(rawMessageData(), rawMessageLength());
}

uint32_t MikeyMessage::csbId() {
    MRef<MikeyPayload*> hdr = *firstPayload();
    if (hdr->payloadType() != MIKEYPAYLOAD_HDR_PAYLOAD_TYPE) {
        throw MikeyExceptionMessageContent("First payload was not a header");
    }
    return dynamic_cast<MikeyPayloadHDR*>(*hdr)->csbId();
}

int MikeyMessage::type() const {
    MRef<const MikeyPayload*> hdr = extractPayload(MIKEYPAYLOAD_HDR_PAYLOAD_TYPE);
    if (hdr.isNull()) {
        throw MikeyExceptionMessageContent("No header in the payload");
    }

    return dynamic_cast<const MikeyPayloadHDR*>(*hdr)->dataType();
}

MRef<MikeyPayload*> MikeyPayloads::extractPayload(int payloadType) {
    list<MRef<MikeyPayload*>>::iterator i;

    for (i = payloads.begin(); i != payloads.end(); ++i) {
        if ((*i)->payloadType() == payloadType) {
            return *i;
        }
    }
    return NULL;
}

MRef<const MikeyPayload*> MikeyPayloads::extractPayload(int payloadType) const {
    list<MRef<MikeyPayload*>>::const_iterator i;

    for (i = payloads.begin(); i != payloads.end(); ++i) {
        if ((*i)->payloadType() == payloadType) {
            return **i;
        }
    }
    return NULL;
}

void MikeyPayloads::remove(MRef<MikeyPayload*> payload) {
    list<MRef<MikeyPayload*>>::iterator i;

    for (i = payloads.begin(); i != payloads.end(); ++i) {
        if (*i == payload) {
            payloads.erase(i);
            return;
        }
    }
}

void MikeyPayloads::addPolicyToPayload(KeyAgreement* ka) {
    // Adding policy to payload
    MikeyPayloadSP*                          PSP;
    list<Policy_type*>*                      policy = ka->getPolicy();
    list<Policy_type*>::iterator             iter;
    map<uint16_t, MikeyPayloadSP*>           existingSPpayloads;
    map<uint16_t, MikeyPayloadSP*>::iterator mapiter;
    for (iter = (*policy).begin(); iter != (*policy).end(); ++iter) {
        uint16_t comp = (uint16_t)((*iter)->policy_No) << 8 | (uint16_t)((*iter)->prot_type);
        mapiter       = existingSPpayloads.find(comp);
        if (mapiter == existingSPpayloads.end()) {
            existingSPpayloads.insert(pair<int, MikeyPayloadSP*>(comp, PSP = new MikeyPayloadSP((*iter)->policy_No, (*iter)->prot_type)));
            addPayload(PSP);
            PSP->addMikeyPolicyParam((*iter)->policy_type, (*iter)->length, (*iter)->value);
        } else
            (mapiter->second)->addMikeyPolicyParam((*iter)->policy_type, (*iter)->length, (*iter)->value);
    }
    // existingSPpayloads.empty();
}

void MikeyPayloads::addPolicyTo_ka(KeyAgreement* ka) {
    // Adding policy to ka
    MikeyPolicyParam*   PParam;
    MRef<MikeyPayload*> i;
    while (1) {
        i = extractPayload(MIKEYPAYLOAD_SP_PAYLOAD_TYPE);
        if (i.isNull()) {
            break;
        }
        auto* SP       = dynamic_cast<MikeyPayloadSP*>(*i);
        int             policy_i = 0;
        int             policy_j = 0;
        while (policy_i < SP->noOfPolicyParam()) {
            if ((PParam = SP->getParameterType(policy_j++)) != nullptr) {
                assert(policy_j - 1 == PParam->type);
                ka->setPolicyParamType(SP->policy_no, SP->prot_type, PParam->type, PParam->length, PParam->value);
                policy_i++;
            }
        }
        payloads.remove(i);
    }
}

MRef<MikeyMessage*> MikeyMessage::parseResponse([[maybe_unused]] KeyAgreement* ka) {
    throw MikeyExceptionUnimplemented("parseResponse not implemented");
}

void MikeyMessage::setOffer([[maybe_unused]] KeyAgreement* ka) {
    throw MikeyExceptionUnimplemented("setOffer not implemented");
}

MRef<MikeyMessage*> MikeyMessage::buildResponse([[maybe_unused]] KeyAgreement* ka) {
    throw MikeyExceptionUnimplemented("buildResponse not implemented");
}

bool MikeyMessage::authenticate([[maybe_unused]] KeyAgreement* ka) {
    throw MikeyExceptionUnimplemented("authenticate not implemented");
}

bool MikeyMessage::isInitiatorMessage() const {
    return false;
}

bool MikeyMessage::isResponderMessage() const {
    return false;
}

int32_t MikeyMessage::keyAgreementType() const {
    throw MikeyExceptionUnimplemented("Unimplemented type of MIKEY message");
}

std::shared_ptr<KeyParametersPayload> MikeyMessage::keyParameters() const {
    throw MikeyExceptionUnimplemented("Unimplemented type of MIKEY message");
}

void MikeyPayloads::addId(const string& theId) {
    MikeyPayloadIDType type = MIKEYPAYLOAD_ID_TYPE_URI;
    string             id   = theId;

    if (id.substr(0, 4) == "nai:") {
        type = MIKEYPAYLOAD_ID_TYPE_NAI;
        id   = id.substr(4);
    }

    auto* initId = new MikeyPayloadID(type, (int)id.size(), (uint8_t*)id.c_str());
    addPayload(initId);
}

const MikeyPayloadID* MikeyPayloads::extractId(int index) const {
    const MikeyPayloadID*                     id = nullptr;
    list<MRef<MikeyPayload*>>::const_iterator i;
    auto last = lastPayload();
    int                                       j;

    for (i = firstPayload(), j = 0; i != last; ++i) {
        MRef<MikeyPayload*> payload = *i;

        if (payload->payloadType() == MIKEYPAYLOAD_ID_PAYLOAD_TYPE) {
            if (j == index) {
                id = dynamic_cast<const MikeyPayloadID*>(*payload);
                break;
            }

            j++;
        }
    }

    return id;
}

string MikeyPayloads::extractIdStr(int index) const {
    const MikeyPayloadID* id = extractId(index);

    if (!id) {
        return "";
    }

    string idData = string((const char*)id->idData(), id->idLength());
    string idStr;

    switch (id->idType()) {
        case MIKEYPAYLOAD_ID_TYPE_NAI:
            idStr = "nai:" + idData;
            break;

        case MIKEYPAYLOAD_ID_TYPE_URI:
            idStr = idData;
            break;

        default:
            return "";
    }

    return idStr;
}

vector<uint8_t> MikeyPayloads::extractIdVec(int index) const {
    const MikeyPayloadID* id = extractId(index);
    vector<uint8_t>        result;

    if (!id) {
        return result;
    }

    result.resize(id->idLength());
    memcpy(&result.front(), id->idData(), id->idLength());
    return result;
}
