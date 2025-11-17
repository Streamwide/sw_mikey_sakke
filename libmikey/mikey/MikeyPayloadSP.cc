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
#include <cstdlib>
#include <libmikey/MikeyException.h>
#include <libmikey/MikeyPayloadSP.h>

using namespace std;
using libmutil::itoa;
using libmutil::binToHex;

//
// MikeyPolicyParam
//
MikeyPolicyParam::MikeyPolicyParam(uint8_t type, uint8_t length, const uint8_t* value): type(type), length(length) {
    this->type   = type;
    this->length = length;
    this->value  = (uint8_t*)calloc(length, sizeof(uint8_t));
    for (int i = 0; i < length; ++i)
        this->value[i] = value[i];
}
// Destructor
MikeyPolicyParam::~MikeyPolicyParam() {
    free(value);
}
//
// MikeyPayloadSP
//
// Constructor when receiving Mikey message i.e. contruct MikeyPayloadSP from bytestream
MikeyPayloadSP::MikeyPayloadSP(uint8_t* start, [[maybe_unused]] int lengthLimit): MikeyPayload(start) {
    this->payloadTypeValue     = MIKEYPAYLOAD_SP_PAYLOAD_TYPE;
    this->policy_param_length  = 0;
    this->nextPayloadTypeValue = start[0];
    this->policy_no            = start[1];
    this->prot_type            = start[2];
    int      i                 = 5;
    uint16_t j                 = ((uint16_t)start[3] << 8 | (uint16_t)start[4]) + 5;
    // uint8_t *value;

    if (j > lengthLimit) {
        throw MikeyExceptionMessageContent("MikeyPayloadSP: policy_param_length seems too large");
    }
    endPtr = startPtr + j;
    // while(i < lengthLimit) {
    while (i < j) {
        this->addMikeyPolicyParam(start[i], start[i + 1], &start[i + 2]);
        i = i + 2 + start[i + 1];
    }
    if (endPtr - startPtr != length()) {
        throw MikeyExceptionMessageContent("MikeyPayloadSP: finishing parsing out-of-boundary");
    }
}
// Constructor when constructing new Mikey message, policy type entries added later with MikeyPayloadSP::addMikeyPolicyParam
MikeyPayloadSP::MikeyPayloadSP(uint8_t policy_no, uint8_t prot_type) {
    this->payloadTypeValue    = MIKEYPAYLOAD_SP_PAYLOAD_TYPE;
    this->policy_param_length = 0;
    this->policy_no           = policy_no;
    this->prot_type           = prot_type;
}

// Destructor
MikeyPayloadSP::~MikeyPayloadSP() {
    list<MikeyPolicyParam*>::iterator i;
    for (i = param.begin(); i != param.end(); ++i)
        delete *i;
    param.clear();
}
// Add a policytype i.e. add one MikeyPolicyParam in list<MikeyPolicyParam *> param
void MikeyPayloadSP::addMikeyPolicyParam(uint8_t type, uint8_t length, uint8_t* value) {
    if (this->getParameterType(type) != nullptr)
        this->deleteMikeyPolicyParam(type);
    param.push_back(new MikeyPolicyParam(type, length, value));
    this->policy_param_length = this->policy_param_length + length + 2;
}
// Get the MikeyPolicyParam in list<MikeyPolicyParam *> param with type type
MikeyPolicyParam* MikeyPayloadSP::getParameterType(uint8_t type) {
    list<MikeyPolicyParam*>::iterator i;
    for (i = param.begin(); i != param.end(); ++i) {
        if ((*i)->type == type)
            return *i;
    }
    return nullptr;
}
// Generate bytestream
void MikeyPayloadSP::writeData(uint8_t* start, int expectedLength) {
    assert(expectedLength == this->length());
    start[0] = this->nextPayloadTypeValue;
    start[1] = this->policy_no;
    start[2] = this->prot_type;
    start[3] = (uint8_t)((this->policy_param_length & 0xFF00) >> 8);
    start[4] = (uint8_t)(this->policy_param_length & 0xFF);
    // Add policy params
    auto i = param.begin();
    int                               j = 5, k;
    while (i != param.end() && j < expectedLength) {
        start[j++] = (*i)->type;
        start[j++] = (*i)->length;
        for (k = 0; k < ((*i)->length); k++)
            start[j++] = ((*i)->value)[k];
        ++i;
    }
}
// Return total length of the MikeyPayloadSP data in bytes
int MikeyPayloadSP::length() const {
    return 5 + this->policy_param_length;
}
// Return number of policy param entries
int MikeyPayloadSP::noOfPolicyParam() {
    return (int)param.size();
}
// Delete the MikeyPolicyParam in list<MikeyPolicyParam *> param with type type
void MikeyPayloadSP::deleteMikeyPolicyParam(uint8_t type) {
    list<MikeyPolicyParam*>::iterator i;
    for (i = param.begin(); i != param.end(); ++i)
        if ((*i)->type == type) {
            this->policy_param_length = this->policy_param_length - (*i)->length - 2;
            delete *i;
            i = param.erase(i);
        }
}

std::string MikeyPayloadSP::debugDump() {
    string ret = "MikeyPayloadSP: next_payload<" + itoa(nextPayloadTypeValue) + "> ";

    ret += string("policyNo: <") + itoa(policy_no) + "> ";
    ret += string("protType: <" + debugDumpProtType(prot_type) + "(") + itoa(prot_type) + ")>\n";

    auto i = param.begin();
    for (; i != param.end(); ++i) {
        ret += string("type: <" + debugDumpParamType((*i)->type) + "(") + itoa((*i)->type) + ")> ";
        ret += string("value: <" + debugDumpParamValue((*i)->type, *(*i)->value) + "(") + itoa(*(*i)->value) + ")>\n";
    }

    return ret;
}

std::string MikeyPayloadSP::debugDumpProtType(uint8_t prot_type) {
    switch (prot_type) {
        case MIKEY_PROTO_SRTP:
            return "MIKEY_PROTO_SRTP";
        case MIKEY_PROTO_IPSEC4:
            return "MIKEY_PROTO_IPSEC4";
        default:
            return "Unknown";
    }
}

std::string MikeyPayloadSP::debugDumpParamType(uint8_t param_type) {
    switch (param_type) {
        case MIKEY_SRTP_EALG:
            return "SRTP Enc Alg";
        case MIKEY_SRTP_EKEYL:
            return "SRTP Enc KeyLen";
        case MIKEY_SRTP_AALG:
            return "SRTP Authent Alg";
        case MIKEY_SRTP_AKEYL:
            return "SRTP Authent KeyLen";
        case MIKEY_SRTP_SALTKEYL:
            return "SRTP Salt KeyLen";
        case MIKEY_SRTP_PRF:
            return "SRTP PRF";
        case MIKEY_SRTP_KEY_DERRATE:
            return "SRTP Key DebRate";
        case MIKEY_SRTP_ENCR_ON_OFF:
            return "SRTP Enc Status";
        case MIKEY_SRTCP_ENCR_ON_OFF:
            return "SRTCP Enc Status";
        case MIKEY_SRTP_FEC_ORDER:
            return "SRTP FEC ORDER";
        case MIKEY_SRTP_AUTH_ON_OFF:
            return "SRTP Auth Status";
        case MIKEY_SRTP_AUTH_TAGL:
            return "SRTP Auth TagLen";
        case MIKEY_SRTP_PREFIX:
            return "SRTP PrefixLen";
        case MIKEY_SRTP_ROC_TRANSMISSION_RATE:
            return "SRTP ROC Transmission Rate";
        case MIKEY_SRTP_ROC_AUTH_TAGL:
            return "SRTP ROC Auth TagLen";
        case MIKEY_SRTCP_AUTH_TAGL:
            return "SRTCP Auth TagLen";
        case MIKEY_SRTP_AEAD_TAGL:
            return "SRTP AEAD TagLen";
        default:
            return "Unknown";
    }
}

std::string MikeyPayloadSP::debugDumpParamValue(uint8_t param_type, uint8_t value) {
    switch (param_type) {
        case MIKEY_SRTP_EALG:
            if (value == MIKEY_SRTP_EALG_NULL)
                return "NULL";
            else if (value == MIKEY_SRTP_EALG_AESCM)
                return "AESCM";
            else if (value == MIKEY_SRTP_EALG_AESF8)
                return "AESF8";
            else if (value == MIKEY_SRTP_EALG_AESGCM)
                return "AESGCM";
            break;
        case MIKEY_SRTP_AALG:
            if (value == MIKEY_SRTP_AALG_NULL)
                return "NULL";
            else if (value == MIKEY_SRTP_AALG_SHA1HMAC)
                return "SHA1HMAC";
            else if (value == MIKEY_SRTP_AALG_RCCM3)
                return "RCCm3 (un-authent ROC)";
            break;
        case MIKEY_SRTP_EKEYL:
        case MIKEY_SRTP_AKEYL:
        case MIKEY_SRTP_SALTKEYL:
        case MIKEY_SRTP_AUTH_TAGL:
        case MIKEY_SRTP_PREFIX:
            return "len";
        case MIKEY_SRTP_PRF:
            if (value == 0)
                return "AES-CM";
            break;
        case MIKEY_SRTP_KEY_DERRATE:
            break;
        case MIKEY_SRTP_ENCR_ON_OFF:
        case MIKEY_SRTCP_ENCR_ON_OFF:
        case MIKEY_SRTP_AUTH_ON_OFF:
            if (value == 0)
                return "off";
            else if (value == 1)
                return "on";
            break;
        case MIKEY_SRTP_FEC_ORDER:
            if (value == 0)
                return "First FEC, then SRTP";
            break;
        default:
            return "Unknown";
    }
    return "Unknown";
}
