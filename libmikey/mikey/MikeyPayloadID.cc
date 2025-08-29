/*
  Copyright (C) 2005, 2004 Erik Eliasson, Johan Bilien

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
 */

#include <cassert>
#include <config.h>
#include <cstring>
#include <libmikey/MikeyException.h>
#include <libmikey/MikeyPayloadID.h>
#include <libmutil/stringutils.h>

using namespace std;
using libmutil::itoa;
using libmutil::binToHex;

MikeyPayloadID::MikeyPayloadID(MikeyPayloadIDType type, int length, uint8_t* data, MikeyPayloadIDRole role) {
    if (role == MIKEYPAYLOAD_ID_ROLE_UNSPECIFIED)
        this->payloadTypeValue = MIKEYPAYLOAD_ID_PAYLOAD_TYPE;
    else
        this->payloadTypeValue = MIKEYPAYLOAD_IDR_PAYLOAD_TYPE;
    this->idTypeValue   = type;
    this->idRoleValue   = role;
    this->idLengthValue = length;
    this->idDataPtr     = new uint8_t[length];
    memcpy(this->idDataPtr, data, length);
}

MikeyPayloadID::MikeyPayloadID(uint8_t* start, int lengthLimit, bool expectIDR): MikeyPayload(start) {

    int const minLength = 4 + (expectIDR ? 1 : 0);
    if (lengthLimit < minLength) {
        string e = "Given initial data is too short (" + std::to_string(lengthLimit) + "B) to form a ID/IDR Payload";
        throw MikeyExceptionMessageLengthException(e.c_str());
    }
    if (expectIDR)
        this->payloadTypeValue = MIKEYPAYLOAD_IDR_PAYLOAD_TYPE;
    else
        this->payloadTypeValue = MIKEYPAYLOAD_ID_PAYLOAD_TYPE;
    setNextPayloadType(*start++);
    if (expectIDR)
        idRoleValue = MikeyPayloadIDRole(*start++);
    else
        idRoleValue = MIKEYPAYLOAD_ID_ROLE_UNSPECIFIED;
    idTypeValue   = MikeyPayloadIDType(*start++);
    idLengthValue = (int)(start[0]) << 8 | start[1];
    start += 2;
    if (lengthLimit < minLength + idLengthValue) {
        string e = "Given data is too short (" + std::to_string(lengthLimit) + "B) to form a ID/IDR Payload";
        throw MikeyExceptionMessageLengthException(e.c_str());
    }

    idDataPtr = new uint8_t[idLengthValue];
    memcpy(idDataPtr, start, idLengthValue);
    endPtr = start + idLengthValue;

    assert(endPtr - startPtr == length());
}

MikeyPayloadID::~MikeyPayloadID() {
    if (idDataPtr)
        delete[] idDataPtr;
    idDataPtr = nullptr;
}

void MikeyPayloadID::writeData(uint8_t* start, int expectedLength) {

    assert(expectedLength == length());
    memset(start, 0, expectedLength);
    *start++ = nextPayloadType();
    if (idRoleValue != MIKEYPAYLOAD_ID_ROLE_UNSPECIFIED)
        *start++ = idRoleValue;
    *start++ = idTypeValue;
    *start++ = (uint8_t)((idLengthValue & 0xFF00) >> 8);
    *start++ = (uint8_t)(idLengthValue & 0xFF);
    memcpy(start, idDataPtr, idLengthValue);
}

int MikeyPayloadID::length() const {

    return (idRoleValue != MIKEYPAYLOAD_ID_ROLE_UNSPECIFIED ? 5 : 4) + idLengthValue;
}

const char* MikeyPayloadID::RoleTypeToString(int e) {
    switch (e) {
        case MIKEYPAYLOAD_ID_ROLE_UNSPECIFIED:      return "unspecified";
        case MIKEYPAYLOAD_ID_ROLE_INITIATOR:        return "initiator";
        case MIKEYPAYLOAD_ID_ROLE_RESPONDER:        return "responder";
        case MIKEYPAYLOAD_ID_ROLE_KMS:              return "kms";
        case MIKEYPAYLOAD_ID_ROLE_PRE_SHARED_KEY:   return "psk";
        case MIKEYPAYLOAD_ID_ROLE_APPLICATION:      return "application";
        case MIKEYPAYLOAD_ID_ROLE_INITIATOR_KMS:    return "initiator_kms";
        case MIKEYPAYLOAD_ID_ROLE_RESPONDER_KMS:    return "responder_kms";
        default:                                    return "unknown";
    }
}

string MikeyPayloadID::debugDump() {
    string res = "";
    res += "MikeyPayloadID: nextPayloadType=<" + itoa(nextPayloadType());
    res += "> role=<" + string(RoleTypeToString(idRoleValue)) + "(" + itoa(idRoleValue) + ")> type=<" + itoa(idTypeValue);
    res += "> length=<" + itoa(idLengthValue) + "> ";
    string tmp = "";
    bool printable = true;
    for(int i=0; i<idLengthValue; i++) {
        tmp += idDataPtr[i];
        if (!(idDataPtr[i] >= ' ' && idDataPtr[i] <= '~')) {
            printable = false;
        }
    }
    if (printable) {
        res += "text: " + tmp + ">";
    } else {
        res += "bin: " + binToHex(idDataPtr, idLengthValue) + ">";
    }

    return res+"\n";
}

MikeyPayloadIDType MikeyPayloadID::idType() const {
    return idTypeValue;
}

MikeyPayloadIDRole MikeyPayloadID::idRole() const {
    return idRoleValue;
}

int MikeyPayloadID::idLength() const {
    return idLengthValue;
}

const uint8_t* MikeyPayloadID::idData() const {
    return idDataPtr;
}
