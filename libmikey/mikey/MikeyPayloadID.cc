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
        throw MikeyExceptionMessageLengthException("Given data is too short to form a ID/IDR Payload");
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
        throw MikeyExceptionMessageLengthException("Given data is too short to form a ID/IDR Payload");
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

string MikeyPayloadID::debugDump() {

    return "MikeyPayloadID: nextPayloadType=<" + itoa(nextPayloadType()) + "> role=<" + itoa(idRoleValue) + "> type=<" + itoa(idTypeValue)
           + "> length=<" + itoa(idLengthValue) + "> data=<" + binToHex(idDataPtr, idLengthValue) + ">";
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
