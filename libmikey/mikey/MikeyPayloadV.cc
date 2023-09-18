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
#include <libmikey/MikeyPayloadV.h>

MikeyPayloadV::MikeyPayloadV(int macAlgValue, uint8_t* verDataPtr) {
    this->payloadTypeValue = MIKEYPAYLOAD_V_PAYLOAD_TYPE;
    this->macAlgValue      = macAlgValue;
    switch (macAlgValue) {
        case MIKEY_PAYLOAD_V_MAC_HMAC_SHA1_160:
            this->verDataPtr = new uint8_t[20];
            memcpy(this->verDataPtr, verDataPtr, 20);
            break;
        case MIKEY_PAYLOAD_V_MAC_NULL:
            this->verDataPtr = nullptr;
            break;
        default:
            throw MikeyExceptionMessageContent("Unknown MAC algorithm in V payload (1)");
    }
}

MikeyPayloadV::MikeyPayloadV(uint8_t* start, int lengthLimit): MikeyPayload(start) {

    this->payloadTypeValue = MIKEYPAYLOAD_V_PAYLOAD_TYPE;
    if (lengthLimit < 2) {
        throw MikeyExceptionMessageLengthException("Given data is too short to form a V Payload");
    }

    setNextPayloadType(start[0]);
    this->macAlgValue = (int)start[1];
    switch (macAlgValue) {
        case MIKEY_PAYLOAD_V_MAC_HMAC_SHA1_160:
            if (lengthLimit < 22) {
                throw MikeyExceptionMessageLengthException("Given data is too short to"
                                                           "form a V Payload");
            }
            verDataPtr = new uint8_t[20];
            memcpy(verDataPtr, &start[2], 20);
            endPtr = startPtr + 22;
            break;
        case MIKEY_PAYLOAD_V_MAC_NULL:
            verDataPtr = nullptr;
            endPtr     = startPtr + 2;
            break;
        default:
            throw MikeyExceptionMessageContent("Unknown MAC algorithm in V payload (2)");
    }
}

MikeyPayloadV::~MikeyPayloadV() {
    if (verDataPtr) {
        delete[] verDataPtr;
        verDataPtr = nullptr;
    }
}

int MikeyPayloadV::length() const {
    return 2 + ((macAlgValue == MIKEY_PAYLOAD_V_MAC_HMAC_SHA1_160) ? 20 : 0);
}

void MikeyPayloadV::writeData(uint8_t* start, [[maybe_unused]] int expectedLength) {
    assert(expectedLength == length());
    start[0] = (uint8_t)nextPayloadType();
    start[1] = (uint8_t)(macAlgValue & 0xFF);
    if (macAlgValue == MIKEY_PAYLOAD_V_MAC_HMAC_SHA1_160)
        memcpy(&start[2], verDataPtr, 20);
}

int MikeyPayloadV::macAlg() {
    return macAlgValue;
}

uint8_t* MikeyPayloadV::verData() {
    return verDataPtr;
}

void MikeyPayloadV::setMac(uint8_t* data) {
    if (verDataPtr)
        delete[] verDataPtr;

    switch (macAlgValue) {
        case MIKEY_PAYLOAD_V_MAC_HMAC_SHA1_160:
            verDataPtr = new uint8_t[20];
            memcpy(verDataPtr, data, 20);
            break;
        case MIKEY_PAYLOAD_V_MAC_NULL:
            verDataPtr = nullptr;
            break;
        default:
            throw MikeyException("Unknown MAC algorithm (Payload V::setMac)");
    }
}
