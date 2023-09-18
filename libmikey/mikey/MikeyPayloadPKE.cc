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
#include <libmikey/MikeyPayloadPKE.h>
#include <libmutil/stringutils.h>

using namespace std;
using libmutil::itoa;
using libmutil::binToHex;

MikeyPayloadPKE::MikeyPayloadPKE(int c, uint8_t* dataPtr, int dataLengthValue) {
    this->payloadTypeValue = MIKEYPAYLOAD_PKE_PAYLOAD_TYPE;
    this->cValue           = c;
    this->dataLengthValue  = dataLengthValue;
    this->dataPtr          = new uint8_t[dataLengthValue];
    memcpy(this->dataPtr, dataPtr, dataLengthValue);
}

MikeyPayloadPKE::MikeyPayloadPKE(uint8_t* start, int lengthLimit): MikeyPayload(start) {
    if (lengthLimit < 3) {
        throw MikeyExceptionMessageLengthException("Given dataPtr is too short to form a PKE Payload");
    }
    this->payloadTypeValue = MIKEYPAYLOAD_PKE_PAYLOAD_TYPE;
    setNextPayloadType(start[0]);
    cValue          = (start[1] >> 6) & 0x3;
    dataLengthValue = (int)((start[1] & 0x3F) << 8) | (int)(start[2]);
    if (lengthLimit < 3 + dataLengthValue) {
        throw MikeyExceptionMessageLengthException("Given dataPtr is too short to form a PKE Payload");
    }
    dataPtr = new uint8_t[dataLengthValue];
    memcpy(dataPtr, &start[3], dataLengthValue);
    endPtr = startPtr + 3 + dataLengthValue;

    assert(endPtr - startPtr == length());
}

MikeyPayloadPKE::~MikeyPayloadPKE() {
    if (dataPtr) {
        delete[] dataPtr;
    }
}

int MikeyPayloadPKE::length() const {
    return 3 + dataLengthValue;
}

void MikeyPayloadPKE::writeData(uint8_t* start, int expectedLength) {
    assert(expectedLength == length());
    memset(start, 0, expectedLength);
    start[0] = (uint8_t)nextPayloadType();
    start[1] = (uint8_t)((cValue & 0x3) << 6 | ((dataLengthValue >> 8) & 0x3F));
    start[2] = (uint8_t)(dataLengthValue & 0xFF);
    memcpy(&start[3], dataPtr, dataLengthValue);
}

int MikeyPayloadPKE::c() {
    return cValue;
}

int MikeyPayloadPKE::dataLength() const {
    return dataLengthValue;
}

const uint8_t* MikeyPayloadPKE::data() const {
    return dataPtr;
}

string MikeyPayloadPKE::debugDump() {
    return "MikeyPayloadPKE: c=<" + itoa(cValue) + "> dataLengthValue=<" + itoa(cValue) + "> dataPtr=<"
           + binToHex(dataPtr, dataLengthValue);
}
