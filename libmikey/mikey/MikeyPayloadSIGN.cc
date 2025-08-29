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
#include <libmikey/MikeyPayloadSIGN.h>
#include <libmutil/stringutils.h>

using namespace std;
using libmutil::itoa;
using libmutil::binToHex;

MikeyPayloadSIGN::MikeyPayloadSIGN(int sigLengthValue, MikeyPayloadSIGNType type) {

    this->payloadTypeValue = MIKEYPAYLOAD_SIGN_PAYLOAD_TYPE;
    setNextPayloadType(0); // Since no other payload will set
                           // this value
    this->sigLengthValue = sigLengthValue;
    this->sigDataPtr     = new uint8_t[sigLengthValue];
    memset(this->sigDataPtr, 0, sigLengthValue);
    this->sigTypeValue = type;
}

MikeyPayloadSIGN::MikeyPayloadSIGN(uint8_t* start, int lengthLimit): MikeyPayload(start) {
    if (lengthLimit < 2) {
        throw MikeyExceptionMessageLengthException("Given data is too short to form a SIGN Payload");
    }
    this->payloadTypeValue = MIKEYPAYLOAD_SIGN_PAYLOAD_TYPE;
    setNextPayloadType(0); // Always last payload
    sigTypeValue   = MikeyPayloadSIGNType((start[0] >> 4) & 0x0F);
    sigLengthValue = ((int)(start[0] & 0x0F)) << 8 | start[1];
    if (lengthLimit < 2 + sigLengthValue) {
        throw MikeyExceptionMessageLengthException("Given data is too short to form a SIGN Payload[2]");
    }
    sigDataPtr = new uint8_t[sigLengthValue];
    memcpy(sigDataPtr, &start[2], sigLengthValue);
    endPtr = startPtr + 2 + sigLengthValue;

    assert(endPtr - startPtr == length());
}

MikeyPayloadSIGN::~MikeyPayloadSIGN() {
    if (sigDataPtr)
        delete[] sigDataPtr;
    sigDataPtr = nullptr;
}

int MikeyPayloadSIGN::length() const {
    return 2 + sigLengthValue;
}

void MikeyPayloadSIGN::writeData(uint8_t* start, int expectedLength) {
    assert(expectedLength == length());
    memset(start, 0, expectedLength);
    start[0] = (uint8_t)(((sigLengthValue & 0x0F00) >> 8) | ((sigTypeValue << 4) & 0xF0));
    start[1] = (uint8_t)(sigLengthValue & 0xFF);
    memcpy(&start[2], sigDataPtr, sigLengthValue);
}

string MikeyPayloadSIGN::debugDump() {
    return "MikeyPayloadSIGN: type=<" + itoa(sigTypeValue) + "> length=<" + itoa(sigLengthValue) + "> signature=<"
           + binToHex(sigDataPtr, sigLengthValue) + ">";
}

int MikeyPayloadSIGN::sigLength() const {
    return sigLengthValue;
}

uint8_t* MikeyPayloadSIGN::sigData() {
    return sigDataPtr;
}

MikeyPayloadSIGNType MikeyPayloadSIGN::sigType() {
    return sigTypeValue;
}

void MikeyPayloadSIGN::setSigData(uint8_t* data, int len) {
    if (sigDataPtr)
        delete[] sigDataPtr;

    sigLengthValue = len;
    sigDataPtr     = new uint8_t[sigLengthValue];
    memcpy(sigDataPtr, data, sigLengthValue);
}
