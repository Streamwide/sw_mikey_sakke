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

#include <cassert>
#include <cstring>
#include <config.h>
#include <cstdlib>
#include <libmikey/MikeyPayloadGeneralExtension.h>
#include <libmikey/MikeyKeyParameters.h>

using libmutil::itoa;
using libmutil::binToHex;

// Constructor when receiving Mikey message i.e. contruct MikeyPayloadGeneralExtensions from bytestream.
MikeyPayloadGeneralExtensions::MikeyPayloadGeneralExtensions(uint8_t* start, [[maybe_unused]] int lengthLimit): MikeyPayload(start) {
    this->payloadTypeValue     = MIKEYPAYLOAD_GENERALEXTENSIONS_PAYLOAD_TYPE;
    this->nextPayloadTypeValue = start[0];
    this->type                 = start[1];
    this->data_len             = (uint16_t)start[2] << 8 | (uint16_t)start[3];
    this->data                 = (uint8_t*)calloc(this->data_len, sizeof(uint8_t));

    for (int i = 0; i < this->data_len; ++i) {
        this->data[i] = start[i + 4];
    }

    if (this->type == MIKEYPAYLOAD_GENERALEXTENSIONS_PAYLOAD_TYPE_KEY_PARAMETERS) {
        mcDataProtected = std::make_shared<MikeyMcDataProtected>(this->data, this->data_len);
    }

    endPtr = startPtr + this->data_len + 4;
    assert(endPtr - startPtr == length());
}
// Constructor when constructing new MikeyPayloadGeneralExtension message
MikeyPayloadGeneralExtensions::MikeyPayloadGeneralExtensions(uint8_t type, uint16_t data_len, const uint8_t* data) {
    this->payloadTypeValue = MIKEYPAYLOAD_GENERALEXTENSIONS_PAYLOAD_TYPE;
    this->type             = type;
    this->data_len         = data_len;
    this->data             = (uint8_t*)calloc(data_len, sizeof(uint8_t));
    memcpy(this->data, data, data_len);
}
// Destructor
MikeyPayloadGeneralExtensions::~MikeyPayloadGeneralExtensions() {
    if (data) {
        free(data);
    }
    data = nullptr;
}
// Return the length of the GeneralExtension in bytes
int MikeyPayloadGeneralExtensions::length() const {
    return this->data_len + 4;
}
// Generate bytestream of MikeyPayloadGeneralExtension
void MikeyPayloadGeneralExtensions::writeData(uint8_t* start, int expectedLength) {
    assert(expectedLength == this->length());
    start[0] = this->nextPayloadTypeValue;
    start[1] = this->type;
    start[2] = (uint8_t)((this->data_len & 0xFF00) >> 8);
    start[3] = (uint8_t)(this->data_len & 0xFF);
    for (int i = 4; i < expectedLength; ++i) {
        start[i] = data[i - 4];
    }
}

std::string MikeyPayloadGeneralExtensions::debugDump() {
    std::string ret = "MikeyPayloadGeneralExt: next_payload=" + itoa(nextPayloadType());
    ret = ret + " type=";
    switch (type) {
        case MIKEY_EXT_TYPE_VENDOR_ID:
            ret = ret + "VENDOR_SPECIFICS";
            break;
        case MIKEY_EXT_TYPE_SDP_ID:
            ret = ret + "SDP_PARAMS";
            break;
        case MIKEY_EXT_TYPE_3GPP:
            ret = ret + "3GPP_KEY_PARAMS";
            break;
        default:
            ret = ret + "UNKNOWN("+itoa(type)+")";
    }
    ret += " length_data=" + itoa(data_len)+"\n";
    ret += mcDataProtected->string();

    return ret;
}