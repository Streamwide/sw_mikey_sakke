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
#include <config.h>
#include <cstdlib>
#include <libmikey/MikeyPayloadGeneralExtension.h>

// Constructor when receiving Mikey message i.e. contruct MikeyPayloadGeneralExtensions from bytestream.
MikeyPayloadGeneralExtensions::MikeyPayloadGeneralExtensions(uint8_t* start, [[maybe_unused]] int lengthLimit): MikeyPayload(start) {
    this->payloadTypeValue     = MIKEYPAYLOAD_GENERALEXTENSIONS_PAYLOAD_TYPE;
    this->nextPayloadTypeValue = start[0];
    this->type                 = start[1];
    this->leng                 = (uint16_t)start[2] << 8 | (uint16_t)start[3];
    this->data                 = (uint8_t*)calloc(this->leng, sizeof(uint8_t));

    for (int i = 4; i < this->leng; ++i) {
        this->data[i - 4] = start[i];
    }

    if (this->type == MIKEYPAYLOAD_GENERALEXTENSIONS_PAYLOAD_TYPE_KEY_PARAMETERS) {
        keyParams = std::make_shared<KeyParametersPayload>(this->data, this->leng);
    }

    endPtr = startPtr + this->leng + 4;
    assert(endPtr - startPtr == length());
}
// Constructor when constructing new MikeyPayloadGeneralExtension message
MikeyPayloadGeneralExtensions::MikeyPayloadGeneralExtensions(uint8_t type, uint16_t length, const uint8_t* d) {
    this->payloadTypeValue = MIKEYPAYLOAD_GENERALEXTENSIONS_PAYLOAD_TYPE;
    this->type             = type;
    this->leng             = length;
    this->data             = (uint8_t*)calloc(length, sizeof(uint8_t));
    for (int i = 3; i < length; ++i) {
        this->data[i - 3] = d[i];
    }
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
    return this->leng + 4;
}
// Generate bytestream of MikeyPayloadGeneralExtension
void MikeyPayloadGeneralExtensions::writeData(uint8_t* start, int expectedLength) {
    assert(expectedLength == this->length());
    start[0] = this->nextPayloadTypeValue;
    start[1] = this->type;
    start[2] = (uint8_t)((this->leng & 0xFF00) >> 8);
    start[3] = (uint8_t)(this->leng & 0xFF);
    for (int i = 4; i < expectedLength; ++i) {
        start[i] = data[i - 4];
    }
}