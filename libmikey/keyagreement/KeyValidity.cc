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
#include <cstring>
#include <libmikey/KeyValidity.h>
#include <libmikey/MikeyDefs.h>
#include <libmikey/MikeyException.h>
#include <libmutil/stringutils.h>

using namespace std;
using libmutil::binToHex;

KeyValidity::KeyValidity() {
    typeValue = KEYVALIDITY_NULL;
}

KeyValidity::KeyValidity(const KeyValidity& source): MObject(source) {
    typeValue = KEYVALIDITY_NULL;
}

KeyValidity::~KeyValidity() = default;;

int KeyValidity::type() {
    return typeValue;
}

int KeyValidity::length() const {
    return 0;
}

void KeyValidity::writeData([[maybe_unused]] uint8_t* start, [[maybe_unused]] int expectedLength) {}

string KeyValidity::debugDump() {
    return "KeyValidityNull";
}

KeyValidity& KeyValidity::operator=(const KeyValidity&) {
    typeValue = KEYVALIDITY_NULL;
    return *this;
}

KeyValiditySPI::KeyValiditySPI(): spiLength(0), spiPtr(nullptr) {
    typeValue = KEYVALIDITY_SPI;
}

KeyValiditySPI::KeyValiditySPI(const KeyValiditySPI& source): KeyValidity(source) {
    typeValue = KEYVALIDITY_SPI;
    spiLength = source.spiLength;
    spiPtr    = new uint8_t[spiLength];
    memcpy(this->spiPtr, source.spiPtr, spiLength);
}

KeyValiditySPI::KeyValiditySPI(uint8_t* rawData, int lengthLimit) {

    if (lengthLimit < 1) {
        throw MikeyExceptionMessageLengthException("Given data is too short to form a KeyValiditySPI");
    }

    spiLength = rawData[0];

    if (lengthLimit < 1 + spiLength) {
        throw MikeyExceptionMessageLengthException("Given data is too short to form a KeyValiditySPI");
    }

    spiPtr = new uint8_t[spiLength];
    memcpy(spiPtr, &rawData[1], spiLength);
}

KeyValiditySPI::KeyValiditySPI(int length, uint8_t* spi) {
    this->spiPtr = new uint8_t[length];
    memcpy(this->spiPtr, spi, length);
    this->spiLength = length;
}

int KeyValiditySPI::length() const {
    return spiLength + 1; // data + length;
}

void KeyValiditySPI::writeData(uint8_t* start, [[maybe_unused]]int expectedLength) {
    assert(expectedLength == length());
    start[0] = spiLength;
    memcpy(&start[1], spiPtr, spiLength);
}

string KeyValiditySPI::debugDump() {
    return (const char*)("KeyValiditySPI: spi=<") + binToHex(spiPtr, spiLength);
}

KeyValiditySPI::~KeyValiditySPI() {
    if (spiPtr)
        delete[] spiPtr;
    return;
}

KeyValiditySPI& KeyValiditySPI::operator=(const KeyValiditySPI& source) {
    if (this != &source) {
        if (spiPtr) {
            delete[] spiPtr;
        }

        spiLength = source.spiLength;
        spiPtr    = new uint8_t[spiLength];
        memcpy(spiPtr, source.spiPtr, spiLength);
    }
    return *this;
}

KeyValidityInterval::KeyValidityInterval(): vfLength(0), vf(nullptr), vtLength(0), vt(nullptr) {
    typeValue = KEYVALIDITY_INTERVAL;
}

KeyValidityInterval::KeyValidityInterval(const KeyValidityInterval& source): KeyValidity(source) {
    typeValue = KEYVALIDITY_INTERVAL;
    vfLength  = source.vfLength;
    vf        = new uint8_t[vfLength];
    memcpy(vf, source.vf, vfLength);
    vtLength = source.vtLength;
    vt       = new uint8_t[vtLength];
    memcpy(vt, source.vt, vtLength);
}

KeyValidityInterval::KeyValidityInterval(uint8_t* raw_data, int length_limit) {
    if (length_limit < 2)
        throw MikeyExceptionMessageLengthException("Given data is too short to form a KeyValidityInterval");
    vfLength = raw_data[0];
    if (length_limit < 2 + vfLength)
        throw MikeyExceptionMessageLengthException("Given data is too short to form a KeyValidityInterval");
    vf = new uint8_t[vfLength];
    memcpy(vf, &raw_data[1], vfLength);
    vtLength = raw_data[vfLength + 1];
    if (length_limit < 2 + vfLength + vtLength)
        throw MikeyExceptionMessageLengthException("Given data is too short to form a KeyValidityInterval");
    vt = new uint8_t[vtLength];
    memcpy(vt, &raw_data[vfLength + 2], vfLength);
}

KeyValidityInterval::KeyValidityInterval(int vfLength, uint8_t* vf, int vtLength, uint8_t* vt) {
    this->vf = new uint8_t[vfLength];
    memcpy(this->vf, vf, vfLength);
    this->vfLength = vfLength;
    this->vt       = new uint8_t[vtLength];
    memcpy(this->vt, vt, vtLength);
    this->vtLength = vtLength;
}

int KeyValidityInterval::length() const {
    return vtLength + vfLength + 3;
}

void KeyValidityInterval::writeData(uint8_t* start, [[maybe_unused]]int expectedLength) {
    assert(expectedLength == length());
    start[0] = vfLength;
    memcpy(&start[1], vf, vfLength);
    start[1 + vfLength] = vtLength;
    memcpy(&start[2 + vfLength], vt, vtLength);
}

KeyValidityInterval& KeyValidityInterval::operator=(const KeyValidityInterval& source) {
    if (this != &source) {
        typeValue = KEYVALIDITY_INTERVAL;
        if (vf) {
            delete[] vf;
        }
        if (vt) {
            delete[] vt;
        }

        vfLength = source.vfLength;
        vf       = new uint8_t[vfLength];
        memcpy(vf, source.vf, vfLength);
        vtLength = source.vtLength;
        vt       = new uint8_t[vtLength];
        memcpy(vt, source.vt, vtLength);
    }
    return *this;
}

KeyValidityInterval::~KeyValidityInterval() {
    if (vf)
        delete[] vf;
    if (vt)
        delete[] vt;
}

string KeyValidityInterval::debugDump() {
    return "KeyValidityInterval: vf=<" + binToHex(vf, vfLength) + "> vt=<" + binToHex(vt, vtLength);
}
