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
 *          Joachim Orrblad <joachim@orrblad.com>
 */

#include <config.h>
#include <libmikey/MikeyCsIdMap.h>
#include <libmikey/MikeyException.h>
#include <libmutil/stringutils.h>

using namespace std;
using libmutil::itoa;
MikeySrtpCs::MikeySrtpCs(uint8_t policyNo, uint32_t ssrc, uint32_t roc): policyNo(policyNo), ssrc(ssrc), roc(roc) {};
// added 041201 JOOR
MikeyIPSEC4Cs::MikeyIPSEC4Cs(uint8_t policyNo, uint32_t spi, uint32_t spiSrcaddr, uint32_t spiDstaddr)
    : policyNo(policyNo), spi(spi), spiSrcaddr(spiSrcaddr), spiDstaddr(spiDstaddr) {};

MikeyCsIdMapSrtp::MikeyCsIdMapSrtp(): cs(vector<MikeySrtpCs*>()) {}

// added 041201 JOOR
MikeyCsIdMapIPSEC4::MikeyCsIdMapIPSEC4(): cs(list<MikeyIPSEC4Cs*>()) {}

MikeyCsIdMapGenericId::MikeyCsIdMapGenericId(uint8_t csId, uint8_t protType, bool sessionDataFlag, uint8_t securityPoliciesNumber, uint8_t securityPolicy, uint8_t spiLen, uint8_t* spi)
    : csId(csId), protType(protType), sessionDataFlag(sessionDataFlag), securityPoliciesNumber(securityPoliciesNumber), securityPolicy(securityPolicy), spiLen(spiLen)  {
        if (securityPoliciesNumber > 1) {
            throw MikeyException("MikeyCsIdMapGenericId: Invalid securityPoliciesNumber should be 1");
        }
        if (spiLen > GENERIC_ID_SPI_MAX) {
            throw MikeyException("MikeyCsIdMapGenericId: spiLen too long, not supported");
        }
        memcpy(this->spi, spi, spiLen);
        totalLen = 3 /* csID + protType + sessionDataFlag + securityPoliciesNumber */ + securityPoliciesNumber + 2 /* Size of field len of session_data (always 0 for now )*/ + 1 /* Size if spiLen field */+ spiLen;
};

MikeyCsIdMapSrtp::MikeyCsIdMapSrtp(uint8_t* data, int length) {
    if (length % 9) {
        throw MikeyException("Invalid length of SRTP_ID map info");
    }

    uint8_t nCs = length / 9;
    for (uint8_t i = 0; i < nCs; ++i) {
        uint8_t   policyNo = data[i * 9];
        uint32_t ssrc =
            (uint32_t)data[i * 9 + 1] << 24 | (uint32_t)data[i * 9 + 2] << 16 | (uint32_t)data[i * 9 + 3] << 8 | (uint32_t)data[i * 9 + 4];
        uint32_t roc =
            (uint32_t)data[i * 9 + 5] << 24 | (uint32_t)data[i * 9 + 6] << 16 | (uint32_t)data[i * 9 + 7] << 8 | (uint32_t)data[i * 9 + 8];
        addStream(ssrc, roc, policyNo);
    }
}

MikeyCsIdMapIPSEC4::MikeyCsIdMapIPSEC4(uint8_t* data, int length) {
    if (length % 13) {
        throw MikeyException("Invalid length of IPSEC4_ID map info");
    }

    uint8_t nCs = length / 13;

    for (uint8_t i = 0; i < nCs; ++i) {
        uint8_t   policyNo = data[i * 13];
        uint32_t spi      = (uint32_t)data[i * 13 + 1] << 24 | (uint32_t)data[i * 13 + 2] << 16 | (uint32_t)data[i * 13 + 3] << 8
                       | (uint32_t)data[i * 13 + 4];
        uint32_t spiSrcaddr = (uint32_t)data[i * 13 + 5] << 24 | (uint32_t)data[i * 13 + 6] << 16 | (uint32_t)data[i * 13 + 7] << 8
                              | (uint32_t)data[i * 13 + 8];
        uint32_t spiDstaddr = (uint32_t)data[i * 13 + 9] << 24 | (uint32_t)data[i * 13 + 10] << 16 | (uint32_t)data[i * 13 + 11] << 8
                              | (uint32_t)data[i * 13 + 12];
        addSA(spi, spiSrcaddr, spiDstaddr, policyNo);
    }
}

MikeyCsIdMapGenericId::MikeyCsIdMapGenericId(uint8_t* data, int lengthLimit) {
    /* See  RFC-6043 $6.1.1 */
    uint32_t n = 0;

    if (lengthLimit < 3) {
        throw MikeyException("Invalid length of GENERIC_ID map info");
    }

    csId                    = data[n++];
    protType                = data[n++];
    sessionDataFlag         = data[n] & 0x80;
    securityPoliciesNumber  = data[n++] & 0x7F; // Each following SecurityPolicy is 1B long
    if (securityPoliciesNumber > 0) { // Handle at least 1 policy for now (as stated in TS 33.180)
        securityPolicy = data[n];
    }
    n += securityPoliciesNumber;
    if ((uint32_t)lengthLimit < n) {
        throw MikeyException("Invalid securityPoliciesNumber regarding lengthLimit");
    }
    sessionDataLen          = data[n] << 8 | data[n+1];
    n += 2;
    n += sessionDataLen; // Ignore the SessionData for now
    if ((uint32_t)lengthLimit < n) {
        throw MikeyException("Invalid sessionDataLen regarding lengthLimit");
    }
    spiLen                  = data[n++];
    if ((uint32_t)lengthLimit < (n+spiLen) || spiLen > 32) {
        throw MikeyException("spiLen is out of bond or unsupported length");
    }
    memcpy(spi, data + n, spiLen);
    n += spiLen;
    if ((uint32_t)lengthLimit < n) {
        throw MikeyException("Invalid spiLen regarding lengthLimit");
    }
    totalLen = n;
}

MikeyCsIdMapSrtp::~MikeyCsIdMapSrtp() {
    vector<MikeySrtpCs*>::iterator i;

    for (i = cs.begin(); i != cs.end(); ++i)
        delete *i;
}
// added 041201 JOOR
MikeyCsIdMapIPSEC4::~MikeyCsIdMapIPSEC4() {
    list<MikeyIPSEC4Cs*>::iterator i;

    for (i = cs.begin(); i != cs.end(); ++i)
        delete *i;
}

int MikeyCsIdMapSrtp::length() const {
    return 9 * (int)cs.size();
}
// added 041201 JOOR
int MikeyCsIdMapIPSEC4::length() const {
    return 13 * (int)cs.size();
}

int MikeyCsIdMapGenericId::length() const {
    return (int)totalLen;
}

void MikeyCsIdMapSrtp::writeData(uint8_t* start, int expectedLength) {
    if (expectedLength < length()) {
        throw MikeyExceptionMessageLengthException("CsSrtpId is too long");
    }

    int                            j = 0, k;
    vector<MikeySrtpCs*>::iterator i;

    for (i = cs.begin(); i != cs.end(); ++i) {
        start[9 * j] = (*i)->policyNo & 0xFF;
        for (k = 0; k < 4; k++) {
            start[9 * j + 1 + k] = ((*i)->ssrc >> 8 * (3 - k)) & 0xFF;
        }
        for (k = 0; k < 4; k++) {
            start[9 * j + 5 + k] = ((*i)->roc >> 8 * (3 - k)) & 0xFF;
        }
        j++;
    }
}
// added 041202 JOOR
void MikeyCsIdMapIPSEC4::writeData(uint8_t* start, int expectedLength) {
    if (expectedLength < length()) {
        throw MikeyExceptionMessageLengthException("CsIPSEC4Id is too long");
    }

    int                            j = 0, k;
    list<MikeyIPSEC4Cs*>::iterator i;

    for (i = cs.begin(); i != cs.end(); ++i) {
        start[13 * j] = (*i)->policyNo & 0xFF;
        for (k = 0; k < 4; k++) {
            start[13 * j + 1 + k] = ((*i)->spi >> 8 * (3 - k)) & 0xFF;
        }
        for (k = 0; k < 4; k++) {
            start[13 * j + 5 + k] = ((*i)->spiSrcaddr >> 8 * (3 - k)) & 0xFF;
        }
        for (k = 0; k < 4; k++) {
            start[13 * j + 9 + k] = ((*i)->spiDstaddr >> 8 * (3 - k)) & 0xFF;
        }
        j++;
    }
}

void MikeyCsIdMapGenericId::writeData(uint8_t* start, int expectedLength) {
    if (expectedLength < length()) {
        throw MikeyExceptionMessageLengthException("CsIdMapGenericId is too long");
    }

    uint32_t n  = 0;
    start[n++]  = csId;
    start[n++]  = protType;
    start[n]    = (sessionDataFlag == true ? 0x80 : 0x0);
    start[n++]  |= securityPoliciesNumber;
    if (securityPoliciesNumber > 0) {
        start[n++] = securityPolicy; // At the moment, handle only 1 PolicyNumber as stated in TS-33.180 $E.2.2-1
    }
    start[n++] = 0; // No SessionDataLen as SSRC are not provided here (see TS-33.180 $E.2.2-1)
    start[n++] = 0; // No SessionDataLen as SSRC are not provided here (see TS-33.180 $E.2.2-1)
    start[n++] = spiLen;
    memcpy(start + n, spi, spiLen); // SPI is the MKI (PCK-ID or GUK-ID or CSK-ID), so the csbid
    n += spiLen;
    if (n != (uint32_t)length()) {
        throw MikeyException("MikeyCsIdMapGenericId wrote unexpected len");
    }
}

uint8_t MikeyCsIdMapSrtp::getNumberCs() {
    return (uint8_t)cs.size();
}

uint8_t MikeyCsIdMapIPSEC4::getNumberCs() {
    return (uint8_t)cs.size();
}

uint8_t MikeyCsIdMapGenericId::getNumberCs() {
    return securityPoliciesNumber;
}

uint8_t MikeyCsIdMapSrtp::findCsId(uint32_t ssrc) {
    vector<MikeySrtpCs*>::iterator i;
    uint8_t                        j = 1;

    for (i = cs.begin(); i != cs.end(); ++i, j++) {
        if ((*i)->ssrc == ssrc) {
            return j;
        }
    }
    return 0;
}
// added 041201 JOOR
uint8_t MikeyCsIdMapIPSEC4::findCsId(uint32_t spi, uint32_t spiSrcaddr, uint32_t spiDstaddr) {
    list<MikeyIPSEC4Cs*>::iterator i;
    uint8_t                        j = 1;

    for (i = cs.begin(); i != cs.end(); ++i, j++) {
        if ((*i)->spi == spi && (*i)->spiSrcaddr == spiSrcaddr && (*i)->spiDstaddr == spiDstaddr) {
            return j;
        }
    }
    return 0;
}
// added 041214 JOOR
uint8_t MikeyCsIdMapSrtp::findpolicyNo(uint32_t ssrc) {
    vector<MikeySrtpCs*>::iterator i;
    for (i = cs.begin(); i != cs.end(); ++i) {
        if ((*i)->ssrc == ssrc) {
            return (*i)->policyNo;
        }
    }
    return 0;
}
// added 050110 JOOR
MikeyIPSEC4Cs* MikeyCsIdMapIPSEC4::getCsIdnumber(int number) {
    list<MikeyIPSEC4Cs*>::iterator i;
    int                            j = 1;
    for (i = cs.begin(); i != cs.end(); ++i) {
        if (j == number)
            return (*i);
        j++;
    }
    return nullptr;
}

// added 041201 JOOR
uint8_t MikeyCsIdMapIPSEC4::findpolicyNo(uint32_t spi, uint32_t spiSrcaddr, uint32_t spiDstaddr) {
    list<MikeyIPSEC4Cs*>::iterator i;
    for (i = cs.begin(); i != cs.end(); ++i) {
        if ((*i)->spi == spi && (*i)->spiSrcaddr == spiSrcaddr && (*i)->spiDstaddr == spiDstaddr) {
            return (*i)->policyNo;
        }
    }
    return 0;
}

uint32_t MikeyCsIdMapSrtp::findRoc(uint32_t ssrc) {
    vector<MikeySrtpCs*>::iterator i;

    for (i = cs.begin(); i != cs.end(); ++i) {
        if ((*i)->ssrc == ssrc) {
            return (*i)->roc;
        }
    }
    return 0;
}

void MikeyCsIdMapSrtp::setSsrc(uint32_t ssrc, uint8_t csId) {
    if (csId > cs.size()) {
        return;
    }

    (cs[csId - 1])->ssrc = ssrc;
}

void MikeyCsIdMapSrtp::setRoc(uint32_t roc, uint8_t csId) {
    if (csId > cs.size()) {
        return;
    }

    (cs[csId - 1])->roc = roc;
}

void MikeyCsIdMapSrtp::addStream(uint32_t ssrc, uint32_t roc, uint8_t policyNo, uint8_t csId) {
    if (csId == 0) {
        cs.push_back(new MikeySrtpCs(policyNo, ssrc, roc));
        return;
    }

    if (csId > cs.size()) {
        return;
    }

    (cs[csId - 1])->ssrc     = ssrc;
    (cs[csId - 1])->policyNo = policyNo;
    (cs[csId - 1])->roc      = roc;
    return;
}

// added 041201 JOOR
void MikeyCsIdMapIPSEC4::addSA(uint32_t spi, uint32_t spiSrcaddr, uint32_t spiDstaddr, uint8_t policyNo, uint8_t csId) {
    if (csId == 0) {
        cs.push_back(new MikeyIPSEC4Cs(policyNo, spi, spiSrcaddr, spiDstaddr));
        return;
    }
    list<MikeyIPSEC4Cs*>::iterator i;
    uint8_t                        j = 1;
    for (i = cs.begin(); i != cs.end(); ++i, j++) {
        if (j == csId) {
            (*i)->spi        = spi;
            (*i)->policyNo   = policyNo;
            (*i)->spiSrcaddr = spiSrcaddr;
            (*i)->spiDstaddr = spiDstaddr;
        }
    }

    return;
}

std::string MikeyCsIdMapSrtp::debugDump() {
    std::string                         output = "MapSrtp:\n";
    std::vector<MikeySrtpCs*>::iterator iCs;
    uint8_t                             csId = 1;

    for (iCs = cs.begin(); iCs != cs.end(); ++iCs, ++csId) {
        output += "\tcsId: <" + itoa(csId) + ">\n";
        output += "\t\tpolicyNo: <" + itoa((*iCs)->policyNo) + ">\n";
        output += "\t\tSSRC: <" + itoa((*iCs)->ssrc) + ">\n";
        output += "\t\tROC: <" + itoa((*iCs)->roc) + ">\n";
    }
    return output;
}

std::string MikeyCsIdMapIPSEC4::debugDump() {
    std::string                         output = "MapIpsec4\n";
    std::list<MikeyIPSEC4Cs*>::iterator iCs;
    uint8_t                             csId = 1;

    for (iCs = cs.begin(); iCs != cs.end(); ++iCs, ++csId) {
        output += "\tcsId: <" + itoa(csId) + ">\n";
        output += "\t\tspi: <" + itoa((*iCs)->spi) + ">\n";
        output += "\t\tpolicyNo: <" + itoa((*iCs)->policyNo) + ">\n";
        output += "\t\tSource Addr.: <" + itoa((*iCs)->spiSrcaddr) + ">\n";
        output += "\t\tDest. Addr.: <" + itoa((*iCs)->spiDstaddr) + ">\n";
    }
    return output;
}

std::string MikeyCsIdMapGenericId::debugDump() {
    std::string                         output = "MapGENERIC-ID\n";
    std::list<MikeyIPSEC4Cs*>::iterator iCs;
    uint8_t                             csId = 1;

    output += "\tcsId: <" + itoa(csId) + ">\n";
    output += "\t\tprotType: <" + itoa(protType) + ">\n";
    output += "\t\tsessionDataFlag: <" + (sessionDataFlag == true ? std::string("true") : std::string("false")) + ">\n";
    output += "\t\tsecurityPoliciesNumber: <" + itoa(securityPoliciesNumber) + ">\n";
    OctetString tmp = OctetString{spiLen, spi};
    output += "\t\tspi(len=" + itoa(spiLen) + "): <" + tmp.translate().c_str() + ">\n";
    return output;
}
