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

#ifndef MIKEYCSIDMAP_H
#define MIKEYCSIDMAP_H

#include <libmikey/libmikey_config.h>

#define HDR_CS_ID_MAP_TYPE_SRTP_ID 0
#define HDR_CS_ID_MAP_TYPE_EMPTY 1      // Introduced by 3GPP TS-33.180 E.1.2
#define HDR_CS_ID_MAP_TYPE_GENERIC_ID 2 // Introduced by RFC 6043 Table 6.4 (See TS-33.180 E.1.2)
#define HDR_CS_ID_MAP_TYPE_IPSEC4_ID 7
#include <libmutil/MemObject.h>
#include <vector>

// CS-ID assignment from TS-33.180 $E.1.3-1
#define CS_ID_INITIATOR_MCPTT_PRIVATE_CALL    0
#define CS_ID_RECEIVER_MCPTT_PRIVATE_CALL     1
#define CS_ID_INITIATOR_MCVIDEO_PRIVATE_CALL  2
#define CS_ID_RECEIVER_MVIDEO_PRIVATE_CALL    3
#define CS_ID_MCPTT_GROUP_CALL                4
#define CS_ID_MCVIDEO_GROUP_CALL              5
#define CS_ID_CSK_SRTCP_FOR_MCPTT             6
#define CS_ID_MUSIK_SRTCP_FOR_MCPTT           7
#define CS_ID_CSK_SRTCP_FOR_MCVIDEO           8
#define CS_ID_MUSIK_SRTCP_FOR_MCVIDEO         9

#define GENERIC_ID_SPI_MAX  32

// CS# info for srtp
class LIBMIKEY_API MikeySrtpCs {
  public:
    MikeySrtpCs(uint8_t policyNo, uint32_t ssrc, uint32_t roc = 0);
    uint8_t  policyNo;
    uint32_t ssrc;
    uint32_t roc;
};

// CS# info for ipv4 IPSEC
// each CS# is related to an unique combination of spi and spiaddresses.
class LIBMIKEY_API MikeyIPSEC4Cs {
  public:
    MikeyIPSEC4Cs(uint8_t policyNo, uint32_t spi, uint32_t spiSrcaddr, uint32_t spiDstaddr);
    uint8_t  policyNo;
    uint32_t spi;
    uint32_t spiSrcaddr;
    uint32_t spiDstaddr;
};

using libmutil::MObject;
class LIBMIKEY_API MikeyCsIdMap : public MObject {
  public:
    virtual int         length() const                               = 0;
    virtual void        writeData(uint8_t* start, int expectedLength) = 0;
    virtual uint8_t     getNumberCs()                                 = 0; // Report the number of Crypto-Sessions present in each bundle (to fill #CS)
    virtual std::string debugDump()                                  = 0;
    std::string getMemObjectType() const override {
        return "MikeyCsIdMap";
    };
};

// Srtp map
class LIBMIKEY_API MikeyCsIdMapSrtp : public MikeyCsIdMap {
  public:
    MikeyCsIdMapSrtp();
    MikeyCsIdMapSrtp(uint8_t* data, int length);
    ~MikeyCsIdMapSrtp() override;

    int  length() const override;
    void writeData(uint8_t* start, int expectedLength) override;

    std::string debugDump() override;
    uint8_t     getNumberCs() override;

    uint8_t   findCsId(uint32_t ssrc);
    uint32_t findRoc(uint32_t ssrc);
    uint8_t   findpolicyNo(uint32_t ssrc);
    void     addStream(uint32_t ssrc, uint32_t roc = 0, uint8_t policyNo = 0, uint8_t csId = 0);

    void setRoc(uint32_t roc, uint8_t csId);
    void setSsrc(uint32_t ssrc, uint8_t csId);

  private:
    std::vector<MikeySrtpCs*> cs;
};

// ipv4 IPSEC map
class LIBMIKEY_API MikeyCsIdMapIPSEC4 : public MikeyCsIdMap {
  public:
    MikeyCsIdMapIPSEC4();
    MikeyCsIdMapIPSEC4(uint8_t* data, int length);
    ~MikeyCsIdMapIPSEC4() override;

    int         length() const override;
    void        writeData(uint8_t* start, int expectedLength) override;
    std::string debugDump() override;
    uint8_t     getNumberCs() override;

    MikeyIPSEC4Cs* getCsIdnumber(int number);
    uint8_t         findCsId(uint32_t spi, uint32_t spiSrcaddr, uint32_t spiDstaddr);
    uint8_t         findpolicyNo(uint32_t spi, uint32_t spiSrcaddr, uint32_t spiDstaddr);
    void           addSA(uint32_t spi, uint32_t spiSrcaddr, uint32_t spiDstaddr, uint8_t policyNo = 0, uint8_t csId = 0);

  private:
    std::list<MikeyIPSEC4Cs*> cs;
};

// Srtp map
class LIBMIKEY_API MikeyCsIdMapGenericId : public MikeyCsIdMap {
  public:
    //MikeyCsIdMapGenericId();
    MikeyCsIdMapGenericId(uint8_t csId, uint8_t protType, bool sessionDataFlag, uint8_t securityPoliciesNumber, uint8_t securityPolicy, uint8_t spiLen, uint8_t* spi);
    MikeyCsIdMapGenericId(uint8_t* data, int length);
    //~MikeyCsIdMapGenericId() override;

    int  length() const override;
    void writeData(uint8_t* start, int expectedLength) override;
    uint8_t     getNumberCs() override;

    std::string debugDump() override;

    uint8_t   findCsId(uint32_t ssrc);

  private:
    uint8_t   csId;
    uint8_t   protType;
    bool      sessionDataFlag;
    uint8_t   securityPoliciesNumber;
    uint8_t   securityPolicy;
    uint16_t  sessionDataLen;
    uint8_t   spiLen;
    uint8_t   spi[GENERIC_ID_SPI_MAX];
    uint32_t  totalLen;
};

#endif
