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

#ifndef MIKEYPAYLOADV_H
#define MIKEYPAYLOADV_H

#include <libmikey/libmikey_config.h>

#include <libmikey/MikeyPayload.h>

#define MIKEYPAYLOAD_V_PAYLOAD_TYPE 9

#define MIKEY_PAYLOAD_V_MAC_NULL 0
#define MIKEY_PAYLOAD_V_MAC_HMAC_SHA1_160 1
/**
 * @author Erik Eliasson, Johan Bilien
 */
class LIBMIKEY_API MikeyPayloadV : public MikeyPayload {
  public:
    MikeyPayloadV(int mac_alg, uint8_t* verData);
    MikeyPayloadV(uint8_t* start, int lengthLimit);
    MikeyPayloadV(const MikeyPayloadV& other) = delete;
    ~MikeyPayloadV() override;

    void writeData(uint8_t* start, int expectedLength) override;
    int  length() const override;

    int     macAlg();
    uint8_t* verData();

    void setMac(uint8_t* data);

    MikeyPayloadV& operator=(const MikeyPayloadV& other) = delete;

  private:
    int     macAlgValue;
    uint8_t* verDataPtr;
};

#endif
