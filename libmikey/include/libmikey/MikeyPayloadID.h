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

#ifndef MIKEYPAYLOADID_H
#define MIKEYPAYLOADID_H

#include <libmikey/libmikey_config.h>

#include <libmikey/MikeyPayload.h>

#define MIKEYPAYLOAD_ID_PAYLOAD_TYPE 6
#define MIKEYPAYLOAD_IDR_PAYLOAD_TYPE 14

enum MikeyPayloadIDType : uint8_t {
    MIKEYPAYLOAD_ID_TYPE_NAI         = 0,
    MIKEYPAYLOAD_ID_TYPE_URI         = 1,
    MIKEYPAYLOAD_ID_TYPE_BYTE_STRING = 2,
};

// RFC-6043
enum MikeyPayloadIDRole : uint8_t {
    MIKEYPAYLOAD_ID_ROLE_UNSPECIFIED    = 0,
    MIKEYPAYLOAD_ID_ROLE_INITIATOR      = 1,
    MIKEYPAYLOAD_ID_ROLE_RESPONDER      = 2,
    MIKEYPAYLOAD_ID_ROLE_KMS            = 3,
    MIKEYPAYLOAD_ID_ROLE_PRE_SHARED_KEY = 4,
    MIKEYPAYLOAD_ID_ROLE_APPLICATION    = 5,
    MIKEYPAYLOAD_ID_ROLE_INITIATOR_KMS  = 6, // RFC-6509
    MIKEYPAYLOAD_ID_ROLE_RESPONDER_KMS  = 7, // RFC-6509
};

/**
 * @author Erik Eliasson, Johan Bilien
 */
class LIBMIKEY_API MikeyPayloadID : public MikeyPayload {
  public:
    MikeyPayloadID(MikeyPayloadIDType type, int idLength, uint8_t* idData, MikeyPayloadIDRole = MIKEYPAYLOAD_ID_ROLE_UNSPECIFIED);
    MikeyPayloadID(uint8_t* start, int lengthLimit, bool expectIDR = false);
    MikeyPayloadID(const MikeyPayloadID& other) = delete;
    ~MikeyPayloadID() override;

    void        writeData(uint8_t* start, int expectedLength) override;
    int         length() const override;
    std::string debugDump() override;

    MikeyPayloadIDType idType() const;
    MikeyPayloadIDRole idRole() const;

    int            idLength() const;
    const uint8_t* idData() const;

    MikeyPayloadID& operator=(const MikeyPayloadID& other) = delete;

  private:
    MikeyPayloadIDType idTypeValue;
    MikeyPayloadIDRole idRoleValue;
    int                idLengthValue;
    uint8_t*           idDataPtr;
};

#endif
