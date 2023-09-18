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

#ifndef MIKEYPAYLOADRAND_H
#define MIKEYPAYLOADRAND_H

#include <libmikey/libmikey_config.h>

#include <libmikey/MikeyPayload.h>

#define MIKEYPAYLOAD_RAND_PAYLOAD_TYPE 11

/**
 * @author Erik Eliasson, Johan Bilien
 */
class LIBMIKEY_API MikeyPayloadRAND : public MikeyPayload {
  public:
    MikeyPayloadRAND(); // computes a 128 bits random value
    // FIXME almost same prototype, leads to mistake!!
    MikeyPayloadRAND(int randlen, uint8_t* rand_data);
    MikeyPayloadRAND(uint8_t* start, int lengthLimit);
    MikeyPayloadRAND(const MikeyPayloadRAND& other) = delete;
    ~MikeyPayloadRAND() override;

    int         length() const override;
    void        writeData(uint8_t* start, int expectedLength) override;
    std::string debugDump() override;

    int     randLength() const;
    uint8_t* randData();

    MikeyPayloadRAND& operator=(const MikeyPayloadRAND& other) = delete;

  private:
    int     randLengthValue;
    uint8_t* randDataPtr;
};

#endif
