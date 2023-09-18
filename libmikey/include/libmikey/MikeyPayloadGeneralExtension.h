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

#ifndef MIKEYPAYLOADGENERALEXTENSIONS_H
#define MIKEYPAYLOADGENERALEXTENSIONS_H

#include <libmikey/MikeyKeyParameters.h>
#include <libmikey/MikeyPayload.h>
#include <libmikey/libmikey_config.h>
#include <memory>

static constexpr int MIKEYPAYLOAD_GENERALEXTENSIONS_PAYLOAD_TYPE = 21;

static constexpr int MIKEY_EXT_TYPE_VENDOR_ID = 0; // Vendor specific byte string
static constexpr int MIKEY_EXT_TYPE_SDP_ID    = 1; // List of SDP key mgmt IDs (allocated for use in [KMASDP])

class LIBMIKEY_API MikeyPayloadGeneralExtensions : public MikeyPayload {
  public:
    // Constructor when receiving Mikey message i.e. contruct MikeyPayloadGeneralExtensions from bytestream.
    MikeyPayloadGeneralExtensions(uint8_t* start_of_header, int lengthLimit);
    // Constructor when constructing new MikeyPayloadGeneralExtension message
    MikeyPayloadGeneralExtensions(uint8_t type, uint16_t length, const uint8_t* d);
    // Destructor
    ~MikeyPayloadGeneralExtensions() override;
    // Generates bytestream of MikeyPayloadGeneralExtension
    void writeData(uint8_t* start, int expectedLength) override;
    // Return the length of the GeneralExtension in bytes
    int                           length() const override;
    uint8_t                               type;
    uint16_t                              leng;
    uint8_t*                              data = nullptr;
    std::shared_ptr<KeyParametersPayload> keyParams;

  private:
};

#endif
