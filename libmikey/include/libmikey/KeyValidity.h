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

#ifndef KEYVALIDITY_H
#define KEYVALIDITY_H

#include <libmikey/libmikey_config.h>

#define KEYVALIDITY_NULL 0
#define KEYVALIDITY_SPI 1
#define KEYVALIDITY_INTERVAL 2

#include <libmikey/MikeyDefs.h>
#include <libmutil/MemObject.h>

#define KeyValidityNull KeyValidity

using libmutil::MObject;

class LIBMIKEY_API KeyValidity : public MObject {
  public:
    KeyValidity();
    KeyValidity(const KeyValidity&);
    ~KeyValidity() override;

    KeyValidity&        operator=(const KeyValidity&);
    virtual int         length() const;
    int                 type();
    virtual void        writeData(uint8_t* start, int expectedLength);
    virtual std::string debugDump();
    std::string getMemObjectType() const override {
        return "KeyValidity";
    };

  protected:
    int typeValue;
};

class LIBMIKEY_API KeyValiditySPI : public KeyValidity {
  public:
    KeyValiditySPI();
    KeyValiditySPI(const KeyValiditySPI&);
    KeyValiditySPI(uint8_t* rawData, int lengthLimit);
    KeyValiditySPI(int length, uint8_t* spi);
    ~KeyValiditySPI() override;

    KeyValiditySPI&     operator=(const KeyValiditySPI&);
    int         length() const override;
    void        writeData(uint8_t* start, int expectedLength) override;
    std::string debugDump() override;

  private:
    int     spiLength;
    uint8_t* spiPtr;
};

class LIBMIKEY_API KeyValidityInterval : public KeyValidity {
  public:
    KeyValidityInterval();
    KeyValidityInterval(const KeyValidityInterval&);
    KeyValidityInterval(uint8_t* rawData, int lengthLimit);
    KeyValidityInterval(int vfLength, uint8_t* vf, int vtLength, uint8_t* vt);
    ~KeyValidityInterval() override;

    KeyValidityInterval& operator=(const KeyValidityInterval&);
    int          length() const override;
    void         writeData(uint8_t* start, int expectedLength) override;
    std::string  debugDump() override;

  private:
    int     vfLength;
    uint8_t* vf;
    int     vtLength;
    uint8_t* vt;
};

#endif
