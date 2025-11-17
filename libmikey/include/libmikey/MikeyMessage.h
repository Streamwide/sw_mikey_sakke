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

#ifndef MIKEYMESSAGE_H
#define MIKEYMESSAGE_H

#include <libmikey/libmikey_config.h>

#include <libmikey/MikeyDefs.h>
#include <libmutil/MemObject.h>

#include <cassert>

#include <libmikey/MikeyPayload.h>
#include <libmikey/MikeyPayloadSIGN.h>

#include <iostream>
#include <libmikey/KeyAgreement.h>
#include <list>
#include <memory>

#define MIKEY_TYPE_PSK_INIT 0
#define MIKEY_TYPE_PSK_RESP 1
#define MIKEY_TYPE_PK_INIT 2
#define MIKEY_TYPE_PK_RESP 3
#define MIKEY_TYPE_DH_INIT 4
#define MIKEY_TYPE_DH_RESP 5
#define MIKEY_TYPE_ERROR 6
#define MIKEY_TYPE_DHHMAC_INIT 7
#define MIKEY_TYPE_DHHMAC_RESP 8
#define MIKEY_TYPE_RSA_R_INIT 9
#define MIKEY_TYPE_RSA_R_RESP 10
#define MIKEY_TYPE_SAKKE_INIT 26
#define MIKEY_TYPE_SAKKE_RESP 27
#define MIKEY_TYPE_CSID_RESP 27 // possible alternative 'more general' spelling for SAKKE_RESP

#define MIKEY_ENCR_NULL 0
#define MIKEY_ENCR_AES_CM_128 1
#define MIKEY_ENCR_AES_KW_128 2

#define MIKEY_MAC_NULL 0
#define MIKEY_MAC_HMAC_SHA1_160 1

static constexpr int64_t MAX_TIME_OFFSET = (int64_t)0xe100000 << 16; // 1 hour

class aes;
class Certificate;
class CertificateSet;
class KeyAgreement;
class KeyAgreementDH;
class KeyAgreementDHHMAC;
class KeyAgreementPKE;
class KeyAgreementPSK;
class KeyAgreementRSAR;
class KeyAgreementSAKKE;
class MikeyPayloadID;
class MikeyMessage;

using libmutil::MRef;

class LIBMIKEY_API MikeyPayloads : public MObject {
  public:
    MikeyPayloads();
    MikeyPayloads(int firstPayloadType, uint8_t* message, int lengthLimit);
    ~MikeyPayloads() override;

    const char* payloadTypeToString(int e);

    void addPayload(MRef<MikeyPayload*> payload);
    void operator+=(MRef<MikeyPayload*> payload);

    void addPkeKemac(KeyAgreementPKE* ka, int encrAlg, int macAlg);
    bool extractPkeEnvKey(KeyAgreementPKE* ka) const;

    void                  addId(const std::string& id);
    const MikeyPayloadID* extractId(int index) const;
    std::string           extractIdStr(int index) const;
    std::vector<uint8_t>  extractIdVec(int index) const;

    std::string debugDump();
    uint8_t*    rawMessageData();
    uint32_t    rawMessageLength() const;
    uint32_t    rawMessageLengthAsOutput() const;

    std::list<MRef<MikeyPayload*>>::const_iterator firstPayload() const;
    std::list<MRef<MikeyPayload*>>::const_iterator lastPayload() const;

    std::list<MRef<MikeyPayload*>>::iterator firstPayload();
    std::list<MRef<MikeyPayload*>>::iterator lastPayload();

    MRef<MikeyPayload*>       extractPayload(int type);
    MRef<const MikeyPayload*> extractPayload(int type) const;
    void                      remove(MRef<MikeyPayload*>);

    std::string b64Message();

  protected:
    static void parse(int firstPayloadType, uint8_t* message, int lengthLimit, std::list<MRef<MikeyPayload*>>& payloads);

    void                 addPolicyToPayload(KeyAgreement* ka);
    void                 addPolicyTo_ka(KeyAgreement* ka);
    std::vector<uint8_t> buildSignData(size_t sigLength, bool addIdsAndT = false);

    /**
     * Store pointer to raw data.
     * It's owned by this object,
     * and will be deleted in destructor.
     */
    void setRawMessageData(uint8_t* data, uint32_t len);

    bool verifyMac(KeyAgreementPSK* ka, int macAlg, const uint8_t* receivedMac, const uint8_t* macInput, unsigned int macInputLength) const;

    /** Derive the transport keys from the env_key and set ka auth key */
    bool deriveTranspKeys(KeyAgreementPSK* ka, uint8_t*& encrKey, uint8_t*& iv, unsigned int& encrKeyLength, int encrAlg, int macAlg,
                          uint64_t t, MikeyMessage* errorMessage);

    std::list<MRef<MikeyPayload*>> payloads;

  private:
    void     compile();
    bool     compiled;
    uint8_t* rawData;
    uint32_t rawLen;
};

/**
 * MikeyMessages can be created in three different ways.
 * 1. new MikeyMessages creates an empty message
 * 2. MikeyMessage::create creates a message from a keyagreement
 * 3. MikeyMessage::parse creates a message from a binary representation
 */
class LIBMIKEY_API MikeyMessage : public MikeyPayloads {
  public:
    static MikeyMessage* create(KeyAgreementDH* ka);
    static MikeyMessage* create(KeyAgreementDHHMAC* ka, int macAlg = MIKEY_MAC_HMAC_SHA1_160);
    static MikeyMessage* create(KeyAgreementPSK* ka, int encrAlg = MIKEY_ENCR_AES_CM_128, int macAlg = MIKEY_MAC_HMAC_SHA1_160);

    // added by choehn
    static MikeyMessage* create(KeyAgreementPKE* ka, int encrAlg = MIKEY_ENCR_AES_CM_128, int macAlg = MIKEY_MAC_HMAC_SHA1_160);
    static MikeyMessage* create(KeyAgreementRSAR* ka);

    template <class KeyAgreementGeneric>
    static MikeyMessage* create(KeyAgreementGeneric* ka) {
        return ka->createMessage();
    }

    /**
     * Parse MIKEY message from binary representation
     * @arg message is owned by this object,
     * and will be deleted in destructor.
     */
    static MikeyMessage* parse(uint8_t* message, int lengthLimit);
    static MikeyMessage* parse(const std::string& b64Message);

    ~MikeyMessage() override;

    int      type() const;
    uint32_t csbId();

    virtual MRef<MikeyMessage*> parseResponse(KeyAgreement* ka);
    virtual void                setOffer(KeyAgreement* ka);
    virtual MRef<MikeyMessage*> buildResponse(KeyAgreement* ka);
    virtual bool                authenticate(KeyAgreement* ka);

    virtual bool                                  isInitiatorMessage() const;
    virtual bool                                  isResponderMessage() const;
    virtual int32_t                               keyAgreementType() const;
    virtual std::shared_ptr<KeyParametersPayload> keyParameters(uint8_t* key) const;

  private:
};

#endif
