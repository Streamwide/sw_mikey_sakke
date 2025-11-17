/*
 Copyright (C) 2004-2007 the Minisip Team

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
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

/* Copyright (C) 2004-2007
 *
 * Authors: Erik Eliasson <eliasson@it.kth.se>
 *          Johan Bilien <jobi@via.ecp.fr>
 *          Mikael Magnusson <mikma@users.sourceforge.net>
 */

#ifndef MIKEY_H
#define MIKEY_H

#include <libmikey/libmikey_config.h>

#include <libmikey/KeyAgreement.h>
#include <libmutil/MemObject.h>

#include <mskms/client-fwd.h>

#include <KMClient.h>

#define FIND_PERIOD_MAX_GAP 32
#define MIKEY_SAKKE_UID_LEN 64

typedef struct mikey_clear_info
{
  uint32_t  key_id;
  uint32_t  creationTimeNtp;
  char      initiatorId[MIKEY_SAKKE_UID_LEN+1];
  char      responderId[MIKEY_SAKKE_UID_LEN+1];
  bool      uidFilled;
} mikey_clear_info_t;


class LIBMIKEY_API IMikeyConfig : public virtual MObject {
  public:
    ~IMikeyConfig() override;

    virtual MikeySakkeKMS::KeyAccessPtr getKeys() const = 0;

    virtual const std::string getUri() const = 0;

    virtual size_t         getPskLength() const = 0;
    virtual const uint8_t* getPsk() const       = 0;

    virtual bool isMethodEnabled(int kaType) const = 0;

    virtual bool isCertCheckEnabled() const = 0;

    virtual void setPayloadSignatureValidation(bool verif) = 0;
    virtual bool payloadSignatureValidation() const = 0;
};

class LIBMIKEY_API Mikey : public MObject {
  public:
    enum State { STATE_START = 0, STATE_INITIATOR, STATE_RESPONDER, STATE_AUTHENTICATED, STATE_ERROR };

    typedef std::vector<uint32_t> Streams;

    explicit Mikey(MRef<IMikeyConfig*> config);
    explicit Mikey();
    ~Mikey() override;

    /* Key management handling */
    // Initiator methods
    bool displayIMessageInfo(const std::string& message);
    static void getClearInfo(MRef<MikeyMessage*>& message, mikey_clear_info_t& info);
    bool getClearInfo(const std::string& message, mikey_clear_info_t& ret);
    uint32_t    inferKeyPeriodNo(mikey_clear_info_t* clearInfo, const char* from_uri);
    std::string initiatorCreate(int kaType, const std::string& peerUri = "", struct key_agreement_params* params = nullptr);
    bool        initiatorAuthenticate(std::string message);
    std::string initiatorParse();

    // Responder methods
    bool responderAuthenticate(const std::string& message, const std::string& peerUri = "", const OctetString& peerId = OctetString());
    std::string responderParse();

    void setMikeyOffer();

    bool                isSecured() const;
    bool                isInitiator() const;
    bool                error() const;
    std::string         authError() const;
    MRef<KeyAgreement*> getKeyAgreement() const;

    void                enableKeyMatAutoDownload(KMClient* client);
    void                disableKeyMatAutoDownload();

    void addSender(uint32_t ssrc);

    const std::string& peerUri() const;

  protected:
    void setState(State newState);

  private:
    void createKeyAgreement(int type, uint32_t keyPeriodNo);
    void addStreamsToKa();

    State               state {STATE_START};
    bool                secured {false};
    MRef<IMikeyConfig*> config;
    Streams             mediaStreamSenders;
    MRef<KeyAgreement*> ka;
    KMClient*           kmsClient;
};

#endif
