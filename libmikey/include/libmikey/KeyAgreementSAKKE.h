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

#ifndef KEYAGREEMENT_SAKKE_H
#define KEYAGREEMENT_SAKKE_H

#include <libmikey/KeyAgreement.h>
#include <libmikey/libmikey_config.h>
#include <mskms/client-fwd.h>
#include <KMClient.h>

#include <optional>

struct OctetString;

uint64_t Get3GPPSecondsNow64();

/* Generates Mikey-Sakke UID (format 2) with current time
 * to overwrite current time, use fifth argument to provide a period number
 */
OctetString genMikeySakkeUid(std::string uri, std::string kms_uri, uint32_t key_period, uint32_t key_period_offset,
                             std::optional<uint32_t> current_key_period_no = std::nullopt);

class LIBMIKEY_API KeyAgreementSAKKE : public KeyAgreement {
  public:
    explicit KeyAgreementSAKKE(MikeySakkeKMS::KeyAccessPtr, KMClient* kmsClient, uint32_t keyPeriodNo);
    // ~KeyAgreementSAKKE();

  public:
    int32_t type() override {
        return KEY_AGREEMENT_TYPE_SAKKE;
    }

    MikeyMessage* createMessage(struct key_agreement_params* params) override;

    MikeySakkeKMS::KeyAccessPtr const& getKeyMaterial() const {
        return keys;
    }

    void setTgk(uint8_t* tgk, unsigned int tgkLength) override;
    void setKfc(uint8_t* kfc, unsigned int kfcLength) override;

  public: // client utilities
    static bool ValidateKeyMaterial(MikeySakkeKMS::KeyStoragePtr const& keys, std::string const& identifier, std::string* error_text);
    void        autoDownloadKeys(uint32_t timestampPeriod, OctetString& user_id, uint32_t retries);
    uint32_t    getKeyPeriodNo();

  protected:
    KeyAgreementSAKKE();

  private:
    MikeySakkeKMS::KeyAccessPtr keys;
    KMClient*                   kmsClient;
    uint32_t                    keyPeriodNo;
};

#endif
