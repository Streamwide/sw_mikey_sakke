#ifndef MIKEYKEYPARAMS_H
#define MIKEYKEYPARAMS_H

#include <libmutil/mtypes.h>
#include <string>

static constexpr uint8_t MIKEYPAYLOAD_GENERALEXTENSIONS_PAYLOAD_TYPE_KEY_PARAMETERS = 7;

class KeyParametersPayload {
  public:
    // 3GPP TS 33.180 §E.6.11
    enum class KeyType {
        UNDEFINED = 0,
        GMK,
        PCK,
        CSK,
        SPK,
        MKFC,
        MSCCK,
        MuSiK,
    };

    enum KeyStatus { NOT_REVOKED = 0b1, SHARED_WITH_GATEWAY = 0b10 };

    // TS 24.282 §15.2.14
    struct MCDataGroupID {
        uint8_t  iei;
        uint16_t length;
        uint8_t* data = nullptr;
        ~MCDataGroupID() {
            if (data) {
                delete[] data;
            }
            data = nullptr;
        }
    };

    // TS33.180 §E.6.3
    struct MCGroupIDs {
        uint8_t              numberOfGroupIDs; // This can only be 1 or 0, according to TS 33.179 §E.6.3, V
        struct MCDataGroupID groupID;          // TLV-E
    };

    // Constructor when constructing new KeyparametersPayload
    KeyParametersPayload(KeyType type, KeyStatus status, uint64_t aTime, uint64_t eTime, std::string txt);
    // Constructor when receiving mikey message, to construct the KeyParametersPayload  from bytestream
    KeyParametersPayload(uint8_t* start_of_payload, uint16_t length);

    uint8_t* bytes() const;
    uint16_t length() const {
        return size;
    };
    std::string string() const;

    // For formats, see TS24.379 §Annex I
    KeyType           keyType;        // TS 33.180§E.6.11, format V
    uint32_t          keyStatus;      //§E.6.9, format V
    uint64_t          activationTime; //§E.6.4, format V
    uint64_t          expiryTime;     //§E.6.10, format V
    std::string       text;           //§E.6.5, format LV-E
    uint16_t          MCGroupIDslen;
    struct MCGroupIDs mcGroupIDsPayload; //§E.6.3, format LV-E
  private:
    uint16_t size;
};

#endif