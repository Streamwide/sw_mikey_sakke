#ifndef MIKEYMCDATAPROTECTED_H
#define MIKEYMCDATAPROTECTED_H

#include <libmikey/MikeyKeyParameters.h>
#include <libmikey/MikeyPayload.h>
#include <libmikey/libmikey_config.h>
#include <memory>

static constexpr int MCDATA_PAYLOAD_PROTECTED = 0x43; // Data Payload with encryption + no authentication (See TS-24.282/15.2.2)
static constexpr int MCDATA_ENCRIPTED_NO_TYPE = 0x40; // Type = 0 but bit 7(encryption) is on

class MikeyMcDataProtected {
  public:
    // Constructor when receiving Mikey message i.e. contruct MikeyMcDataProtected from bytestream.
    MikeyMcDataProtected(uint8_t* start, int length);
    // Constructor when constructing new MikeyMcDataProtected message
    MikeyMcDataProtected(uint8_t* payloadToProtect, uint16_t payloadLen, uint8_t* key, uint32_t dppkId);
    // Destructor
    ~MikeyMcDataProtected();
    // Generates bytestream of MikeyMcDataProtected
    uint8_t* bytes() const;
    // Return a KeyParameters well-structured (if present) or deciphered it with the key if needed
    std::shared_ptr<KeyParametersPayload> getKeyParams(uint8_t* key);
    // Return the length of the GeneralExtension in bytes
    int                           length() const;
    std::string                   string(); // Debugging purpose
    bool isPayloadEncrypted() const {
      return (messageType & 0x40) == 0x40;
    }
    bool isPayloadAuthenticated() const {
      return (messageType & 0x80) == 0x80;
    }
  private:
    uint8_t messageType;
    uint64_t dateTime;
    uint32_t payloadId;
    uint8_t payloadSequenceNumber;
    uint8_t payloadAlgorithm;
    uint8_t signalingAlgorithm;
    uint8_t iv[16];
    uint8_t     payloadCipheredType;
    uint16_t    payloadCipheredLen;
    uint8_t*    payloadCiphered;
    uint32_t dppkId;
    uint32_t size;
    uint8_t  ad[32];
    std::shared_ptr<KeyParametersPayload> keyParams;
};

#endif /* MIKEYMCDATAPROTECTED_H */
