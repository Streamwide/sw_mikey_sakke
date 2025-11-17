#include <cstring>
#include <libmikey/MikeyMcDataProtected.h>
#include <libmikey/MikeyKeyParameters.h>
#include <libmikey/MikeyException.h>
#include <libmutil/stringutils.h>
#include <libmutil/Logger.h>
#include <util/mcdata-crypto.h>
#include <mscrypto/sakke.h>
#include <libmcrypto/rand.h>

using namespace std;
using libmutil::itoa;
using libmutil::binToHex;

uint8_t *doEncryptCustom(const int algo, const uint8_t* enc_key, const uint8_t* clear, const uint32_t clear_len, const uint8_t* ad, const uint8_t ad_len, const uint8_t* iv, const uint8_t iv_len, uint32_t* len_out);
uint8_t *doDecryptCustom(const int algo, const uint8_t* enc_key, const uint8_t* clear, const uint32_t clear_len, const uint8_t* ad, const uint8_t ad_len, const uint8_t iv_len, uint32_t* len_out);

// See TS-33-180/8.5.4.1
#define MCDATA_AD_LEN 32
#define MCDATA_IV_LEN 16

MikeyMcDataProtected::~MikeyMcDataProtected() {
    if (this->payloadCiphered != nullptr) {
        free(payloadCiphered);
        this->payloadCiphered = nullptr;
        this->payloadCipheredLen = 0;
    }
}

// Creation of payload during an I-MESSAGE generation
MikeyMcDataProtected::MikeyMcDataProtected(uint8_t* payloadToProtect, uint16_t payloadToProtectLen, uint8_t* key, uint32_t dppkId) {
    // See TS-33-180/8.5.4.1
    this->messageType           = MCDATA_PAYLOAD_PROTECTED; // See TS-24.282/15.2.2 (bit7=Encryption, bit8=Authentication)
    this->dateTime              = 1;                        // Datetime of the protected payload creation
    this->payloadId             = 0;                        // Static value 0 for 3GPP key parameter
    this->payloadSequenceNumber = 0;                        // Static value 0 for 3GPP key parameter
    this->payloadAlgorithm      = MCDATA_AEAD_AES_128_GCM;
    this->signalingAlgorithm    = MCDATA_AEAD_AES_128_GCM;
    uint8_t includeSignalingAlgorithm = 0;
    Rand::randomize(this->iv, MCDATA_IV_LEN);
    this->dppkId                = dppkId;                   // Should be same as CSB-ID (present in HDR)
    this->payloadCiphered       = NULL;                     // Payload is to be encrypted with SSV
    this->payloadCipheredLen    = 0;

    uint8_t ad[MCDATA_AD_LEN];
    uint8_t n = 0;
    ad[n++]  = static_cast<uint8_t>(messageType);
    ad[n++]  = (dateTime & 0xFF00000000) >> 32;
    ad[n++]  = (dateTime & 0xFF000000) >> 24;
    ad[n++]  = (dateTime & 0xFF0000) >> 16;
    ad[n++]  = (dateTime & 0xFF00) >> 8;
    ad[n++]  = (dateTime & 0xFF);
    ad[n++]  = (payloadId & 0xFF000000) >> 24;
    ad[n++]  = (payloadId & 0xFF0000) >> 16;
    ad[n++]  = (payloadId & 0xFF00) >> 8;
    ad[n++]  = (payloadId & 0xFF);
    ad[n++]  = payloadSequenceNumber;
    ad[n++]  = payloadAlgorithm;
    memcpy(ad+12, iv, MCDATA_IV_LEN);
    n += MCDATA_IV_LEN;
    ad[n++]  = (dppkId & 0xFF000000) >> 24;
    ad[n++]  = (dppkId & 0xFF0000) >> 16;
    ad[n++]  = (dppkId & 0xFF00) >> 8;
    ad[n++]  = (dppkId & 0xFF);
    uint32_t lenOut = 0;
    
    OctetString dppkIdOs {4, ad+n-4};
    OctetString dppkOs {16, key};
    std::vector<uint8_t> dpck = MikeySakkeCrypto::DerivateDppkToDpck(dppkIdOs, dppkOs);
    this->payloadCiphered = doEncryptCustom(MCDATA_AEAD_AES_128_GCM, dpck.data(), payloadToProtect, payloadToProtectLen, ad, MCDATA_AD_LEN, this->iv, MCDATA_IV_LEN, &lenOut);
    if (this->payloadCiphered == NULL) {
        throw MikeyExceptionMessageContent("McData: cannot generate ProtectedPayload");
    }
    if (lenOut > MCDATA_IV_LEN) {
        // doEncrypCustom does generate a format like this: CIPHER_DATA(len=clear_len)|TAG(16B)|IV(12B) -> need to remove the IV
        this->payloadCipheredLen = lenOut - MCDATA_IV_LEN;
    }

    this->size = 35 + includeSignalingAlgorithm + this->payloadCipheredLen;
    // TODO dppkId
}

// Parse a McDataProtect payload from an I-MESSAGE read
MikeyMcDataProtected::MikeyMcDataProtected(uint8_t* start, int lengthLimit) {
    if (lengthLimit < 16) {
        throw MikeyExceptionMessageLengthException("Given data is too short to form a McDataProtected Payload");
    }
    MIKEY_SAKKE_LOGD("MikeyMcDataProtected Input: %s", binToHex(start, 71).c_str());
    this->payloadCiphered = nullptr;
    this->payloadCipheredLen = 0;
    this->size = 0;
    this->keyParams = nullptr;
    this->signalingAlgorithm = 0;

    // See TS-33-180/8.5.4.1
    //    1B: Message type
    //    5B: DateTime of creation of the payload
    //    4B: PayloadID identifier for the payload
    //    1B: Payload Sequence Number for the payload
    //    1B: Payload algorithm encryption
    //    1B: Signalling algorithm encryption (optional ?)
    //   16B: IV
    //    4B: DPPK-ID identifier of the key which is used to encript the payload
    //  2-XB: ProtectedPayload itself
    //  (XB): MIKEY-SAKKE_IMESSAGE (not supported currently)
    //
    // AD (for auth tag in AEAD_AES) is MessageType|DateTime|PayloadID|PayloadSN|P-Algorithm|IV|DPPK-ID

    uint32_t n = 0;
    this->messageType           = start[n++];
    this->dateTime              = (uint64_t)start[n] << 32 | (uint64_t)start[n+1] << 24 | (uint64_t)start[n+2] << 16 | (uint64_t)start[n+3] << 8 | (uint64_t)start[n+4];
    n += 5;
    this->payloadId             = (uint32_t)start[n] << 24 | (uint32_t)start[n+1] << 16 | (uint32_t)start[n+2] << 8 | (uint32_t)start[n+3];
    n += 4;
    this->payloadSequenceNumber = start[n++];
    this->payloadAlgorithm      = start[n++];
    //this->signalingAlgorithm    = start[n++]; // It is an optional field, what is the conditional criteria ?


    // Compatibility mode with I-MESSAGE generated <= 1.1.13 or 2.0.2 (McDataProtected was directly a KeyParametersPayload)
    // Also the "messageType" had an incorrect value (starting from 1 instead of 0)
    if ((lengthLimit == 20 || lengthLimit == 21) && this->messageType >= 0x1 && this->messageType <= 0x3 // Before fix, GMK=1, PCK=2, CSK=3
        && this->dateTime == 256 && this->payloadId == 0 && this->payloadSequenceNumber == 0
        && this->payloadAlgorithm == 0 && this->signalingAlgorithm == 0) {
        // Create static entry (as it was in the past)
        this->keyParams = std::make_shared<KeyParametersPayload>(static_cast<KeyParametersPayload::KeyType>(this->messageType - 1), KeyParametersPayload::NOT_REVOKED, 0, 0, "");
    } else {
        // Normal case (delete the compatility mode in the future)
        uint32_t n_startiv = n;
        if (n + MCDATA_IV_LEN > (uint32_t)lengthLimit) {
            MIKEY_SAKKE_LOGE("McDataProtected: payloadLen is too small to copy IV");
            throw MikeyExceptionMessageLengthException("McDataProtected: payloadLen is too small to copy IV");
        }
        memcpy(this->iv, start+n, MCDATA_IV_LEN);
        n += MCDATA_IV_LEN;
        this->dppkId                = (uint32_t)start[n] << 24 | (uint32_t)start[n+1] << 16 | (uint32_t)start[n+2] << 8 | (uint32_t)start[n+3];
        n += 4;
        this->payloadCipheredType   = start[n++];
        MIKEY_SAKKE_LOGD("-->> CipheredPayoad in McData struct: %s", binToHex(start+n, lengthLimit-n).c_str());
        this->payloadCipheredLen    = (uint16_t)start[n] << 8 | (uint16_t)start[n+1];
        n += 2;
        this->payloadCipheredLen    = lengthLimit - n;
        if (n + this->payloadCipheredLen > (uint32_t)lengthLimit) {
            MIKEY_SAKKE_LOGE("McDataProtected: payloadLen is too small to copy cipheredPayload");
            throw MikeyExceptionMessageLengthException("McDataProtected: payloadLen is too small to copy cipheredPayload");
        }
        this->payloadCiphered       = (uint8_t*)malloc((this->payloadCipheredLen + MCDATA_IV_LEN) * sizeof(this->payloadCiphered));
        memcpy(this->payloadCiphered, start + n, this->payloadCipheredLen);
        memcpy(this->payloadCiphered + this->payloadCipheredLen, this->iv, MCDATA_IV_LEN);

        // Preparing Associated-Data
        memcpy(this->ad, start, 12);
        memcpy(this->ad+12, start+n_startiv, 20);
    }
    size=n+this->payloadCipheredLen;
}

int MikeyMcDataProtected::length() const {
    return size;
}

uint8_t* MikeyMcDataProtected::bytes() const {
    uint8_t*    payload = nullptr;
    uint8_t     n       = 0;

    //    1B: Message type
    //    5B: DateTime of creation of the payload
    //    4B: PayloadID identifier for the payload
    //    1B: Payload Sequence Number for the payload
    //    1B: Payload algorithm encryption
    //    1B: Signalling algorithm encryption (optional ?)
    //   16B: IV
    //    4B: DPPK-ID identifier of the key which is used to encript the payload
    //  2-XB: ProtectedPayload itself
    //  (XB): MIKEY-SAKKE_IMESSAGE (not supported currently)

    payload       = new uint8_t[size]();
    payload[n++]  = messageType;
    payload[n++]  = (dateTime & 0xFF00000000) >> 32;
    payload[n++]  = (dateTime & 0xFF000000) >> 24;
    payload[n++]  = (dateTime & 0xFF0000) >> 16;
    payload[n++]  = (dateTime & 0xFF00) >> 8;
    payload[n++]  = (dateTime & 0xFF);
    payload[n++]  = (payloadId & 0xFF000000) >> 24;
    payload[n++]  = (payloadId & 0xFF0000) >> 16;
    payload[n++]  = (payloadId & 0xFF00) >> 8;
    payload[n++]  = (payloadId & 0xFF);
    payload[n++]  = payloadSequenceNumber;
    payload[n++]  = payloadAlgorithm;
    //payload[n++]  = signalingAlgorithm;
    memcpy(payload+n, iv , 16);
    n             += 16;
    payload[n++]  = (dppkId & 0xFF000000) >> 24;
    payload[n++]  = (dppkId & 0xFF0000) >> 16;
    payload[n++]  = (dppkId & 0xFF00) >> 8;
    payload[n++]  = (dppkId & 0xFF);
    payload[n++]  = 0; // Type of TLV-E ProtectedPayload <--- Where does this value is defined ?
    payload[n++]  = (payloadCipheredLen & 0xFF00) >> 8;
    payload[n++]  = (payloadCipheredLen & 0xFF);
    memcpy(payload+n, payloadCiphered, payloadCipheredLen);
    n             += payloadCipheredLen;

    if (n != length()) {
        throw MikeyExceptionMessageContent("MikeyMcDataProtected: Unexpected len");
    }
    return payload;
}

std::string MikeyMcDataProtected::string() {
    std::string ret = "MikeyMcDataProtected: MessageType=";
    switch (this->messageType) {
        case MCDATA_PAYLOAD_PROTECTED:
            ret = ret + "MCDATA_PAYLOAD_PROTECTED";
            break;
        default:
            ret = ret + "UNKNOWN(" + itoa(this->messageType) + ")";
    }

    ret += " dateTime=" + itoa(this->dateTime);
    ret += " payloadID=" + itoa(this->payloadId);
    ret += " payloadSN=" + itoa(this->payloadSequenceNumber);
    ret += " payloadAlgo=" + itoa(this->payloadAlgorithm);
    ret += " signalingAlgo=" + itoa(this->signalingAlgorithm);
    std::stringstream stream;
    stream << std::hex << this->dppkId;
    ret += " DPPK-ID=" + stream.str();
    ret += "\nPayload(len="+itoa(this->payloadCipheredLen)+"): {\n";
    ret += "type: " + itoa(payloadCipheredType) + "\n";
    ret += "ad  : " + OctetString{MCDATA_AD_LEN, this->ad}.translate() + "\n";
    ret += "iv  : " + OctetString{MCDATA_IV_LEN, this->iv}.translate() + "\n";
    ret += (this->keyParams == nullptr ? "not yet unciphered: "+OctetString{this->payloadCipheredLen + (uint32_t)MCDATA_IV_LEN, this->payloadCiphered}.translate() : this->keyParams->string()) + "\n}\n";

    return ret;
}

// keyDpck is the secret extracted from SAKKE with a derivation
std::shared_ptr<KeyParametersPayload> MikeyMcDataProtected::getKeyParams(uint8_t* keyDpck) {
    if (this->keyParams != nullptr) {
        return this->keyParams;
    }

    if (keyDpck == NULL || this->payloadCiphered == NULL || this->payloadCipheredLen == 0) {
        MIKEY_SAKKE_LOGE("MikeyMcDataProtected::getKeyParams: invalid value keyDpck[%p], payload[%p] len[%d]", keyDpck, this->payloadCiphered, this->payloadCipheredLen);
        return nullptr;
    }

    uint32_t lenOut = 0;
    // Add IV_LEN as the IV has been added ad-hoc
    uint8_t* payload = doDecryptCustom(MCDATA_AEAD_AES_128_GCM, keyDpck, this->payloadCiphered, this->payloadCipheredLen + MCDATA_IV_LEN, this->ad, MCDATA_AD_LEN, MCDATA_IV_LEN, &lenOut);

    if (payload == NULL) {
        MIKEY_SAKKE_LOGE("MikeyMcDataProtected::getKeyParams: cannot decrypt");
        return nullptr;
    }
    MIKEY_SAKKE_LOGD("Decrypted(%d) payload[%s]", lenOut, binToHex(payload, 20).c_str());
    if (lenOut == 0) {
        // Tag has not been verified, integrity is not assured
        MIKEY_SAKKE_LOGE("MikeyMcDataProtected::getKeyParams: cannot authenticate ciphered payload");
        free(payload);
        return nullptr;
    }
    if (this->messageType == MCDATA_PAYLOAD_PROTECTED || this->messageType == MCDATA_ENCRIPTED_NO_TYPE) {
        this->keyParams = std::make_shared<KeyParametersPayload>(payload, lenOut);
    } else {
        MIKEY_SAKKE_LOGE("MikeyMcDataProtected: type[%d] not supported", this->messageType);
    }

    free(payload);
    free(this->payloadCiphered);
    this->payloadCiphered = nullptr;
    this->payloadCipheredLen = 0;
    return this->keyParams;
}