#include <libmikey/MikeyKeyParameters.h>
#include <sstream>

KeyParametersPayload::KeyParametersPayload(KeyType type, KeyStatus status, uint64_t aTime, uint64_t eTime, std::string txt)
    : keyType(type), keyStatus(status), activationTime(aTime), expiryTime(eTime), text(txt) {
    mcGroupIDsPayload.numberOfGroupIDs = 0;

    // In the payload, the text's length has to be encoded on two bytes
    // so the text can't be longer than 0xFFFF (65535) characters
    if (txt.length() > 0xFFFF) {
        txt.resize(0xFFFF);
    }

    /// Compute length of payload
    // TS 33.180 §E.6.1
    static constexpr uint16_t minimum_size = 1 + 1 + 4 + 5 + 5 + 2 + 2;
    // Add text field length
    size = minimum_size + text.length();
    // Compute MCGroupIDs length
    MCGroupIDslen = 0;
    MCGroupIDslen += sizeof(mcGroupIDsPayload.numberOfGroupIDs);

    if (mcGroupIDsPayload.numberOfGroupIDs) {
        MCGroupIDslen += 1 + 2 + mcGroupIDsPayload.groupID.length; // Size of IEI + length size + length value
    }

    size += MCGroupIDslen;
}

KeyParametersPayload::KeyParametersPayload(uint8_t* start_of_payload, uint16_t length) {
    auto payload = start_of_payload;
    size         = length;
    keyType      = static_cast<KeyType>(payload[0]);
    keyStatus    = (uint32_t)payload[1] << 24 | (uint32_t)payload[2] << 16 | (uint32_t)payload[3] << 8 | (uint32_t)payload[4];

    activationTime = (uint64_t)payload[5] << 32 | (uint64_t)payload[6] << 24 | (uint64_t)payload[7] << 16 | (uint64_t)payload[8] << 8
                     | (uint64_t)payload[9];

    expiryTime = (uint64_t)payload[10] << 32 | (uint64_t)payload[11] << 24 | (uint64_t)payload[12] << 16 | (uint64_t)payload[13] << 8
                 | (uint64_t)payload[14];
    uint16_t txt_len = (uint16_t)payload[15] << 8 | (uint16_t)payload[16];
    uint16_t i;
    for (i = 0; i <= txt_len; ++i) {
        text.push_back(payload[16 + i]);
    }
    i             = i + 16;
    MCGroupIDslen = (uint16_t)payload[i] << 8 | (uint16_t)payload[i + 1];
    i += 2;
    if (MCGroupIDslen == 1) {
        mcGroupIDsPayload.numberOfGroupIDs = 0;
    } else {
        mcGroupIDsPayload.numberOfGroupIDs = 1;
        mcGroupIDsPayload.groupID.iei      = payload[i++];
        mcGroupIDsPayload.groupID.length   = (uint16_t)payload[i] << 8 | (uint16_t)payload[i + 1];
        i += 2;
        mcGroupIDsPayload.groupID.data = new uint8_t[mcGroupIDsPayload.groupID.length]();
        for (uint16_t j = 0; j < mcGroupIDsPayload.groupID.length; ++j) {
            mcGroupIDsPayload.groupID.data[j] = payload[i++];
        }
    }
}

uint8_t* KeyParametersPayload::bytes() const {
    uint8_t* payload = nullptr;

    payload     = new uint8_t[size]();
    payload[0]  = MIKEYPAYLOAD_GENERALEXTENSIONS_PAYLOAD_TYPE_KEY_PARAMETERS;
    payload[1]  = (size & 0xFF00) >> 8;
    payload[2]  = size & 0xFF;
    payload[3]  = static_cast<uint8_t>(keyType);
    payload[4]  = (keyStatus & 0xFF000000) >> 24;
    payload[5]  = (keyStatus & 0xFF0000) >> 16;
    payload[6]  = (keyStatus & 0xFF00) >> 8;
    payload[7]  = (keyStatus & 0xFF);
    payload[8]  = (activationTime & 0xFF00000000) >> 32;
    payload[9]  = (activationTime & 0xFF000000) >> 24;
    payload[10] = (activationTime & 0xFF0000) >> 16;
    payload[11] = (activationTime & 0xFF00) >> 8;
    payload[12] = (activationTime & 0xFF);
    payload[13] = (expiryTime & 0xFF00000000) >> 32;
    payload[14] = (expiryTime & 0xFF000000) >> 24;
    payload[15] = (expiryTime & 0xFF0000) >> 16;
    payload[16] = (expiryTime & 0xFF00) >> 8;
    payload[17] = (expiryTime & 0xFF);
    payload[18] = (text.length() & 0xFF00) >> 8;
    payload[19] = (text.length() & 0xFF);
    uint16_t n  = 0;
    if (text.length() > 0) {
        for (n = 0; n < text.length(); ++n) {
            payload[20 + n] = (uint8_t)text[n];
        }
    }

    payload[20 + n++] = (MCGroupIDslen & 0xFF00) >> 8;
    payload[20 + n++] = (MCGroupIDslen & 0xFF);

    payload[20 + n++] = mcGroupIDsPayload.numberOfGroupIDs;

    n += 20;
    if (mcGroupIDsPayload.numberOfGroupIDs) {
        payload[n++] = mcGroupIDsPayload.groupID.iei;
        payload[n++] = (mcGroupIDsPayload.groupID.length & 0xFF00) >> 8;
        payload[n++] = mcGroupIDsPayload.groupID.length & 0xFF;
        for (uint16_t i = 0; i < mcGroupIDsPayload.groupID.length; ++i) {
            payload[n + i] = mcGroupIDsPayload.groupID.data[i];
        }
    }

    return payload;
}

std::string KeyParametersPayload::string() const {
    std::stringstream ss;
    ss << "Keytype : " << static_cast<int>(keyType) << '\n';
    ss << "keyStatus : " << keyStatus << '\n';
    ss << "activationTime : " << activationTime << '\n';
    ss << "expiryTime : " << expiryTime << '\n';
    ss << "text : " << text << std::endl;
    return ss.str();
}