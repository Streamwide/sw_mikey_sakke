#include <libmikey/MikeyKeyParameters.h>
#include <libmutil/stringutils.h>
#include <util/octet-string.h>
#include <libmutil/Logger.h>
#include <sstream>
#include <cstring>

using libmutil::itoa;

KeyParametersPayload::KeyParametersPayload(KeyType type, KeyStatus status, uint64_t aTime, uint64_t eTime, std::string txt)
    : keyType(type), keyStatus(status), activationTime(aTime), expiryTime(eTime), text(txt) {
    mcGroupIDsPayload.numberOfGroupIDs = 0;

    // In the payload, the text's length has to be encoded on two bytes
    // so the text can't be longer than 0xFFFF (65535) characters
    if (txt.length() > 0xFFFF) {
        txt.resize(0xFFFF);
    }

    /// Compute length of payload
    // TS 33.180 §E.6.1 ->
    //      1B: KeyType
    //      4B: Status
    //      5B: ActivationTime
    //      5B: ExpiryTime
    //      2B: TextLen + XB of text
    //      (2B): McGroupsIDsLen + XB of GroupsIds <- Only Present in case of GMK/MKFC/MuSiK
    //      XB: Reserved for key info
    static constexpr uint16_t minimum_size = 1 + 4 + 5 + 5 + 2;
    // Add text field length
    size = minimum_size + text.length();
    // Compute MCGroupIDs length (at the end, len will always be >=1, at least for the "numberOfGroupIDs" field)
    MCGroupIDslen = 0;

    if (keyType == KeyType::GMK || keyType == KeyType::MKFC || keyType == KeyType::MuSiK) {
        size += 2; // McGroupsIDsLen (TS 33.180 §E.6.1)
        MCGroupIDslen = 1; // Add 1B for the mandatory "Number of Group IDs" TS 33.180 §E.6.3
        if (mcGroupIDsPayload.numberOfGroupIDs) { // Handle only 1 group for now
            MCGroupIDslen += 1 + 2 + mcGroupIDsPayload.groupID.length; // Size of IEI + length size + length value
        }
    }

    keyStatusRevok = keyStatus & KeyStatus::NOT_REVOKED;
    keyStatusGateway = keyStatus & KeyStatus::SHARED_WITH_GATEWAY;

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
    for (i = 17; i-17 < txt_len; ++i) {
        text.push_back(payload[i]);
    }

    if (keyType == KeyType::GMK || keyType == KeyType::MKFC || keyType == KeyType::MuSiK) {
        MCGroupIDslen = (uint16_t)payload[i] << 8 | (uint16_t)payload[i + 1];
        i += 2;
        if (MCGroupIDslen > 1) {
            mcGroupIDsPayload.numberOfGroupIDs = payload[i++];

            if (mcGroupIDsPayload.numberOfGroupIDs != 0 && MCGroupIDslen > 3) {
                mcGroupIDsPayload.groupID.iei      = payload[i++];
                mcGroupIDsPayload.groupID.length   = (uint16_t)payload[i] << 8 | (uint16_t)payload[i + 1];
                i += 2;
                if (mcGroupIDsPayload.groupID.length > (MCGroupIDslen - 4)) {
                    MIKEY_SAKKE_LOGE("KeyParametersPayload: OutOfBond groupID len[%d] vs MCGroupIDslen[%d]", mcGroupIDsPayload.groupID.length, MCGroupIDslen);
                } else {
                    mcGroupIDsPayload.groupID.data = new uint8_t[mcGroupIDsPayload.groupID.length]();
                    for (uint16_t j = 0; j < mcGroupIDsPayload.groupID.length; ++j) {
                        mcGroupIDsPayload.groupID.data[j] = payload[i++];
                    }
                }
            }
        }
    }
    keyStatusRevok = keyStatus & KeyStatus::NOT_REVOKED;
    keyStatusGateway = keyStatus & KeyStatus::SHARED_WITH_GATEWAY;

    if (size != i) {
        MIKEY_SAKKE_LOGE("CAUTION: KeyParametersPayload may not have been fully parsed as length does not match (%dB in input but %dB read)", size, i);
    }
}

uint8_t* KeyParametersPayload::bytes() const {
    uint8_t* payload = nullptr;

    payload     = new uint8_t[size]();
    uint16_t n  = 0;
    payload[n++]  = static_cast<uint8_t>(keyType);
    payload[n++]  = (keyStatus & 0xFF000000) >> 24;
    payload[n++]  = (keyStatus & 0xFF0000) >> 16;
    payload[n++]  = (keyStatus & 0xFF00) >> 8;
    payload[n++]  = (keyStatus & 0xFF);
    payload[n++]  = (activationTime & 0xFF00000000) >> 32;
    payload[n++]  = (activationTime & 0xFF000000) >> 24;
    payload[n++] = (activationTime & 0xFF0000) >> 16;
    payload[n++] = (activationTime & 0xFF00) >> 8;
    payload[n++] = (activationTime & 0xFF);
    payload[n++] = (expiryTime & 0xFF00000000) >> 32;
    payload[n++] = (expiryTime & 0xFF000000) >> 24;
    payload[n++] = (expiryTime & 0xFF0000) >> 16;
    payload[n++] = (expiryTime & 0xFF00) >> 8;
    payload[n++] = (expiryTime & 0xFF);
    payload[n++] = (text.length() & 0xFF00) >> 8;
    payload[n++] = (text.length() & 0xFF);
    if (text.length() > 0) {
        memcpy(payload + n, text.c_str(), text.length());
        n += text.length();
    }

    if (keyType == KeyType::GMK || keyType == KeyType::MKFC || keyType == KeyType::MuSiK) {
        payload[n++] = (MCGroupIDslen & 0xFF00) >> 8;
        payload[n++] = (MCGroupIDslen & 0xFF);
        payload[n++] = mcGroupIDsPayload.numberOfGroupIDs;

        if (mcGroupIDsPayload.numberOfGroupIDs) {
            payload[n++] = mcGroupIDsPayload.groupID.iei;
            payload[n++] = (mcGroupIDsPayload.groupID.length & 0xFF00) >> 8;
            payload[n++] = mcGroupIDsPayload.groupID.length & 0xFF;
            for (uint16_t i = 0; i < mcGroupIDsPayload.groupID.length; ++i) {
                payload[n++] = mcGroupIDsPayload.groupID.data[i];
            }
        }
    }

    if (size != n) {
        MIKEY_SAKKE_LOGE("CAUTION: KeyParametersPayload memory usage is not expected (%dB allocated by %dB used)", size, n);
    }
    return payload;
}

std::string KeyParametersPayload::string() const {
    std::stringstream ss;
    ss << "Keytype : ";
    switch (keyType) {
        case KeyParametersPayload::KeyType::GMK:
            ss << "GMK";
            break;
        case KeyParametersPayload::KeyType::PCK:
            ss << "PCK";
            break;
        case KeyParametersPayload::KeyType::CSK:
            ss << "CSK";
            break;
        case KeyParametersPayload::KeyType::SPK:
            ss << "SPK";
            break;
        case KeyParametersPayload::KeyType::MKFC:
            ss << "MKFC";
            break;
        case KeyParametersPayload::KeyType::MSCCK:
            ss << "MSCCK";
            break;
        case KeyParametersPayload::KeyType::MuSiK:
            ss << "MuSiK";
            break;
        default:
            ss << "UNKNOWN(" << static_cast<int>(keyType) << ")";
    }
    ss << "\n";
    ss << "keyStatus (KeyNotRevoked) : " << keyStatusRevok << '\n';
    ss << "keyStatus (Shared with S-Gateway) : " << keyStatusGateway << '\n';
    ss << "activationTime : " << activationTime << '\n';
    ss << "expiryTime : " << expiryTime << '\n';
    ss << "GroupsIds (len="<< itoa(MCGroupIDslen) << "): {\n";
    if (MCGroupIDslen > 0) {
        ss << "\tNbGroup=" << itoa(mcGroupIDsPayload.numberOfGroupIDs) << '\n';
        if (mcGroupIDsPayload.numberOfGroupIDs > 0) {
            ss << "\tgroupID.iei=" << itoa(mcGroupIDsPayload.groupID.iei) << '\n';
            ss << "\tGroupID(len="<< itoa(mcGroupIDsPayload.groupID.length)<< ")=" << OctetString{mcGroupIDsPayload.groupID.length, mcGroupIDsPayload.groupID.data}.translate() << '\n';
        }
    }
    ss << "}" << std::endl;;
    return ss.str();
}