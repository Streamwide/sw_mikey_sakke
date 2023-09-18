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

#include <config.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <libmcrypto/hmac.h>
#include <libmcrypto/rand.h>
#include <libmikey/KeyAgreement.h>
#include <libmikey/MikeyMessage.h>
#include <libmikey/MikeyPayloadSP.h>

#ifdef SCSIM_SUPPORT
#include <libmcrypto/SipSimSmartCardGD.h>
#endif

using namespace std;

/* serves as define to split inkey in 256 bit chunks */
#define PRF_KEY_CHUNK_LENGTH 32
/* 160 bit of SHA1 take 20 bytes */
#define SHA1_DIGEST_SIZE 20
#define SHA256_DIGEST_SIZE 32

enum class prf_hash_algorithm_e {
    HMAC_SHA_1,
    HMAC_SHA_256,
};

KeyAgreement::KeyAgreement(): kvPtr(new KeyValidityNull()), csIdMapPtr(nullptr) {}

KeyAgreement::~KeyAgreement() {
    if (tgkPtr) {
        delete[] tgkPtr;
    }
    if (kfcPtr) {
        delete[] kfcPtr;
    }
    if (randPtr) {
        delete[] randPtr;
    }
    list<Policy_type*>::iterator i;
    for (i = policy.begin(); i != policy.end(); ++i)
        delete *i;
    policy.clear();
}

unsigned int KeyAgreement::randLength() const {
    return randLengthValue;
}

const uint8_t* KeyAgreement::rand() const {
    return randPtr;
}

MRef<KeyValidity*> KeyAgreement::keyValidity() {
    return kvPtr;
}

void KeyAgreement::setKeyValidity(MRef<KeyValidity*> kv) {
    this->kvPtr = NULL;

    switch (kv->type()) {
        case KEYVALIDITY_NULL:
            this->kvPtr = new KeyValidityNull();
            break;
        case KEYVALIDITY_SPI:
            this->kvPtr = new KeyValiditySPI(*(KeyValiditySPI*)(*kv));
            break;
        case KEYVALIDITY_INTERVAL:
            this->kvPtr = new KeyValidityInterval(*(KeyValidityInterval*)(*kv));
            break;
        default:
            return;
    }
}

void KeyAgreement::setRand(uint8_t* rand, int randLengthValue) {
    this->randLengthValue = randLengthValue;

    if (this->randPtr)
        delete[] this->randPtr;

    this->randPtr = new uint8_t[randLengthValue];
    memcpy(this->randPtr, rand, randLengthValue);
}

/* Described in rfc3830.txt Section 4.1.2 */
void prf(const unsigned char* s, const unsigned int sLength, const uint8_t* label, const unsigned int labelLength, unsigned int m,
         uint8_t* output, prf_hash_algorithm_e prf_algo) {

    std::function<void(const unsigned char*, unsigned int, const unsigned char*, unsigned int, unsigned char*, unsigned int*)> hash_func;
    size_t DIGEST_SIZE = 0;
    if (prf_algo == prf_hash_algorithm_e::HMAC_SHA_1) {
        DIGEST_SIZE = SHA1_DIGEST_SIZE;
        hash_func =
            static_cast<void (*)(const unsigned char*, unsigned int, const unsigned char*, unsigned int, unsigned char*, unsigned int*)>(
                hmac_sha1);
    } else if (prf_algo == prf_hash_algorithm_e::HMAC_SHA_256) {

        DIGEST_SIZE = SHA256_DIGEST_SIZE;
        hash_func =
            static_cast<void (*)(const unsigned char*, unsigned int, const unsigned char*, unsigned int, unsigned char*, unsigned int*)>(
                hmac_sha256);
    } else {
        MIKEY_SAKKE_LOGE("Error : undefined PRF");
        return;
    }
    unsigned int i;
    unsigned int hmac_output_length;
    auto*        hmac_input = new uint8_t[labelLength + DIGEST_SIZE];

    /* initial step
     * calculate A_1 and store in hmac_input */

    hash_func(s, sLength, label, labelLength, hmac_input, &hmac_output_length);
    assert(hmac_output_length == DIGEST_SIZE);
    memcpy(&hmac_input[DIGEST_SIZE], label, labelLength);

    /* calculate P(s,label,1)
     * and store in output[0 ... DIGEST_SIZE -1] */

    hash_func(s, sLength, hmac_input, labelLength + DIGEST_SIZE, output, &hmac_output_length);
    assert(hmac_output_length == DIGEST_SIZE);

    /* need key-length > DIGEST_SIZE * 8 bits? */
    for (i = 2; i <= m; ++i) {
        /* calculate A_i = HMAC (s, A_(i-1))
         * A_(i-1) is found in hmac_input
         * and A_i is stored in hmac_input,
         * important: label in upper indices [DIGEST_SIZE ... labelLength + DIGEST_SIZE -1]
         * stays untouched and is repetitively reused! */

        hash_func(s, sLength, hmac_input, DIGEST_SIZE, hmac_input, &hmac_output_length);
        assert(hmac_output_length == DIGEST_SIZE);

        /* calculate P(s,label,i), which is stored in
         * output[0 ... (i * DIGEST_SIZE) -1] */

        hash_func(s, sLength, hmac_input, labelLength + DIGEST_SIZE, &output[DIGEST_SIZE * (i - 1)], &hmac_output_length);
        assert(hmac_output_length == DIGEST_SIZE);
    }

    /* output now contains complete P(s,label,m)
     * in output[0 ... (m * DIGEST_SIZE) -1] */
    delete[] hmac_input;
}

/* Described in rfc3830.txt Section 4.1.2 */

void kdf(const uint8_t* inkey, const unsigned int inkeyLength, const uint8_t* label, const unsigned int labelLength, uint8_t* outkey,
         const unsigned int outkeyLength, prf_hash_algorithm_e prf_algo) {
    unsigned int n;
    unsigned int m;
    unsigned int i;
    unsigned int j;
    uint8_t*     p_output;

    size_t DIGEST_SIZE = 0;
    if (prf_algo == prf_hash_algorithm_e::HMAC_SHA_1) {
        DIGEST_SIZE = SHA1_DIGEST_SIZE;
    } else { // if (prf_algo == prf_hash_algorithm_e::HMAC_SHA_256)
        DIGEST_SIZE = SHA256_DIGEST_SIZE;
    }

    n = (inkeyLength + PRF_KEY_CHUNK_LENGTH - 1) / PRF_KEY_CHUNK_LENGTH;
    m = (outkeyLength + DIGEST_SIZE - 1) / DIGEST_SIZE;

    p_output = new uint8_t[m * DIGEST_SIZE];

    memset(outkey, 0, outkeyLength);
    for (i = 1; i <= n - 1; ++i) {
        prf(&inkey[(i - 1) * PRF_KEY_CHUNK_LENGTH], PRF_KEY_CHUNK_LENGTH, label, labelLength, m, p_output, prf_algo);
        for (j = 0; j < outkeyLength; ++j) {
            outkey[j] ^= p_output[j];
        }
    }

    /* Last step */
    size_t remainder = inkeyLength % PRF_KEY_CHUNK_LENGTH;
    prf(&inkey[(n - 1) * PRF_KEY_CHUNK_LENGTH], remainder == 0 ? PRF_KEY_CHUNK_LENGTH : remainder, label, labelLength, m, p_output,
        prf_algo);

    for (j = 0; j < outkeyLength; ++j) {
        outkey[j] ^= p_output[j];
    }
    delete[] p_output;
}

void KeyAgreement::initLabel(int type, uint8_t* label) {
    switch (type) {
        case KEY_DERIV_SALT:
            label[0] = 0x39;
            label[1] = 0xA2;
            label[2] = 0xC1;
            label[3] = 0x4B;
            break;
        case KEY_DERIV_TEK:
            label[0] = 0x2A;
            label[1] = 0xD0;
            label[2] = 0x1C;
            label[3] = 0x64;
            break;
        case KEY_DERIV_TRANS_ENCR:
            label[0] = 0x15;
            label[1] = 0x05;
            label[2] = 0x33;
            label[3] = 0xE1;
            break;
        case KEY_DERIV_TRANS_SALT:
            label[0] = 0x29;
            label[1] = 0xB8;
            label[2] = 0x89;
            label[3] = 0x16;
            break;
        case KEY_DERIV_TRANS_AUTH:
            label[0] = 0x2D;
            label[1] = 0x22;
            label[2] = 0xAC;
            label[3] = 0x75;
            break;
        case KEY_DERIV_ENCR:
            label[0] = 0x15;
            label[1] = 0x79;
            label[2] = 0x8C;
            label[3] = 0xEF;
            break;
        case KEY_DERIV_AUTH:
            label[0] = 0x1B;
            label[1] = 0x5C;
            label[2] = 0x79;
            label[3] = 0x73;
            break;
    }
}

void KeyAgreement::keyDeriv2(const uint8_t csId, const uint8_t* csbIdValue, const uint8_t* inkey, const unsigned int inkeyLength,
                             uint8_t* key, const unsigned int keyLength, const int type, const uint8_t* rand,
                             const unsigned int rand_length) {
    auto* label = new uint8_t[4 + 4 + 1 + rand_length];

    initLabel(type, label);

    label[4] = csId;
    label[5] = csbIdValue[0];
    label[6] = csbIdValue[1];
    label[7] = csbIdValue[2];
    label[8] = csbIdValue[3];
    memcpy(&label[9], rand, rand_length);
    kdf(inkey, inkeyLength, label, 9 + rand_length, key, keyLength, prf_hash_algorithm_e::HMAC_SHA_256);

    delete[] label;
}

void KeyAgreement::keyDeriv(unsigned char csId, unsigned int csbIdValue, unsigned char* inkey, unsigned int inkeyLength, unsigned char* key,
                            unsigned int keyLength, int type) {

    auto* label = new uint8_t[4 + 4 + 1 + randLengthValue];

    initLabel(type, label);

    label[4] = csId;
    label[5] = (uint8_t)((csbIdValue >> 24) & 0xFF);
    label[6] = (uint8_t)((csbIdValue >> 16) & 0xFF);
    label[7] = (uint8_t)((csbIdValue >> 8) & 0xFF);
    label[8] = (uint8_t)(csbIdValue & 0xFF);
    memcpy(&label[9], randPtr, randLengthValue);
    kdf(inkey, inkeyLength, label, 9 + randLengthValue, key, keyLength, prf_hash_algorithm_e::HMAC_SHA_256);

    delete[] label;
}

void KeyAgreement::genTek(uint8_t csId, uint8_t* tek, unsigned int tekLength) {
#ifdef SCSIM_SUPPORT
    SipSimSmartCardGD* gdSim = dynamic_cast<SipSimSmartCardGD*>(*sim);
    if (gdSim) {
        gdSim->getKey(csId, csbIdValue, randPtr, randLengthValue, tek, tekLength, KEY_DERIV_TEK);
    } else
#endif
        keyDeriv(csId, csbIdValue, tgkPtr, tgkLengthValue, tek, tekLength, KEY_DERIV_TEK);
}

void KeyAgreement::genSalt(uint8_t csId, uint8_t* salt, unsigned int saltLength) {
    keyDeriv(csId, csbIdValue, tgkPtr, tgkLengthValue, salt, saltLength, KEY_DERIV_SALT);
}

void KeyAgreement::genEncr(uint8_t csId, uint8_t* e_key, unsigned int e_keylen) {
    keyDeriv(csId, csbIdValue, tgkPtr, tgkLengthValue, e_key, e_keylen, KEY_DERIV_ENCR);
}

void KeyAgreement::genAuth(uint8_t csId, uint8_t* a_key, unsigned int a_keylen) {
    keyDeriv(csId, csbIdValue, tgkPtr, tgkLengthValue, a_key, a_keylen, KEY_DERIV_AUTH);
}

unsigned int KeyAgreement::csbId() {
    return csbIdValue;
}

void KeyAgreement::setCsbId(unsigned int csbIdValue) {
    this->csbIdValue = csbIdValue;
}

void KeyAgreement::setTgk(uint8_t* tgk, unsigned int tgkLengthValue) {
    if (this->tgkPtr)
        delete[] this->tgkPtr;
    this->tgkLengthValue = tgkLengthValue;
    this->tgkPtr         = new uint8_t[tgkLengthValue];
    if (tgk) {
        memcpy(this->tgkPtr, tgk, tgkLengthValue);
    } else {
        Rand::randomize(this->tgkPtr, tgkLengthValue);
    }
}

unsigned int KeyAgreement::tgkLength() const {
    return tgkLengthValue;
}

const uint8_t* KeyAgreement::tgk() const {
    return tgkPtr;
}

uint32_t KeyAgreement::tgkId() {
    return tgkIdValue;
}
void KeyAgreement::setTgkId(uint32_t tgkId) {
    this->tgkIdValue = tgkId;
}

void KeyAgreement::setTgkId(OctetString tgkId) {
    if (tgkId.size() != 4) {
        MIKEY_SAKKE_LOGE("Can't write Key ID : wrong argument length (%d)", tgkId.size());
        return;
    }
    uint32_t tmp = (uint32_t)(tgkId.raw()[0]) << 24;
    tmp |= (uint32_t)(tgkId.raw()[1]) << 16;
    tmp |= (uint32_t)(tgkId.raw()[2]) << 8;
    tmp |= (uint32_t)(tgkId.raw()[3]);
    this->setTgkId(tmp);
}

void KeyAgreement::setKfc(uint8_t* kfc, unsigned int kfcLengthValue) {
    if (this->kfcPtr)
        delete[] this->kfcPtr;
    this->kfcLengthValue = kfcLengthValue;
    this->kfcPtr         = new uint8_t[kfcLengthValue];
    if (kfc) {
        memcpy(this->kfcPtr, kfc, kfcLengthValue);
    } else {
        Rand::randomize(this->kfcPtr, kfcLengthValue);
    }
}

unsigned int KeyAgreement::kfcLength() const {
    return kfcLengthValue;
}

const uint8_t* KeyAgreement::kfc() const {
    return kfcPtr;
}

uint32_t KeyAgreement::kfcId() {
    return kfcIdValue;
}
void KeyAgreement::setKfcId(uint32_t kfcId) {
    this->kfcIdValue = kfcId;
}

void KeyAgreement::setKfcId(OctetString kfcId) {
    if (kfcId.size() != 4) {
        MIKEY_SAKKE_LOGE("Can't write Key ID : wrong argument length (%d)", kfcId.size());
        return;
    }
    uint32_t tmp = (uint32_t)(kfcId.raw()[0]) << 24;
    tmp |= (uint32_t)(kfcId.raw()[1]) << 16;
    tmp |= (uint32_t)(kfcId.raw()[2]) << 8;
    tmp |= (uint32_t)(kfcId.raw()[3]);
    this->setKfcId(tmp);
}

MRef<MikeyMessage*> KeyAgreement::initiatorData() {
    return initiatorDataPtr;
}

void KeyAgreement::setInitiatorData(MRef<MikeyMessage*> data) {
    initiatorDataPtr = data;
}

MRef<MikeyMessage*> KeyAgreement::responderData() {
    return responderDataPtr;
}

void KeyAgreement::setResponderData(MRef<MikeyMessage*> data) {
    responderDataPtr = data;
}

string KeyAgreement::authError() {
    return authErrorValue;
}

void KeyAgreement::setAuthError(const string& error) {
    authErrorValue = error;
}

const std::string& KeyAgreement::uri() const {
    return uriValue;
}

void KeyAgreement::setUri(const std::string& theUri) {
    uriValue = theUri;
}

const std::string& KeyAgreement::peerUri() const {
    return peerUriValue;
}

const OctetString& KeyAgreement::peerId() const {
    return peerIdValue;
}

void KeyAgreement::setPeerUri(const std::string& thePeerUri) {
    peerUriValue = thePeerUri;
}

void KeyAgreement::setPeerId(const OctetString& thePeerId) {
    peerIdValue = thePeerId;
}

void KeyAgreement::setCsIdMap(MRef<MikeyCsIdMap*> idMap) {
    csIdMapPtr = idMap;
}

MRef<MikeyCsIdMap*> KeyAgreement::csIdMap() {
    return csIdMapPtr;
}

uint8_t KeyAgreement::nCs() {
    return nCsValue;
}

void KeyAgreement::setnCs(uint8_t value) {
    nCsValue = value;
}

uint8_t KeyAgreement::getSrtpCsId(uint32_t ssrc) {
    auto* csIdMap = dynamic_cast<MikeyCsIdMapSrtp*>(*csIdMapPtr);

    if (csIdMap == nullptr) {
        return 0;
    }

    return csIdMap->findCsId(ssrc);
}

uint32_t KeyAgreement::getSrtpRoc(uint32_t ssrc) {
    auto* csIdMap = dynamic_cast<MikeyCsIdMapSrtp*>(*csIdMapPtr);

    if (csIdMap == nullptr) {
        return 0;
    }
    return csIdMap->findRoc(ssrc);
}

uint8_t KeyAgreement::findpolicyNo(uint32_t ssrc) {
    auto* csIdMap = dynamic_cast<MikeyCsIdMapSrtp*>(*csIdMapPtr);
    if (csIdMap == nullptr) {
        return 0;
    }
    return csIdMap->findpolicyNo(ssrc);
}

void KeyAgreement::setSrtpStreamSsrc(uint32_t ssrc, uint8_t csId) {
    auto* csIdMap = dynamic_cast<MikeyCsIdMapSrtp*>(*csIdMapPtr);
    if (csIdMap == nullptr) {
        return;
    }
    csIdMap->setSsrc(ssrc, csId);
}

void KeyAgreement::setSrtpStreamRoc(uint32_t roc, uint8_t csId) {
    auto* csIdMap = dynamic_cast<MikeyCsIdMapSrtp*>(*csIdMapPtr);
    if (csIdMap == nullptr) {
        return;
    }
    csIdMap->setRoc(roc, csId);
}

void KeyAgreement::addSrtpStream(uint32_t ssrc, uint32_t roc, uint8_t policyNo, uint8_t csId) {
    MikeyCsIdMapSrtp* csIdMap;

    if (!csIdMapPtr) {
        csIdMapPtr = new MikeyCsIdMapSrtp();
        csIdMap    = (MikeyCsIdMapSrtp*)(*csIdMapPtr);
    } else {
        csIdMap = dynamic_cast<MikeyCsIdMapSrtp*>(*csIdMapPtr);
    }

    csIdMap->addStream(ssrc, roc, policyNo, csId);

    if (csId == 0)
        ++nCsValue;
}

void KeyAgreement::addIpsecSA(uint32_t spi, uint32_t spiSrcaddr, uint32_t spiDstaddr, uint8_t policyNo, uint8_t csId) {
    auto* csIdMap = dynamic_cast<MikeyCsIdMapIPSEC4*>(*csIdMapPtr);
    if (csIdMap == nullptr) {
        csIdMapPtr = new MikeyCsIdMapIPSEC4();
        csIdMap    = (MikeyCsIdMapIPSEC4*)(*csIdMapPtr);
    }
    csIdMap->addSA(spi, spiSrcaddr, spiDstaddr, policyNo, csId);
    if (csId == 0)
        ++nCsValue;
}

void KeyAgreement::setCsIdMapType(uint8_t type) {
    CsIdMapType = type;
}
uint8_t KeyAgreement::getCsIdMapType() {
    return CsIdMapType;
}

/* Security Policy */

void KeyAgreement::setPolicyParamType(uint8_t policy_No, uint8_t prot_type, uint8_t policy_type, uint8_t length, uint8_t* value) {
    Policy_type* pol;
    if ((pol = getPolicyParamType(policy_No, prot_type, policy_type)) == nullptr)
        policy.push_back(new Policy_type(policy_No, prot_type, policy_type, length, value));
    else {
        policy.remove(pol);
        delete pol;
        policy.push_back(new Policy_type(policy_No, prot_type, policy_type, length, value));
    }
}

uint8_t KeyAgreement::setPolicyParamType(uint8_t prot_type, uint8_t policy_type, uint8_t length, uint8_t* value) {
    list<Policy_type*>::iterator i;
    uint8_t                      policyNo = 0;
    i                                     = policy.begin();
    while (i != policy.end()) {
        if ((*i)->policy_No == policyNo) {
            i = policy.begin();
            ++policyNo;
        } else
            ++i;
    }
    policy.push_back(new Policy_type(policyNo, prot_type, policy_type, length, value));
    return policyNo;
}

static uint8_t ipsec4values[] = {MIKEY_IPSEC_SATYPE_ESP,
                                 MIKEY_IPSEC_MODE_TRANSPORT,
                                 MIKEY_IPSEC_SAFLAG_PSEQ,
                                 MIKEY_IPSEC_EALG_3DESCBC,
                                 24,
                                 MIKEY_IPSEC_AALG_SHA1HMAC,
                                 16};
static uint8_t srtpvalues[]   = {
      MIKEY_SRTP_EALG_AESCM, 16, MIKEY_SRTP_AALG_SHA1HMAC, 20, 14, MIKEY_SRTP_PRF_AESCM, 0, 1, 1, MIKEY_FEC_ORDER_FEC_SRTP, 1, 10, 0};

uint8_t KeyAgreement::setdefaultPolicy(uint8_t prot_type) {
    list<Policy_type*>::iterator iter;
    uint8_t                      policyNo = 0;
    iter                                  = policy.begin();
    while (iter != policy.end()) {
        if ((*iter)->policy_No == policyNo) {
            iter = policy.begin();
            ++policyNo;
        } else
            ++iter;
    }
    int i, arraysize;
    switch (prot_type) {
        case MIKEY_PROTO_SRTP:
            arraysize = 13;
            for (i = 0; i < arraysize; ++i)
                policy.push_back(new Policy_type(policyNo, prot_type, i, 1, &srtpvalues[i]));
            break;
        case MIKEY_PROTO_IPSEC4:
            arraysize = 7;
            for (i = 0; i < arraysize; ++i)
                policy.push_back(new Policy_type(policyNo, prot_type, i, 1, &ipsec4values[i]));
            break;
    }
    return policyNo;
}

Policy_type* KeyAgreement::getPolicyParamType(uint8_t policy_No, uint8_t prot_type, uint8_t policy_type) {
    list<Policy_type*>::iterator i;
    for (i = policy.begin(); i != policy.end(); ++i)
        if ((*i)->policy_No == policy_No && (*i)->prot_type == prot_type && (*i)->policy_type == policy_type)
            return *i;
    return nullptr;
}

uint8_t KeyAgreement::getPolicyParamTypeValue(uint8_t policy_No, uint8_t prot_type, uint8_t policy_type) {
    list<Policy_type*>::iterator i;
    for (i = policy.begin(); i != policy.end(); ++i)
        if ((*i)->policy_No == policy_No && (*i)->prot_type == prot_type && (*i)->policy_type == policy_type && (*i)->length == 1) {
            return (uint8_t)(*i)->value[0];
        }

    switch (prot_type) {
        case MIKEY_PROTO_SRTP:
            if (policy_type < sizeof(srtpvalues) / sizeof(srtpvalues[0])) {
                return srtpvalues[policy_type];
            }
            MIKEY_SAKKE_LOGE("MIKEY_PROTO_SRTP type out of range %d", policy_type);
            break;
        case MIKEY_PROTO_IPSEC4:
            if (policy_type < sizeof(ipsec4values) / sizeof(ipsec4values[0]))
                return ipsec4values[policy_type];
            MIKEY_SAKKE_LOGE("MIKEY_PROTO_IPSEC4 type out of range %d", policy_type);
            break;
        default:
            break;
    }
    return 0;
}

Policy_type::Policy_type(uint8_t policy_No, uint8_t prot_type, uint8_t policy_type, uint8_t length, const uint8_t* value) {
    this->policy_No   = policy_No;
    this->prot_type   = prot_type;
    this->policy_type = policy_type;
    this->length      = length;
    this->value       = (uint8_t*)calloc(length, sizeof(uint8_t));
    for (int i = 0; i < length; ++i)
        this->value[i] = value[i];
}

Policy_type::~Policy_type() {
    free(value);
}
