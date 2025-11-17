#include <cstring>
#include <iostream>
#include <libmutil/Logger.h>
#include <mscrypto/ecc/curve.h>
#include <mscrypto/ecc/point.h>
#include <mscrypto/eccsi.h>
#include <mscrypto/hash/sha256.h>
#include <mscrypto/parameter-set.h>
#include <mskms/key-storage.h>
#include <openssl/ec.h>
#include <util/bigint-ssl.h>
#include <util/octet-string.h>
#include <util/printable.inl>

namespace MikeySakkeCrypto {

bool ValidateSigningKeysAndCacheHS(const OctetString& identifier, std::string const& community, MikeySakkeKMS::KeyStoragePtr const& keys) {
    MIKEY_SAKKE_LOGD("Validating keys for user %s in community %s", identifier.translate().c_str(), community.c_str());
    /**
     * This validates the received Secret Signing key according to RFC 6507 5.1.2
     * https://tools.ietf.org/html/rfc6507#section-5.1.2
     **/
    OctetString const& PVT  = keys->GetPublicKey(identifier.translate(), "PVT");
    OctetString const& KPAK = keys->GetPublicKey(community, "KPAK");
    OctetString const& SSK  = keys->GetPrivateKey(identifier.translate(), "SSK");

    MIKEY_SAKKE_LOGD("PVT %s", PVT.translate().c_str());
    MIKEY_SAKKE_LOGD("KPAK %s", KPAK.translate().c_str());
    #ifdef SHOW_SECRETS_IN_LOGS_DEV_ONLY
    MIKEY_SAKKE_LOGD("SSK %s", SSK.translate().c_str());
    #endif /* SHOW_SECRETS_IN_LOGS_DEV_ONLY */

    if (KPAK.octets[0] != 0x04 || PVT.octets[0] != 0x04) {
        MIKEY_SAKKE_LOGE("Key invalid format. Must be uncompressed data.");
        return false;
    }

    try // point constructor will throw if not on curve
    {
        // TODO : The curve seems to be generated with constant parameters
        // Check if these parameters should be changed and how/by who
        ECC::PrimeCurveJacobianPtr E = eccsi_6509_param_set().curve;

        /// RFC6507 5.1.2
        // 1) Validate that the PVT lies on the elliptic curve E;
        ECC::Point<bigint_ssl> pvt(E, PVT);

        // 2) Compute HS = hash( G || KPAK || ID || PVT ), an N-octet
        // integer.  The integer HS SHOULD be stored with the SSK for
        // later use;
        SHA256Digest HS;
        HS.digest(E->base_point_octets());
        HS.digest(KPAK);
#ifdef USE_IDENTIFIER_AS_HEXSTRING
        HS.digest(identifier.translate());
#else
        HS.digest(identifier.raw(), identifier.size());
#endif
        HS.digest(PVT);
        HS.complete();

        // 2.1) Cache HS for later use by Sign().
        keys->StorePublicKey(identifier.translate(), "HS", HS);

        // 3) Validate that KPAK = [SSK]G - [HS]PVT.
        // 3.bis Specifically, to save inversion,
        //       validate that KPAK + [HS]PVT = [SSK]G
        ECC::Point<bigint_ssl> lhs(E, KPAK);
        lhs.add(pvt.multiply(as_bigint_ssl(HS))); // XXX: scrunches pvt

        // TODO: enhance Point/Curve C++ interface (access to the
        // TODO: group's base-point as a single entity is awkward)
        ECC::Point<bigint_ssl> rhs(E);
        auto const*            ecg_E = E->read_internal<EC_GROUP>();
        auto const*            ecp_G = E->read_internal<EC_POINT>();
        EC_POINT_mul(ecg_E, rhs.readwrite_internal<EC_POINT>(), nullptr, ecp_G, as_bigint_ssl(SSK), bigint_ssl_scratch::get());

        if (lhs == rhs) {
            MIKEY_SAKKE_LOGD("Successfuly validated keys and cached HS");
            return true;
        }
    } catch (std::exception& e) {
        MIKEY_SAKKE_LOGE("Exception verifying ECCSI signing keys: %s", e.what());
    }
    MIKEY_SAKKE_LOGE("Failed to verify ECCSI signing keys.  Revoking keys for '%s'", identifier.translate().c_str());
    keys->RevokeKeys(identifier.translate());
    return false;
}

bool Sign(uint8_t const* msg, size_t msg_len, uint8_t* sign_out, size_t sign_len, OctetString const& identifier,
          RandomGenerator const& randomize, MikeySakkeKMS::KeyAccessPtr const& keys) {

    auto identifier_str = identifier.translate();
    // RFC6507 5.2.1
    //
    OctetString const& PVT = keys->GetPublicKey(identifier_str, "PVT");
    MIKEY_SAKKE_LOGD("Sign ECCSI with identifier<%s> and PVT<%s>", identifier_str.c_str(), PVT.translate().c_str());

    if (PVT.empty() || PVT.octets[0] != 0x04) {
        MIKEY_SAKKE_LOGE("Key invalid format. Must be uncompressed data.");
        return false;
    }

    ECC::PrimeCurveJacobianPtr E = eccsi_6509_param_set().curve;

    bigint_ssl const& q = E->point_order();

    OctetString rand(BN_num_bytes(q));

    // XXX: Note that s below is used as scratch value for HE + r * SSK
    // XXX: within the [1-4] loop; it is updated to s' in [5] and the
    // XXX: true s in [6].

    bigint_ssl j, r, s;

    BN_CTX* scratch = bigint_ssl_scratch::get();

    // [1-4]: Loop until security criteria met:
    //
    for (;;) {
        // 1) Choose a random (ephemeral) non-zero value j in F_q
        //
        MIKEY_SAKKE_LOGD("== Signature Step 1/");
        randomize(rand.raw(), rand.size());
        #ifdef SHOW_SECRETS_IN_LOGS_DEV_ONLY
        MIKEY_SAKKE_LOGD("1. Rand size: %d", rand.size());
        MIKEY_SAKKE_LOGD("1. Random is: %s", rand.translate().c_str());
        #endif /* SHOW_SECRETS_IN_LOGS_DEV_ONLY */
        to_bigint_ssl(j, rand);
        BN_mod(j, j, q, scratch);

        if (j.is_zero())
            continue;

        // 2) Compute J = (Jx,Jy) = [j]G and assign Jx to r
        MIKEY_SAKKE_LOGD("== Signature Step 2/");
        {
            ECC::Point<bigint_ssl> J(E);
            auto const*            ecg_E = E->read_internal<EC_GROUP>();
            auto const*            ecp_G = E->read_internal<EC_POINT>();
            EC_POINT_mul(ecg_E, J.readwrite_internal<EC_POINT>(), nullptr, ecp_G, j, scratch);

            r = J.x();

            // Addition of RBY for Softil test
            //MIKEY_SAKKE_LOGI("2. Reseting r");
            //OctetString r_bytes = OctetString::skipws("1500B02FE37B92B94612F5665ABEF81FB8C5072B49D7793622A9D57761D665D9");
            //r.reset();
            //MIKEY_SAKKE_LOGI("2. Reassigning r");
            //to_bigint_ssl(r, r_bytes);
            #ifdef SHOW_SECRETS_IN_LOGS_DEV_ONLY
            MIKEY_SAKKE_LOGD("2. r is: %s", as_octet_string(r).translate().c_str());
            #endif /* SHOW_SECRETS_IN_LOGS_DEV_ONLY */
        }

        // 3) Compute HE = hash( HS || r || M )
        //
        MIKEY_SAKKE_LOGD("== Signature Step 3/");
        SHA256Digest HE;
        MIKEY_SAKKE_LOGD("3. HS is: %s", keys->GetPublicKey(identifier_str, "HS").translate().c_str());
        HE.digest(keys->GetPublicKey(identifier_str, "HS"));
        HE.digest(as_octet_string(r));
        HE.digest(msg, msg_len);
        HE.complete();

        MIKEY_SAKKE_LOGD("3. HE is %s" , HE.str().translate().c_str());

        // 4) Verify that HE + r * SSK is non-zero (mod q)
        //
        MIKEY_SAKKE_LOGD("== Signature Step 4/");
        #ifdef SHOW_SECRETS_IN_LOGS_DEV_ONLY
        MIKEY_SAKKE_LOGD("3. SSK is: %s", keys->GetPrivateKey(identifier_str, "SSK").translate().c_str());
        #endif
        BN_mod_mul(s, r, as_bigint_ssl(keys->GetPrivateKey(identifier_str, "SSK")), q, scratch);
        BN_mod_add(s, s, as_bigint_ssl(HE.str()), q, scratch);

        if (as_octet_string(r).size() < (size_t)eccsi_6509_param_set().hash_len) {
            continue;
        }
        if (as_octet_string(s).size() < (size_t)eccsi_6509_param_set().hash_len) {
            continue;
        }

        if (!s.is_zero())
            break;
    }

    // 5) Compute s' = ( (( HE + r * SSK )^-1) * j ) (mod q)
    //    and erase ephemeral j
    //
    MIKEY_SAKKE_LOGD("== Signature Step 5/");
    BN_mod_inverse(s, s, q, scratch);
    BN_mod_mul(s, s, j, q, scratch);
    BN_zero(j);

    // 6) Set s = q - s' if octet_count(s) > N
    //
    MIKEY_SAKKE_LOGD("== Signature Step 6/");
    if (BN_num_bytes(s) > eccsi_6509_param_set().hash_len)
        BN_sub(s, q, s);

    // 7) Output the signature SIG = ( r || s || PVT )
    //
    MIKEY_SAKKE_LOGD("== Signature Step 7/");
    OctetString SIG; // TODO: use a mutable range over output buffer for efficiency
    MIKEY_SAKKE_LOGD("7. s is: %s", as_octet_string(s).translate().c_str());
    OctetString r_os             = as_octet_string(r);
    OctetString s_os             = as_octet_string(s);

    size_t      r_leading_zeroes = eccsi_6509_param_set().hash_len - BN_num_bytes(r);
    size_t      s_leading_zeroes = eccsi_6509_param_set().hash_len - BN_num_bytes(s);

    for (size_t i = 0; i < r_leading_zeroes; ++i) {
        SIG.concat(0);
    }
    SIG.concat(r_os);
    for (size_t i = 0; i < s_leading_zeroes; ++i) {
        SIG.concat(0);
    }
    SIG.concat(s_os);
    SIG.concat(PVT);

    if (sign_len != SIG.size())
        return false;

    std::memcpy(sign_out, SIG.raw(), SIG.size());

    return true;
}

OctetString Sign(uint8_t const* msg, size_t msg_len, OctetString const& identifier, RandomGenerator const& random,
                 MikeySakkeKMS::KeyAccessPtr const& keys) {
    OctetString SIG;
    SIG.octets.resize(1 + 4 * eccsi_6509_param_set().hash_len);
    if (!Sign(msg, msg_len, SIG.raw(), SIG.size(), identifier, random, keys))
        return {};
    return SIG;
}

bool Verify(uint8_t const* msg, size_t msg_len, uint8_t const* sign, size_t sign_len, const OctetString& identifier,
            std::string const& community, MikeySakkeKMS::KeyAccessPtr const& keys) {
    size_t hash_len = eccsi_6509_param_set().hash_len;
    MIKEY_SAKKE_LOGD("Verifying ECCSI signature with senderId(%s) and senderCommunity(%s)", identifier.translate().c_str(), community.c_str());

    // No value in continuing if signature is not the correct size; two
    // N-octet integers r and s, plus an elliptical curve point PVT
    // over E expressed in uncompressed form with length 2N -- See
    // RFC6507 3.3)
    //
    size_t const expected_len = hash_len * 4 + 1;

    if (sign_len != expected_len) {
        MIKEY_SAKKE_LOGE("Unexpected ECCSI signature length (%zu != %zu)", sign_len, expected_len);
        return false;
    }

    // RFC6507 5.2.2
    //
    OctetString const& KPAK = keys->GetPublicKey(community, "KPAK");
    if (KPAK.octets[0] != 0x04) {
        MIKEY_SAKKE_LOGE("Key invalid format. Must be uncompressed data.");
        return false;
    }
    ECC::PrimeCurveJacobianPtr E = eccsi_6509_param_set().curve;

    bigint_ssl const& p = E->field_order();

    BN_CTX* scratch = bigint_ssl_scratch::get();

    try // point constructor will throw if not on curve
    {
        size_t const r_len   = hash_len;
        size_t const s_len   = hash_len;
        size_t const PVT_len = 2 * hash_len + 1;

        uint8_t const* r_begin   = sign;
        uint8_t const* s_begin   = r_begin + r_len;
        uint8_t const* PVT_begin = s_begin + s_len;

        // 1) Check that PVT lies on the elliptical curve E
        //
        ECC::Point<bigint_ssl> pvt(E, PVT_begin, PVT_len);

        // 2) Compute HS = hash( G || KPAK || ID || PVT )
        //
        SHA256Digest HS;
        HS.digest(E->base_point_octets());
        HS.digest(KPAK);
#ifdef USE_IDENTIFIER_AS_HEXSTRING
        HS.digest(identifier.translate());
#else
        HS.digest(identifier.raw(), identifier.size());
#endif
        HS.digest(PVT_begin, PVT_len);
        HS.complete();

        // 3) Compute HE = hash( HS || r || M )
        //
        SHA256Digest HE;
        HE.digest(HS);
        HE.digest(r_begin, r_len);
        HE.digest(msg, msg_len);
        HE.complete();

        /*
        // uncomment to debug ECCSI signature
        MIKEY_SAKKE_LOGD("[ECCSI-Verify] G\t: %s", E->base_point_octets().translate().c_str());
        MIKEY_SAKKE_LOGD("[ECCSI-Verify] KPAK\t: %s", KPAK.translate().c_str());
        MIKEY_SAKKE_LOGD("[ECCSI-Verify] ID\t: %s", identifier.translate().c_str());
        OctetString PVT_os = OctetString {PVT_len, PVT_begin};
        MIKEY_SAKKE_LOGD("[ECCSI-Verify] PVT\t: %s", PVT_os.translate().c_str());
        MIKEY_SAKKE_LOGD("[ECCSI-Verify] HS\t: %s", HS.str().translate().c_str());
        OctetString r_os = OctetString {r_len, r_begin};
        MIKEY_SAKKE_LOGD("[ECCSI-Verify] r\t: %s", r_os.translate().c_str());
        OctetString msg_os = OctetString {msg_len, msg};
        MIKEY_SAKKE_LOGD("[ECCSI-Verify] M\t: %s", msg_os.translate().c_str());
        MIKEY_SAKKE_LOGD("[ECCSI-Verify] HE: %s", HE.str().translate().c_str());
        */

        // [4-5]: Use OpenSSL EC_POINTs_mul to combine steps [4] and
        //        [5] after pre-multiplication of scalars.
        //
        // 4) Y = [HS]PVT + KPAK
        //
        // 5) Compute J = [s]( [HE]G + [r]Y )
        //
        // Expanded expression:
        //
        // 5') Compute J = [s][HE]G + [s][r][HS]PVT + [s][r]KPAK
        //
        // Note: reusing 'pvt' above as basis for J to save unnecessary
        // allocation and point-on-curve check.  'pvt' is not needed
        // again.
        //
        ECC::Point<bigint_ssl>& J = pvt;
        ECC::Point<bigint_ssl>  kpak(E, KPAK); // XXX: could cache this with community keys

        bigint_ssl        r = as_bigint_ssl(r_begin, r_len);
        bigint_ssl const& s = as_bigint_ssl(s_begin, s_len);

        BN_CTX_start(scratch);

        BIGNUM* sr   = BN_CTX_get(scratch);
        BIGNUM* srHS = BN_CTX_get(scratch);
        BIGNUM* sHE  = BN_CTX_get(scratch);

        BN_mul(sr, s, r, scratch);
        BN_mul(srHS, sr, as_bigint_ssl(HS), scratch);
        BN_mul(sHE, s, as_bigint_ssl(HE), scratch);

        // EC_POINTs_mul handles scaled base-point addition via the
        // optional 3rd argument, hence there are only 2 elements in
        // each of the following vectors.
        //
        EC_POINT const* points[]  = {pvt.read_internal<EC_POINT>(), kpak.read_internal<EC_POINT>()};
        BIGNUM const*   scalars[] = {srHS, sr};
        auto const*     ecg_E     = E->read_internal<EC_GROUP>();
        auto*           ecp_J     = J.readwrite_internal<EC_POINT>();

        EC_POINT* tmp  = EC_POINT_new(ecg_E);
        EC_POINT* tmp2 = EC_POINT_new(ecg_E);
        EC_POINT_mul(ecg_E, tmp, sHE, points[0], scalars[0], scratch);
        EC_POINT_mul(ecg_E, tmp2, nullptr, points[1], scalars[1], scratch);
        EC_POINT_add(ecg_E, ecp_J, tmp, tmp2, scratch);
        EC_POINT_free(tmp);
        EC_POINT_free(tmp2);
        BN_CTX_end(scratch);

        // 6) Viewing J in affine coordinates (Jx,Jy), check that
        //    Jx = r mod p, and that Jx mod p != 0.
        //
        // Note: If Jx = r mod p and Jx != 0, then Jx mod p != 0.
        //
        BN_mod(r, r, p, scratch);
        if (BN_cmp(J.x(), r) == 0 && !J.x().is_zero())
            return true;
    } catch (std::exception& e) {
        MIKEY_SAKKE_LOGE("Exception verifying ECCSI signature: %s", e.what());
    }
    MIKEY_SAKKE_LOGE("Failed to verify ECCSI signature from '%s'", identifier.translate().c_str());
    return false;
}

} // namespace MikeySakkeCrypto
