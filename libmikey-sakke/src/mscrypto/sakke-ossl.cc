#include <libmutil/Logger.h>
#include <mscrypto/hash/sha256.h>
#include <mscrypto/parameter-set.h>
#include <mscrypto/sakke.h>
#include <mskms/client-fwd.h>
#include <mskms/key-storage.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <util/bigint-ssl.h>

namespace MikeySakkeCrypto {

void HashToIntegerRangeSHA256(bigint_ssl& v, uint8_t* octets, size_t octet_count, bigint_ssl const& n) {
    // RFC6508 5.1

    // 1) A = hashfn(s)
    SHA256Digest A;
    A.digest(octets, octet_count).complete();

    // 2) h = zero initialized string of hashlen bits
    SHA256Digest h;

    // 3) l = ceiling(lg(n)/hashlen)
    int l = (BN_num_bits(n) + 255) >> 8;

    // 4) For i in [1, l] do
    //
    //    a) Let h_i = hashfn(h_(i - 1))
    //
    //    b) Let v_i = hashfn(h_i || A), where || denotes concatenation
    //
    // 5) Let v' = v_1 || ...  || v_l
    //
    OctetString scratch; // v_i and h_i || A
    OctetString vprime;
    for (; l != 0; --l) {
        h.digest(h).sync();

        if (scratch.empty())
            scratch.concat(h).concat(A);
        else
            std::memcpy(scratch.raw(), h.str().raw(), 32);

        InplaceSHA256Digest vi(scratch.raw());
        vi.digest(scratch).sync();
        vprime.concat(32, scratch.raw());
    }
    h.complete();

    // 6) v = v' mod n
    //
    to_bigint_ssl(v, vprime);
    BN_nnmod(v, v, n, bigint_ssl_scratch::get());
}

//=============================================================================
// RFC6508 2.1 -- F_p^2 and PF_p arithmetic

template <class B>
struct PF_p_ref {
    PF_p_ref() {}
    PF_p_ref(PF_p_ref& other) = default;
    template <class Other>
    PF_p_ref(Other const& other): x_1(other.x_1), x_2(other.x_2) {}
    B x_1;
    B x_2;

  private:
    PF_p_ref& operator=(PF_p_ref const&);
};
typedef PF_p_ref<bigint_ssl>       PF_p;
typedef PF_p_ref<bigint_ssl const> PF_p_const;

// Square an element A of PF_p, placing the result in R.  R and A
// may point to the same storage.
//
void PF_p_sqr(bigint_ssl const& p, PF_p& R, PF_p_const A) {
    bigint_ssl_scratch& scratch = bigint_ssl_scratch::get();
    PF_p                Ta;
    PF_p                Tb;

    Ta.x_1 = A.x_1;
    Ta.x_2 = A.x_2;

    BN_add(Tb.x_1, Ta.x_1, Ta.x_2);
    BN_sub(Tb.x_2, Ta.x_1, Ta.x_2);

    BN_mul(R.x_1, Tb.x_1, Tb.x_2, scratch);
    BN_nnmod(R.x_1, R.x_1, p, scratch);

    BN_mul(R.x_2, Ta.x_1, Ta.x_2, scratch);

    BN_lshift1(R.x_2, R.x_2);
    BN_nnmod(R.x_2, R.x_2, p, scratch);
}

// Multiply two elements, A and B, of PF_p, placing the result in R.
// Any of R, A or B may share the same memory (though if A and B share
// the same memory it is more efficient to call PF_p_sqr() above.
//
void PF_p_mul(bigint_ssl const& p, PF_p& R, PF_p_const A, PF_p_const B) {
    bigint_ssl_scratch& scratch = bigint_ssl_scratch::get();
    PF_p                Ta;
    PF_p                Tb;

    Ta.x_1 = A.x_1;
    Ta.x_2 = A.x_2;
    Tb.x_1 = B.x_1;
    Tb.x_2 = B.x_2;

    BN_mul(R.x_1, Ta.x_1, Tb.x_1, scratch);

    bigint_ssl tmp;
    BN_mul(tmp, Ta.x_2, Tb.x_2, scratch);
    BN_sub(R.x_1, R.x_1, tmp);
    BN_nnmod(R.x_1, R.x_1, p, scratch);

    BN_mul(R.x_2, Ta.x_1, Tb.x_2, scratch);

    BN_clear(tmp);
    BN_mul(tmp, Ta.x_2, Tb.x_1, scratch);
    BN_add(R.x_2, R.x_2, tmp);

    BN_nnmod(R.x_2, R.x_2, p, scratch);
}

// Raise an element A of PF_p to power n, storing the result in R.
// R and A may share the same storage.
//
void PF_p_pow(bigint_ssl const& p, PF_p& R, PF_p_const A, bigint_ssl const& n) {
    if (n.is_zero())
        throw std::invalid_argument("PF_p_pow raise to power 0 not implemented.");

    PF_p acc;
    acc.x_1 = A.x_1;
    acc.x_2 = A.x_2;

    for (size_t N = BN_num_bits(n) - 1; N != 0; --N) {
        PF_p_sqr(p, acc, acc);
        if (BN_is_bit_set(n, N - 1)) {
            PF_p_mul(p, acc, acc, A);
        }
    }
    R.x_1 = acc.x_1;
    R.x_2 = acc.x_2;
}
//=============================================================================

inline MikeySakkeCrypto::SakkeParameterSet const& GetParamSet(std::string const& community, MikeySakkeKMS::KeyAccessPtr const& keys, int keyLen=16) {
    if (keys->GetPublicParameter(community, "SakkeSet") != "1")
        throw std::invalid_argument("Only SAKKE parameter set 1 is supported.");
    if (keyLen == 32) {
        return MikeySakkeCrypto::sakke_param_set_2();
    }
    return MikeySakkeCrypto::sakke_param_set_1();
}

//=============================================================================
// Scratch holder for elements of E(F_p)[q]
//
template <class B>
struct EF_pq_ref {
    EF_pq_ref() {}
    explicit EF_pq_ref(ECC::Point<bigint_ssl> const& p): x {p.x()}, y {p.y()} {}
    template <class Other>
    explicit EF_pq_ref(Other const& other): x(other.x), y(other.y) {}
    B x;
    B y;

  private:
    EF_pq_ref& operator=(EF_pq_ref const&);
};
typedef EF_pq_ref<bigint_ssl>       EF_pq;
typedef EF_pq_ref<bigint_ssl const> EF_pq_const;
//=============================================================================

//=============================================================================
// RFC2508 3.2. The Tate-Lichtenbaum Pairing
// Ref also: MIKEY-SAKKE on Android 3.2.2
//
// Transcribed from the reference implementation
//
void ComputePairing(SakkeParameterSet const& params, bigint_ssl& w, ECC::Point<bigint_ssl> const& R, ECC::Point<bigint_ssl> const& Q) {
    ECC::PrimeCurveAffinePtr E = params.E_a;
    bigint_ssl const&        p = E->field_order();
    bigint_ssl const&        q = E->point_order();

    bigint_ssl_scratch& scratch = bigint_ssl_scratch::get();
    bigint_ssl          q_minus_one;
    bigint_ssl          one;
    BN_one(one);
    BN_sub(q_minus_one, q, one);

    // XXX: Going via ECC::Point requires a number of unnecessary
    // XXX: dereferences.  Use EF_pq_ref above for scratch values.

    PF_p  v, T;
    EF_pq C(R);

    BN_one(v.x_1);
    BN_zero(v.x_2);

    bigint_ssl two;
    BN_set_word(two, 2);

    bigint_ssl t;

    for (size_t N = BN_num_bits(q_minus_one) - 1; N != 0; --N) {
        PF_p_sqr(p, v, v);

        BN_mod_exp(T.x_1, C.x, two, p, scratch);
        BN_sub_word(T.x_1, 1);
        BN_mul_word(T.x_1, 3);
        BN_add(t, Q.x(), C.x);
        BN_mul(T.x_1, T.x_1, t, scratch);
        BN_nnmod(T.x_1, T.x_1, p, scratch);
        BN_mod_exp(t, C.y, two, p, scratch);
        bigint_ssl tmp;
        BN_mul(tmp, t, two, scratch);
        BN_sub(T.x_1, T.x_1, tmp);
        BN_nnmod(T.x_1, T.x_1, p, scratch);
        BN_lshift1(T.x_2, C.y);
        BN_mul(T.x_2, T.x_2, Q.y(), scratch);
        BN_nnmod(T.x_2, T.x_2, p, scratch);

        PF_p_mul(p, v, v, T);

        // inline doubling of EC point
        // (it is known the C is not at infinity)
        {
            bigint_ssl lambda;
            bigint_ssl lambda_sq;
            bigint_ssl EAT1;
            EF_pq      EAR;

            BN_mod_exp(lambda, C.x, two, p, scratch);
            BN_sub_word(lambda, 1);
            BN_mul_word(lambda, 3);
            BN_lshift1(EAT1, C.y);
            BN_mod_inverse(EAT1, EAT1, p, scratch);
            BN_mul(lambda, lambda, EAT1, scratch);
            BN_nnmod(lambda, lambda, p, scratch);

            BN_mod_exp(lambda_sq, lambda, two, p, scratch);

            BN_lshift1(EAT1, C.x);
            BN_sub(EAR.x, lambda_sq, EAT1);
            BN_nnmod(EAR.x, EAR.x, p, scratch);

            BN_sub(EAR.y, EAT1, lambda_sq);
            BN_add(EAR.y, EAR.y, C.x);
            BN_mul(EAR.y, EAR.y, lambda, scratch);
            BN_nnmod(EAR.y, EAR.y, p, scratch);
            BN_sub(EAR.y, EAR.y, C.y);
            BN_nnmod(EAR.y, EAR.y, p, scratch);

            C.x = EAR.x;
            C.y = EAR.y;
        }

        if (BN_is_bit_set(q_minus_one, N - 1)) {
            BN_add(T.x_1, Q.x(), R.x());
            BN_mul(T.x_1, T.x_1, C.y, scratch);
            BN_nnmod(T.x_1, T.x_1, p, scratch);
            BN_add(t, Q.x(), C.x);

            bigint_ssl tmp2;
            BN_mul(tmp2, R.y(), t, scratch);
            BN_sub(T.x_1, T.x_1, tmp2);

            BN_nnmod(T.x_1, T.x_1, p, scratch);

            BN_sub(T.x_2, C.x, R.x());
            BN_mul(T.x_2, T.x_2, Q.y(), scratch);
            BN_nnmod(T.x_2, T.x_2, p, scratch);

            PF_p_mul(p, v, v, T);

            // inline addition of EC point R to C
            // (it is known that neither R nor C are at infinity)
            {
                bigint_ssl lambda;
                bigint_ssl lambda_sq;
                bigint_ssl EAT1;
                EF_pq      EAR;

                BN_sub(lambda, R.y(), C.y);
                BN_sub(EAT1, R.x(), C.x);
                BN_mod_inverse(EAT1, EAT1, p, scratch);
                BN_mul(lambda, lambda, EAT1, scratch);
                BN_nnmod(lambda, lambda, p, scratch);

                BN_mod_exp(lambda_sq, lambda, two, p, scratch);
                BN_sub(EAR.x, lambda_sq, C.x);
                BN_sub(EAR.x, EAR.x, R.x());
                BN_nnmod(EAR.x, EAR.x, p, scratch);

                BN_sub(EAR.y, R.x(), lambda_sq);
                BN_copy(tmp, C.x);
                BN_mul_word(tmp, 2);
                BN_add(EAR.y, EAR.y, tmp);

                BN_mul(EAR.y, EAR.y, lambda, scratch);

                BN_nnmod(EAR.y, EAR.y, p, scratch);
                BN_sub(EAR.y, EAR.y, C.y);
                BN_nnmod(EAR.y, EAR.y, p, scratch);

                C.x = EAR.x;
                C.y = EAR.y;
            }
        }
    }

    PF_p_sqr(p, v, v);
    PF_p_sqr(p, v, v);

    BN_mod_inverse(w, v.x_1, p, scratch);
    BN_mul(w, w, v.x_2, scratch);
    BN_nnmod(w, w, p, scratch);
}

//=============================================================================

bool ValidateReceiverSecretKey(const OctetString& identifier, std::string const& community, MikeySakkeKMS::KeyStoragePtr const& keys) {
    SakkeParameterSet const& params = GetParamSet(community, keys);

    // RFC6508 6.1.2
    //
    // Upon receipt of key material, each user MUST verify its RSK.
    // For Identifier 'a', RSKs from KMS_T are verified by checking
    // that the following equation holds: < [a]P + Z, K_(a,T) > = g,
    // where 'a' is interpreted as an integer.
    //
    // Note that P is already loaded as the base-point of E_j, hence
    // a single call to EC_POINT_mul can be made to do the scaling of P
    // by a and the addition of [1]Z.
    //
    // Note also that, although this initial multiplication is done
    // with OpenSSL, subsequent arithmetic is done using GMP with
    // direct access to the point's affine coordinates.  As such, the
    // effect of this scope is to transform the resulting Jacobian
    // point from E_j into the equivalent affine point suitable for use
    // with E_a.
    //

    const OctetString& Z   = keys->GetPublicKey(community, "Z");
    const OctetString& RSK = keys->GetPrivateKey(identifier.translate(), "RSK");

    if (Z.octets[0] != 0x04 || RSK.octets[0] != 0x04) {
        MIKEY_SAKKE_LOGE("Key invalid format. Must be uncompressed data.");
        return false;
    }
    ECC::Point<bigint_ssl> a_P_plus_Z(params.E_a);
    {
        ECC::Point<bigint_ssl> ecp_a_P_plus_Z(params.E_j);
        ECC::Point<bigint_ssl> ecp_Z(params.E_j, Z);
        auto const*            ecg = params.E_j->read_internal<EC_GROUP>();
        BN_CTX*                ssl = bigint_ssl_scratch::get();
        BN_CTX_start(ssl);
        BIGNUM* ssl_a = BN_CTX_get(ssl);
        // We should be able to pass identifier.raw(), this is a workaround
#ifdef USE_IDENTIFIER_AS_HEXSTRING
        BN_bin2bn((uint8_t*)identifier.translate().c_str(), identifier.translate().length(), ssl_a);
#else
        BN_bin2bn((uint8_t*)identifier.raw(), identifier.size(), ssl_a);
#endif
        EC_POINT_mul(ecg, ecp_a_P_plus_Z.readwrite_internal<EC_POINT>(), ssl_a, ecp_Z.read_internal<EC_POINT>(), BN_value_one(), ssl);
        BN_CTX_end(ssl);

        a_P_plus_Z.assign(ecp_a_P_plus_Z.x(), ecp_a_P_plus_Z.y());
    }

    ECC::Point<bigint_ssl> ecp_RSK(params.E_a, RSK);

    bigint_ssl w;
    ComputePairing(params, w, a_P_plus_Z, ecp_RSK);

    if (w == params.g) {
        MIKEY_SAKKE_LOGD("Successfuly validated Secret Key for %s", identifier.translate().c_str());
        return true;
    }

    // otherwise revoke this keyset
    keys->RevokeKeys(identifier.translate());
    MIKEY_SAKKE_LOGE("Failed to validate Secret Key for %s", identifier.translate().c_str());
    return false;
}

OctetString GenerateSharedSecretAndSED(OctetString& SED, OctetString const& identifier, std::string const& community,
                                       MikeySakkeKMS::KeyAccessPtr const& keys, const OctetString& SSV) {

    SakkeParameterSet const& params = GetParamSet(community, keys, SSV.size());
    bigint_ssl_scratch&      ssl    = bigint_ssl_scratch::get();
    bigint_ssl const         p      = params.E_a->field_order();
    bigint_ssl const         q      = params.E_a->point_order();

    const OctetString& Z = keys->GetPublicKey(community, "Z");
    if (Z.octets[0] != 0x04) {
        MIKEY_SAKKE_LOGE("Key invalid format. Must be uncompressed data.");
        return {};
    }

    // RFC6508 6.2.1
    //
    // 1) Select random ephemeral integer for SSV in [0,2^n)
    // We use SSV passed in function args

    // 2) Compute r = HashToIntegerRangeSHA256( SSV || b, q, Hash )
    //
    OctetString SSV_b(SSV);
#ifdef USE_IDENTIFIER_AS_HEXSTRING
    SSV_b.concat(OctetString {identifier.translate(), OctetString::Translation::Untranslated});
#else
    SSV_b.concat(OctetString {identifier});
#endif
    bigint_ssl ssl_r;
    HashToIntegerRangeSHA256(ssl_r, SSV_b.raw(), SSV_b.size(), q);

    // 3) Compute R_(b,S) = [r]([b]P + Z_S) in E(F_p)
    //
    {
        EC_POINT* R    = EC_POINT_new(params.E_j->read_internal<EC_GROUP>());
#ifdef USE_IDENTIFIER_AS_HEXSTRING
        BIGNUM*   b_bn = BN_bin2bn((uint8_t*)identifier.translate().c_str(), identifier.translate().length(), NULL);
#else
        BIGNUM* b_bn = BN_bin2bn((uint8_t*)identifier.raw(), identifier.size(), NULL);
#endif

        ECC::Point<bigint_ssl> ecp_Z(params.E_j, Z);

        EC_POINT_mul(params.E_j->read_internal<EC_GROUP>(), R, nullptr, params.E_j->read_internal<EC_POINT>(), b_bn, ssl);
        EC_POINT_add(params.E_j->read_internal<EC_GROUP>(), R, R, ecp_Z.read_internal<EC_POINT>(), ssl);
        EC_POINT_mul(params.E_j->read_internal<EC_GROUP>(), R, 0, R, ssl_r, ssl);
        bigint_ssl Rbx_bn;
        bigint_ssl Rby_bn;
        EC_POINT_get_affine_coordinates(params.E_j->read_internal<EC_GROUP>(), R, Rbx_bn, Rby_bn, ssl);

        // BN_bn2bin will truncate leading zeroes so we need to make sure we catch that when it happens
        size_t      coord_len = BN_num_bytes(p);
        OctetString Rb;
        Rb.reserve(2 * coord_len);
        OctetString Rbx {(size_t)BN_num_bytes(Rbx_bn)};
        OctetString Rby {(size_t)BN_num_bytes(Rby_bn)};

        BN_bn2bin(Rbx_bn, Rbx.raw());
        BN_bn2bin(Rby_bn, Rby.raw());

        // Write back leading zeroes
        auto zero_bytes = coord_len - Rbx.size();
        while (zero_bytes > 0) {
            Rb.octets.emplace_back(0x00);
            --zero_bytes;
        }
        Rb.concat(Rbx);

        zero_bytes = coord_len - Rby.size();
        while (zero_bytes > 0) {
            Rb.octets.emplace_back(0x00);
            --zero_bytes;
        }
        Rb.concat(Rby);

        // This is necessary. It indicates that the following data is uncompressed.
        // It will help openssl interpret the data when decoding the data into an elliptic curve point
        SED.octets.emplace_back(0x04);
        SED.concat(Rb);
        EC_POINT_free(R);
    }

    // 4) Compute the HINT, H;
    //
    // 4.a) Compute g^r.
    //
    OctetString g_pow_r_octets;
    if (!ssl_r.is_zero()) {
        [[maybe_unused]] bigint_ssl_scratch& scratch = bigint_ssl_scratch::get();
        PF_p                                 g;
        BN_one(g.x_1);
        g.x_2 = params.g;
        PF_p_pow(p, g, g, ssl_r);

        // Form representation of PF_p (x_1, x_2) in F_p (x_2/x_1 mod p)
        //
        bigint_ssl g_pow_r;
        BN_mod_inverse(g_pow_r, g.x_1, p, ssl);

        BN_mul(g_pow_r, g_pow_r, g.x_2, ssl);
        BN_nnmod(g_pow_r, g_pow_r, p, ssl);

        g_pow_r_octets = as_octet_string(g_pow_r);
    }

    // 4.b) Compute H := SSV XOR HashToIntegerRange( g^r, 2^n, Hash );
    //
    OctetString H_octets;
    H_octets.octets.reserve(SSV.size());

    {
        bigint_ssl H;
        bigint_ssl two_pow_n = ssl_r; // reuse 'r' from above
        BN_one(two_pow_n);
        BN_lshift(two_pow_n, two_pow_n, params.n);
        HashToIntegerRangeSHA256(H, g_pow_r_octets.raw(), g_pow_r_octets.size(), two_pow_n);
        bigint_ssl ssv = ssl_r; // reuse 'r' from above

        size_t  len = SSV.size();
        uint8_t h_bytes[len];

        BN_bn2binpad(H, h_bytes, len);
        for (size_t i = 0; i < len; ++i) {
            H_octets.octets.push_back(h_bytes[i] ^ SSV.raw()[i]);
        }
    }

    // 5) Form the SED ( R_(b,S), H )
    //
    SED.concat(H_octets);

    // 6) Output SSV
    return SSV;
}

OctetString ExtractSharedSecret(OctetString const& SED, const OctetString& identifier, std::string const& community,
                                MikeySakkeKMS::KeyAccessPtr const& keys, int SSVSize) {

    SakkeParameterSet const& params = GetParamSet(community, keys, SSVSize);
    bigint_ssl_scratch&      ssl    = bigint_ssl_scratch::get();
    bigint_ssl const         p      = params.E_a->field_order();
    bigint_ssl const         q      = params.E_a->point_order();
    auto&                    curve  = params.E_a;

    size_t L              = BN_num_bytes(p);
    size_t Rb_octet_count = 2 * L + 1; // (for 0x04 prefix);

    if (SED.size() < Rb_octet_count) {
        MIKEY_SAKKE_LOGE("Shared secret extraction failure: SED invalid size");
        return {};
    }

    MIKEY_SAKKE_LOGD("Extracting secret from");
    MIKEY_SAKKE_LOGD("SED:          %s", SED.translate().c_str());
    MIKEY_SAKKE_LOGD("identifier:   %s", identifier.translate().c_str());
    MIKEY_SAKKE_LOGD("community:    %s", community.c_str());
    const OctetString& Z   = keys->GetPublicKey(community, "Z");
    const OctetString& RSK = keys->GetPrivateKey(identifier.translate(), "RSK");
    MIKEY_SAKKE_LOGD("Z     : %s", Z.translate().c_str());
    MIKEY_SAKKE_LOGD("RSK   : %s", RSK.translate().c_str());

    if (!Z.size() || !RSK.size() || Z.octets[0] != 0x04 || RSK.octets[0] != 0x04) {
        MIKEY_SAKKE_LOGE("Z/RSK Key invalid format (or empty). Must be uncompressed data.");
        return {};
    }

    // RFC6508 6.2.2
    //
    // 1) Parse the Encapsulated Data ( R_(b,S), H ), and extract
    //    R_(b,S) and H;
    //

    ECC::Point<bigint_ssl> Rb(curve, SED.raw(), Rb_octet_count);
    OctetString            H_octets(SED.size() - Rb_octet_count, SED.raw() + Rb_octet_count);

    // 2) Compute w := < R_(b,S), K_(b,S) >
    //
    OctetString w_octets;
    w_octets.octets.reserve(128);
    {
        bigint_ssl             w;
        ECC::Point<bigint_ssl> ecp_RSK(curve, RSK);
        ComputePairing(params, w, Rb, ecp_RSK);
        w_octets = as_octet_string(w);
    }

    // 3) Compute SSV := H XOR HashToIntegerRange( w, 2^n, Hash );
    //
    OctetString SSV_octets;
    SSV_octets.octets.reserve(H_octets.size());
    {
        bigint_ssl SSV;
        bigint_ssl two_pow_n;

        BN_one(two_pow_n);
        BN_lshift(two_pow_n, two_pow_n, params.n);
        HashToIntegerRangeSHA256(SSV, w_octets.raw(), w_octets.size(), two_pow_n);
        bigint_ssl H;
        to_bigint_ssl(H, H_octets);

        size_t  len = H_octets.size();
        uint8_t ssv_bytes[len];

        BN_bn2binpad(SSV, ssv_bytes, len);

        for (size_t i = 0; i < len; ++i) {
            SSV_octets.octets.push_back(H_octets.raw()[i] ^ ssv_bytes[i]);
        }
    }

    // 4) Compute r = HashToIntegerRangeSHA256( SSV || b, q, Hash )
    //
    OctetString SSV_b(SSV_octets);
#ifdef USE_IDENTIFIER_AS_HEXSTRING
    SSV_b.concat(OctetString {identifier.translate(), OctetString::Translation::Untranslated});
#else
    SSV_b.concat(OctetString {identifier});
#endif

    bigint_ssl r;
    HashToIntegerRangeSHA256(r, SSV_b.raw(), SSV_b.size(), q);

    // 5) Compute TEST = [r][b]P + [r]Z_S
    //
    ECC::Point<bigint_ssl> TEST(params.E_j, Z);
    {
        ECC::Point<bigint_ssl>& ecp_Z = TEST;
        BN_CTX_start(ssl);
        BIGNUM* ssl_rb = BN_CTX_get(ssl);

#ifdef USE_IDENTIFIER_AS_HEXSTRING
        BN_bin2bn((uint8_t*)identifier.translate().c_str(), identifier.translate().length(), ssl_rb);
#else
        BN_bin2bn((uint8_t*)identifier.raw(), identifier.size(), ssl_rb);
#endif

        BN_mul(ssl_rb, r, ssl_rb, ssl);

        auto const*     ecg       = params.E_j->read_internal<EC_GROUP>();
        EC_POINT const* points[]  = {ecp_Z.read_internal<EC_POINT>()};
        BIGNUM const*   scalars[] = {r};
        EC_POINT_mul(ecg, TEST.readwrite_internal<EC_POINT>(), ssl_rb, points[0], scalars[0], ssl);

        BN_CTX_end(ssl);
    }

    if (TEST.octets() == Rb.octets()) {
        return SSV_octets;
    }

    MIKEY_SAKKE_LOGE("TEST != Rb, Shouldn't use extracted sakke payload");
    MIKEY_SAKKE_LOGD("Extracted secret : %s", SSV_octets.translate().c_str());
    return {};
}

std::vector<uint8_t> GenerateGukIdSalt(OctetString peerUri, OctetString const& GMK) {
    std::vector<uint8_t> dppk = GenericKdf(0x50, peerUri, GMK);

    // The 28 least significant bits of the 256 bits of the KDF output shall be used as the User Salt.
    // TS 33.179 §F.1.3
    // Get last 4 bytes of the output
    std::vector<uint8_t> salt(dppk.end() - std::min<int>(dppk.size(), 4), dppk.end());
    // Remove 4 upper bits
    salt[0] = salt[0] & 0x0F;
    return salt;
}

std::vector<uint8_t> GenerateGukId(OctetString peerUri, const OctetString& gmk, const OctetString& gmkId) {
    if (gmk.empty() || gmkId.empty()) {
        MIKEY_SAKKE_LOGE("Invalid GMK or GMK-ID");
        return {};
    }
    std::vector<uint8_t> salt = GenerateGukIdSalt(peerUri, gmk);

    // Part 2 -
    // Now GUK-ID is XOR product of salt with 28 least significant bits of GMK-ID
    MIKEY_SAKKE_LOGD("GMKID %s", gmkId.translate().c_str());
    if (gmkId.empty()) {
        return {};
    }

    uint8_t purpose_tag = gmkId.octets[0] & 0xF0;

    std::vector<uint8_t> randomID(gmkId.octets);
    // The random Identifier Part of the GMK-ID is the 28 least significant bits
    randomID[0] = randomID[0] & 0x0F;

    std::vector<uint8_t> GUK_ID;
    GUK_ID.reserve(4);
    for (int i = 0; i < 4; ++i) {
        GUK_ID.push_back(salt[i] ^ randomID[i]);
    }
    // Insert Purpose tag in front
    GUK_ID[0] |= purpose_tag;

    return GUK_ID;
} // namespace MikeySakkeCrypto

OctetString ExtractGmkId(OctetString gukId, OctetString peerUri, OctetString const& GMK) {
    // Get the salt
    std::vector<uint8_t> salt = GenerateGukIdSalt(peerUri, GMK);

    // Isolate purpose tag (4 MSBs of guk-id)
    uint8_t purpose_tag = gukId.raw()[0] & 0xF0;

    // Get 28-bit identifier
    OctetString identifier(gukId);
    identifier.raw()[0] = identifier.raw()[0] & 0xF;

    // XOR
    OctetString gmkId;
    gmkId.empty();
    for (int i = 0; i < 4; ++i) {
        gmkId.concat(identifier.raw()[i] ^ salt[i]);
    }

    // Add purpose tag back
    gmkId.raw()[0] = gmkId.raw()[0] | purpose_tag;

    return gmkId;
}

std::vector<uint8_t> GenericKdf(const uint8_t FC, OctetString const& P0, OctetString const& key) {
    // Use KDF specified in annex B of 3GPP TS 33.220
    // With the following imposed parameters (3GPP TS33.179 §F.1.3)
    //  FC = 0x53 for DPPK, 0x50 for GukID-salt
    //  P0 = refer to TS (depend of the type of output)
    //  L0 = length of above

    // Encoding of Non-Negative Integer is specified in 3GPP TS33 220 Annex B.2.1.3
    // k should be in range [0, 65535]
    if (P0.size() > 65535) {
        return std::vector<uint8_t> {};
    }

    uint16_t L0 = P0.size();

    OctetString S;
    S.concat(FC);
    S.concat(P0);
    S.concat((uint8_t)L0 >> 8);
    S.concat((uint8_t)L0 & 0xFF);

    // The output of KDF is equal to HMAC-SHA-256(Key, S)
    static constexpr int maxOutPutSize = EVP_MAX_MD_SIZE;
    unsigned int         outputSize    = 0;
    uint8_t              output[maxOutPutSize];
    memset(output, 0, maxOutPutSize);

    HMAC(EVP_sha256(), key.raw(), key.size(), S.raw(), S.size(), output, &outputSize);
    std::vector<uint8_t> ret;

    // If the initial keysize was only 128 bits, then the output is to be limited to
    // the least significant 128 bits
    ret.reserve(key.size());
    uint8_t offset = 0;
    if (key.size() != outputSize) {
        offset = outputSize-key.size();
    }
    std::copy(std::begin(output)+offset, std::begin(output)+outputSize, std::back_inserter(ret));

    return ret;
}

std::vector<uint8_t> DerivateDppkToDpck(OctetString const& dppkId, OctetString const& DPPK) {
    // TS33.180 : §8.5.3
    // Part 1 - Generate a DPCK (MCData Payload Cipher Key)
    // Info (See §8.3): For 1to1 MCData, DPPK (MCData Payload Protection Key) is the PCK (Private Call Key)
    // Info (See §8.4): For Groups MCData, DPPK is the GMK (Group Master Key)
    // Use KDF specified in annex B of 3GPP TS 33.220
    // With the following imposed parameters (3GPP TS33.179 §F.1.3) <-- Where does it comes from ?
    //  FC = 0x53   -> 3GPP TS33.180 §F.1.5
    //  P0 = DPPK-ID
    //  L0 = length of above

    // Encoding of Non-Negative Integer is specified in 3GPP TS33 220 Annex B.2.1.3
    // k should be in range [0, 65535]
    if (dppkId.size() > 65535) {
        return std::vector<uint8_t> {};
    }

    return GenericKdf(0x53, dppkId, DPPK);
}

} // namespace MikeySakkeCrypto
