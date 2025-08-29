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
#include <util/bigint.h>

namespace MikeySakkeCrypto {

void HashToIntegerRangeSHA256(bigint& v, uint8_t* octets, size_t octet_count, bigint const& n) {
    // RFC6508 5.1

    // 1) A = hashfn(s)
    SHA256Digest A;
    A.digest(octets, octet_count).complete();

    // 2) h = zero initialized string of hashlen bits
    SHA256Digest h;

    // 3) l = ceiling(lg(n)/hashlen)
    int l = (bits(n) + 255) >> 8;

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
    to_bigint(v, vprime);
    mpz_mod(v, v, n);
}

//=============================================================================
// RFC6508 2.1 -- F_p^2 and PF_p arithmetic

template <class B>
struct PF_p_ref {
    explicit PF_p_ref(bigint_scratch& scratch): x_1(scratch.get()), x_2(scratch.get()) {}
    PF_p_ref(PF_p_ref& other) = default;
    template <class Other>
    PF_p_ref(Other const& other): x_1(other.x_1), x_2(other.x_2) {}
    B& x_1;
    B& x_2;

  private:
    PF_p_ref& operator=(PF_p_ref const&);
};
using PF_p       = PF_p_ref<bigint>;
using PF_p_const = PF_p_ref<bigint const>;

// Square an element A of PF_p, placing the result in R.  R and A
// may point to the same storage.
//
void PF_p_sqr(bigint const& p, PF_p R, PF_p_const A) {
    bigint_scratch scratch;
    PF_p           Ta(scratch);
    PF_p           Tb(scratch);

    Ta.x_1 = A.x_1;
    Ta.x_2 = A.x_2;

    Tb.x_1 = Ta.x_1 + Ta.x_2;
    Tb.x_2 = Ta.x_1 - Ta.x_2;

    R.x_1 = Tb.x_1 * Tb.x_2;
    mpz_mod(R.x_1, R.x_1, p);

    R.x_2 = Ta.x_1 * Ta.x_2;

    R.x_2 <<= 1;
    mpz_mod(R.x_2, R.x_2, p);
}

// Multiply two elements, A and B, of PF_p, placing the result in R.
// Any of R, A or B may share the same memory (though if A and B share
// the same memory it is more efficient to call PF_p_sqr() above.
//
void PF_p_mul(bigint const& p, PF_p R, PF_p_const A, PF_p_const B) {
    bigint_scratch scratch;
    PF_p           Ta(scratch);
    PF_p           Tb(scratch);

    Ta.x_1 = A.x_1;
    Ta.x_2 = A.x_2;
    Tb.x_1 = B.x_1;
    Tb.x_2 = B.x_2;

    R.x_1 = Ta.x_1 * Tb.x_1;
    mpz_submul(R.x_1.get_mpz_t(),   // XXX: should be implemented by
               Ta.x_2.get_mpz_t(),  // XXX: r -= op1 * op2 expression
               Tb.x_2.get_mpz_t()); // XXX: template, but isn't
    mpz_mod(R.x_1, R.x_1, p);

    R.x_2 = Ta.x_1 * Tb.x_2;
    mpz_addmul(R.x_2.get_mpz_t(),   // XXX: should be implemented by
               Ta.x_2.get_mpz_t(),  // XXX: r += op1 * op2 expression
               Tb.x_1.get_mpz_t()); // XXX: template, but isn't
    mpz_mod(R.x_2, R.x_2, p);
}

// Raise an element A of PF_p to power n, storing the result in R.
// R and A may share the same storage.
//
void PF_p_pow(bigint const& p, PF_p& R, PF_p_const A, bigint const& n) {
    if (is_zero(n))
        throw std::invalid_argument("PF_p_pow raise to power 0 not implemented.");

    bigint_scratch scratch;
    PF_p           acc(scratch);
    acc.x_1 = A.x_1;
    acc.x_2 = A.x_2;

    for (size_t N = bits(n) - 1; N != 0; --N) {
        PF_p_sqr(p, acc, acc);
        if (mpz_tstbit(n.get_mpz_t(), N - 1))
            PF_p_mul(p, acc, acc, A);
    }
    R.x_1 = acc.x_1;
    R.x_2 = acc.x_2;
}
//=============================================================================

inline MikeySakkeCrypto::SakkeParameterSet const GetParamSet(std::string const& community, MikeySakkeKMS::KeyAccessPtr const& keys) {
    if (keys->GetPublicParameter(community, "SakkeSet") != "1")
        throw std::invalid_argument("Only SAKKE parameter set 1 is supported.");

    return MikeySakkeCrypto::sakke_param_set_1();
}

//=============================================================================
// Scratch holder for elements of E(F_p)[q]
//
template <class B>
struct EF_pq_ref {
    explicit EF_pq_ref(bigint_scratch& scratch): x(scratch.get()), y(scratch.get()) {}
    EF_pq_ref(bigint_scratch& scratch, ECC::Point<bigint> const& p): x(scratch.get()), y(scratch.get()) {
        x = p.x();
        y = p.y();
    }
    template <class Other>
    explicit EF_pq_ref(Other const& other): x(other.x), y(other.y) {}
    B& x;
    B& y;

  private:
    EF_pq_ref& operator=(EF_pq_ref const&);
};

using EF_pq       = EF_pq_ref<bigint>;
using EF_pq_const = EF_pq_ref<bigint const>;

//=============================================================================

//=============================================================================
// RFC2508 3.2. The Tate-Lichtenbaum Pairing
// Ref also: MIKEY-SAKKE on Android 3.2.2
//
// Transcribed from the reference implementation
//
void ComputePairing(SakkeParameterSet const& params, bigint& w, ECC::Point<bigint> const& R, ECC::Point<bigint> const& Q) {
    ECC::PrimeCurveAffinePtr E = params.E_a;
    bigint const&            p = E->field_order();
    bigint const&            q = E->point_order();

    bigint_scratch scratch;
    bigint&        q_minus_one = scratch.get();
    q_minus_one                = q - 1;

    // XXX: Going via ECC::Point requires a number of unnecessary
    // XXX: dereferences.  Use EF_pq_ref above for scratch values.

    PF_p  v(scratch), T(scratch);
    EF_pq C(scratch, R);

    v.x_1 = 1;
    v.x_2 = 0;

    bigint& t = scratch.get();

    for (size_t N = bits(q_minus_one) - 1; N != 0; --N) {
        PF_p_sqr(p, v, v);

        mpz_powm_ui(T.x_1, C.x, 2, p);
        T.x_1 -= 1;
        T.x_1 *= 3;
        t = Q.x() + C.x;
        T.x_1 *= t;
        mpz_mod(T.x_1, T.x_1, p);
        mpz_powm_ui(t, C.y, 2, p);
        mpz_submul_ui(T.x_1, t, 2);
        mpz_mod(T.x_1, T.x_1, p);

        T.x_2 = C.y << 1;
        T.x_2 *= Q.y();
        mpz_mod(T.x_2, T.x_2, p);

        PF_p_mul(p, v, v, T);

        // inline doubling of EC point
        // (it is known the C is not at infinity)
        {
            bigint_scratch ecd_scratch;
            bigint&        lambda    = ecd_scratch.get();
            bigint&        lambda_sq = ecd_scratch.get();
            bigint&        EAT1      = ecd_scratch.get();
            EF_pq          EAR(ecd_scratch);

            mpz_powm_ui(lambda, C.x, 2, p);
            lambda -= 1;
            lambda *= 3;
            EAT1 = C.y << 1;
            mpz_invert(EAT1, EAT1, p);
            lambda *= EAT1;
            mpz_mod(lambda, lambda, p);

            mpz_powm_ui(lambda_sq, lambda, 2, p);

            EAT1  = C.x << 1;
            EAR.x = lambda_sq - EAT1;
            mpz_mod(EAR.x, EAR.x, p);

            EAR.y = EAT1 - lambda_sq;
            EAR.y += C.x;
            EAR.y *= lambda;
            mpz_mod(EAR.y, EAR.y, p);
            EAR.y -= C.y;
            mpz_mod(EAR.y, EAR.y, p);

            C.x = EAR.x;
            C.y = EAR.y;
        }

        if (mpz_tstbit(q_minus_one, N - 1)) {
            T.x_1 = Q.x() + R.x();
            T.x_1 *= C.y;
            mpz_mod(T.x_1, T.x_1, p);
            t = Q.x() + C.x;
            mpz_submul(T.x_1, R.y(), t);
            mpz_mod(T.x_1, T.x_1, p);

            T.x_2 = C.x - R.x();
            T.x_2 *= Q.y();
            mpz_mod(T.x_2, T.x_2, p);

            PF_p_mul(p, v, v, T);

            // inline addition of EC point R to C
            // (it is known that neither R nor C are at infinity)
            {
                bigint_scratch eca_scratch;
                bigint&        lambda    = eca_scratch.get();
                bigint&        lambda_sq = eca_scratch.get();
                bigint&        EAT1      = eca_scratch.get();
                EF_pq          EAR(eca_scratch);

                lambda = R.y() - C.y;
                EAT1   = R.x() - C.x;
                mpz_invert(EAT1, EAT1, p);
                lambda *= EAT1;
                mpz_mod(lambda, lambda, p);

                mpz_powm_ui(lambda_sq, lambda, 2, p);

                EAR.x = lambda_sq - C.x;
                EAR.x -= R.x();
                mpz_mod(EAR.x, EAR.x, p);

                EAR.y = R.x() - lambda_sq;
                mpz_addmul_ui(EAR.y, C.x, 2);
                EAR.y *= lambda;
                mpz_mod(EAR.y, EAR.y, p);
                EAR.y -= C.y;
                mpz_mod(EAR.y, EAR.y, p);

                C.x = EAR.x;
                C.y = EAR.y;
            }
        }
    }

    PF_p_sqr(p, v, v);
    PF_p_sqr(p, v, v);

    mpz_invert(w, v.x_1, p);
    w *= v.x_2;
    mpz_mod(w, w, p);
}

//=============================================================================

bool ValidateReceiverSecretKey(const OctetString& identifier, std::string const& community, MikeySakkeKMS::KeyStoragePtr const& keys) {
    SakkeParameterSet const params = GetParamSet(community, keys);

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

    ECC::Point<bigint> a_P_plus_Z(params.E_a);
    {
        ECC::Point<bigint_ssl> ecp_a_P_plus_Z(params.E_j);
        ECC::Point<bigint_ssl> ecp_Z(params.E_j, Z);
        auto const*            ecg = params.E_j->read_internal<EC_GROUP>();
        BN_CTX*                ssl = bigint_ssl_scratch::get();
        BN_CTX_start(ssl);
        BIGNUM* ssl_a = BN_CTX_get(ssl);
        // We should be able to pass identifier.raw(), this is a workaround
        BN_bin2bn((uint8_t*)identifier.translate().c_str(), identifier.translate().length(), ssl_a);
        EC_POINT_mul(ecg, ecp_a_P_plus_Z.readwrite_internal<EC_POINT>(), ssl_a, ecp_Z.read_internal<EC_POINT>(), BN_value_one(), ssl);
        BN_CTX_end(ssl);

        bigint_scratch scratch;
        a_P_plus_Z.assign(to_bigint(scratch.get(), ecp_a_P_plus_Z.x()), to_bigint(scratch.get(), ecp_a_P_plus_Z.y()));
    }

    ECC::Point<bigint> ecp_RSK(params.E_a, RSK);

    bigint_scratch scratch;
    bigint&        w = scratch.get();
    ComputePairing(params, w, a_P_plus_Z, ecp_RSK);

    if (w == params.g) {
        MIKEY_SAKKE_LOGD("Successfuly validated Secret Sey for %s", identifier.translate().c_str());
        return true;
    }

    // otherwise revoke this keyset
    keys->RevokeKeys(identifier.translate());
    MIKEY_SAKKE_LOGE("Failed to validate Secret Key for %s", identifier.translate().c_str());
    return false;
}

OctetString GenerateSharedSecretAndSED(OctetString& SED, OctetString const& identifier, std::string const& community,
                                       MikeySakkeKMS::KeyAccessPtr const& keys, const OctetString& SSV) {

    SakkeParameterSet const& params = GetParamSet(community, keys);
    bigint_scratch           gmp;
    bigint const&            p = params.E_a->field_order();
    bigint const&            q = params.E_a->point_order();

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
    // TODO this is a workaround, we should be able to simply pass the octetstring
    SSV_b.concat(OctetString {identifier.translate(), OctetString::Translation::Untranslated});
    bigint& r = gmp.get();
    HashToIntegerRangeSHA256(r, SSV_b.raw(), SSV_b.size(), q);

    // 3) Compute R_(b,S) = [r]([b]P + Z_S) in E(F_p)
    //
    // Rewrite to use OpenSSL vector scale and sum (EC_POINTs_mul).
    // Note that P has been set as the base-point in E_j so only Z and
    // its scalar are placed in the vector.  Note also that the storage
    // used for Z is reused for the result Rb.
    //
    // 3') Compute R_(b,S) = [r][b]P + [r]Z_S
    //
    {
        ECC::Point<bigint_ssl>  ecp_Z(params.E_j, Z);
        ECC::Point<bigint_ssl>& ecp_Rb = ecp_Z;
        BN_CTX*                 ssl    = bigint_ssl_scratch::get();

        // BN_CTX_start(ssl);
        bigint_ssl ssl_r;
        bigint_ssl ssl_rb;

        to_BIGNUM(ssl_r, r);
        // TODO this is a workaround, we should be able to simply pass the octetstring
        BN_bin2bn((uint8_t*)identifier.translate().c_str(), identifier.translate().length(), ssl_rb);
        BN_mul(ssl_rb, ssl_r, ssl_rb, ssl);

        auto const*     ecg       = params.E_j->read_internal<EC_GROUP>();
        EC_POINT const* points[]  = {ecp_Z.read_internal<EC_POINT>()};
        BIGNUM const*   scalars[] = {ssl_r};
        EC_POINT_mul(ecg, ecp_Rb.readwrite_internal<EC_POINT>(), ssl_rb, points[0], scalars[0], ssl);

        bigint_ssl Rbx_bn;
        bigint_ssl Rby_bn;
        EC_POINT_get_affine_coordinates(params.E_j->read_internal<EC_GROUP>(), points[0], Rbx_bn, Rby_bn, ssl);

        // BN_bn2bin will truncate leading zeroes so we need to make sure we catch that when it happens
        size_t coord_len = (bits(p) + 7) >> 3;

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
    }

    // 4) Compute the HINT, H;
    //
    // 4.a) Compute g^r.
    //
    OctetString g_pow_r_octets;
    if (!is_zero(r)) {
        bigint_scratch scratch;
        PF_p           g(scratch);
        g.x_1 = 1;
        g.x_2 = params.g;
        PF_p_pow(p, g, g, r);

        // Form representation of PF_p (x_1, x_2) in F_p (x_2/x_1 mod p)
        //
        bigint& g_pow_r = scratch.get();
        mpz_invert(g_pow_r, g.x_1, p);
        g_pow_r = (g_pow_r * g.x_2);
        mpz_mod(g_pow_r, g_pow_r, p);

        to<OctetString>(g_pow_r_octets, g_pow_r);
    }

    // 4.b) Compute H := SSV XOR HashToIntegerRange( g^r, 2^n, Hash );
    //
    OctetString H_octets;
    {
        bigint_scratch scratch;
        bigint&        H         = scratch.get();
        bigint&        two_pow_n = r; // reuse 'r' from above
        two_pow_n                = 1;
        two_pow_n <<= params.n;
        HashToIntegerRangeSHA256(H, g_pow_r_octets.raw(), g_pow_r_octets.size(), two_pow_n);
        bigint& ssv = r; // reuse 'r' from above
        H           = to_bigint(ssv, SSV) ^ H;
        to<OctetString>(H_octets, H);
    }

    // 5) Form the SED ( R_(b,S), H )
    //
    SED.concat(H_octets);

    // 6) Output SSV
    return SSV;
}

OctetString ExtractSharedSecret(OctetString const& SED, const OctetString& identifier, std::string const& community,
                                MikeySakkeKMS::KeyAccessPtr const& keys) {
    SakkeParameterSet const& params = GetParamSet(community, keys);
    bigint_scratch           scratch;
    bigint const&            p = params.E_a->field_order();
    bigint const&            q = params.E_a->point_order();

    size_t L              = (bits(p) + 7) >> 3;
    size_t Rb_octet_count = 2 * L + 1; // +1 for 0x04 to indicate that the data is uncompressed

    if (SED.size() < Rb_octet_count) {
        MIKEY_SAKKE_LOGE("Shared secret extraction failure: SED invalid size");
        return {};
    }

    const OctetString& Z   = keys->GetPublicKey(community, "Z");
    const OctetString& RSK = keys->GetPrivateKey(identifier.translate(), "RSK");

    if (Z.octets[0] != 0x04 || RSK.octets[0] != 0x04) {
        MIKEY_SAKKE_LOGE("Key invalid format. Must be uncompressed data.");
        return {};
    }

    // RFC6508 6.2.2
    //
    // 1) Parse the Encapsulated Data ( R_(b,S), H ), and extract
    //    R_(b,S) and H;
    //
    ECC::Point<bigint> Rb(params.E_a, SED.raw(), Rb_octet_count);
    OctetString        H_octets(SED.size() - Rb_octet_count, SED.raw() + Rb_octet_count);

    // 2) Compute w := < R_(b,S), K_(b,S) >
    //
    OctetString w_octets;
    {
        bigint_scratch     w_scratch;
        bigint&            w = w_scratch.get();
        ECC::Point<bigint> ecp_RSK(params.E_a, RSK);
        ComputePairing(params, w, Rb, ecp_RSK);
        to<OctetString>(w_octets, w);
    }

    // 3) Compute SSV := H XOR HashToIntegerRange( w, 2^n, Hash );
    //
    OctetString SSV_octets;
    {
        bigint& SSV       = scratch.get();
        bigint& two_pow_n = scratch.get();
        two_pow_n         = 1;
        two_pow_n <<= params.n;
        HashToIntegerRangeSHA256(SSV, w_octets.raw(), w_octets.size(), two_pow_n);
        bigint& H = two_pow_n; // reuse 'two_pow_n' from above
        SSV       = to_bigint(H, H_octets) ^ SSV;

        auto leading_zeroes = (params.n / 8) - ((bits(SSV) + 7) >> 3);
        for (size_t i = 0; i < leading_zeroes; ++i) {
            SSV_octets.concat(0);
        }
        OctetString tmp;
        to<OctetString>(tmp, SSV);
        SSV_octets.concat(tmp);
    }

    // 4) Compute r = HashToIntegerRangeSHA256( SSV || b, q, Hash )
    //
    OctetString SSV_b(SSV_octets);
    // TODO this is a workaround, we should be able to simply pass the octetstring
    SSV_b.concat(OctetString {identifier.translate(), OctetString::Translation::Untranslated});

    bigint& r = scratch.get();
    HashToIntegerRangeSHA256(r, SSV_b.raw(), SSV_b.size(), q);

    // 5) Compute TEST = [r][b]P + [r]Z_S
    //
    ECC::Point<bigint_ssl> TEST(params.E_j, Z);
    {
        ECC::Point<bigint_ssl>& ecp_Z = TEST;
        BN_CTX*                 ssl   = bigint_ssl_scratch::get();
        BN_CTX_start(ssl);
        BIGNUM* ssl_r  = BN_CTX_get(ssl);
        BIGNUM* ssl_rb = BN_CTX_get(ssl);

        to_BIGNUM(ssl_r, r);
        // We should be able to pass identifier.raw(), this is a workaround
        BN_bin2bn((uint8_t*)identifier.translate().c_str(), identifier.translate().length(), ssl_rb);

        BN_mul(ssl_rb, ssl_r, ssl_rb, ssl);

        auto const*     ecg       = params.E_j->read_internal<EC_GROUP>();
        EC_POINT const* points[]  = {ecp_Z.read_internal<EC_POINT>()};
        BIGNUM const*   scalars[] = {ssl_r};
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

    // The 28 least significant bits of the 256/128 bits of the KDF output shall be used as the User Salt.
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
    //  FC = 0xaa for DPPK, 0x50 for GukID-salt
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
    // With the following imposed parameters (3GPP TS33.179 §F.1.3)
    //  FC = 0xaa.
    //  P0 = DPPK-ID
    //  L0 = length of above

    // Encoding of Non-Negative Integer is specified in 3GPP TS33 220 Annex B.2.1.3
    // k should be in range [0, 65535]
    if (dppkId.size() > 65535) {
        return std::vector<uint8_t> {};
    }

    return GenericKdf(0xaa, dppkId, DPPK);
}

} // namespace MikeySakkeCrypto

#if TEST_SAKKE
#include <iostream>

using namespace MikeySakkeCrypto;

static void TestHashToIntegerRangeSHA256() {
    OctetString M = OctetString::skipws("12345678 9ABCDEF0 12345678 9ABCDEF0"
                                        "32303131 2D303200 74656C3A 2B343437"
                                        "37303039 30303132 3300             ");

    OctetString q = OctetString::skipws("265EAEC7 C2958FF6 99718466 36B4195E"
                                        "905B0338 672D2098 6FA6B8D6 2CF8068B"
                                        "BD02AAC9 F8BF03C6 C8A1CC35 4C69672C"
                                        "39E46CE7 FDF22286 4D5B49FD 2999A9B4"
                                        "389B1921 CC9AD335 144AB173 595A0738"
                                        "6DABFD2A 0C614AA0 A9F3CF14 870F026A"
                                        "A7E535AB D5A5C7C7 FF38FA08 E2615F6C"
                                        "203177C4 2B1EB3A1 D99B601E BFAA17FB");

    bigint r;
    HashToIntegerRangeSHA256(r, M.raw(), M.size(), as_bigint(q));

    std::cout << "M:  " << M << "\n\n";
    std::cout << "q:  " << q << "\n\n";
    std::cout << "r:  " << as_octet_string(r) << "\n\n";
}

int main() {
    TestHashToIntegerRangeSHA256();
}
#endif // TEST_SAKKE
