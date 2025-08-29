#ifndef MSCRYPTO_PARAMETER_SET_H
#define MSCRYPTO_PARAMETER_SET_H

#include <mscrypto/ecc/curve.h>
#ifdef OPENSSL_ONLY
#include <util/bigint-ssl.h>
using bigint = bigint_ssl;
#else
#include <util/bigint.h>
#endif
namespace MikeySakkeCrypto {

enum HashingAlgorithm {
    SHA1   = 1,
    SHA256 = 256,
};

template <HashingAlgorithm> struct HashLen;
template <> struct HashLen<SHA1> { static const int octets = 20; };
template <> struct HashLen<SHA256> { static const int octets = 32; };

/**
 * Describes a parameter set for SAKKE key encryption.
 */
struct SakkeParameterSet {
    uint8_t iana_sakke_params_value;

    int                        n;
    ECC::PrimeCurveAffinePtr   E_a; // for T-L pairing
    ECC::PrimeCurveJacobianPtr E_j; // for everything else
    bigint                     g;
    HashingAlgorithm           hash;
    int                        hash_len;

    SakkeParameterSet(uint8_t iana_sakke_params_value, int n, char const* p_asciihex, char const* q_asciihex, char const* Px_asciihex,
                      char const* Py_asciihex, char const* g_asciihex, HashingAlgorithm, int hash_len);
};

/**
 * Describes a parameter set for MIKEY-SAKKE message signing with
 * ECCSI.
 */
struct SigningParameterSet {
    ECC::PrimeCurveJacobianPtr curve;
    HashingAlgorithm           hash;
    int                        hash_len;

    SigningParameterSet(std::string const& nist, HashingAlgorithm, int hash_len);
};

/**
 * Currently the one and only SAKKE parameter set defined for
 * MIKEY-SAKKE (RFC 6509).
 */
SakkeParameterSet const& sakke_param_set_1();
SakkeParameterSet const& sakke_param_set_2();

/**
 * The P-256 curve used for MIKEY-SAKKE message signing (RFC 6509).
 */
SigningParameterSet const& eccsi_6509_param_set();

} // namespace MikeySakkeCrypto

#endif // MSCRYPTO_PARAMETER_SET_H
