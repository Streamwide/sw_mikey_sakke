#ifndef MSCRYPTO_ECC_FWD_H
#define MSCRYPTO_ECC_FWD_H

#include <memory>
#ifdef OPENSSL_ONLY
#include <util/bigint-ssl.h>
#else
#include <util/bigint.h> // FIXME: bigint is not opaque so can't be fwd'd
#endif

class bigint_ssl;

namespace MikeySakkeCrypto {
namespace ECC {

template <typename BigInt> class PrimeCurve;
template <typename BigInt> class Point;
#ifdef OPENSSL_ONLY
typedef PrimeCurve<bigint_ssl> PrimeCurveAffine;
#else
typedef PrimeCurve<bigint> PrimeCurveAffine;
#endif
typedef PrimeCurve<bigint_ssl> PrimeCurveJacobian;

typedef std::shared_ptr<const PrimeCurveJacobian> PrimeCurveJacobianPtr;
typedef std::shared_ptr<const PrimeCurveAffine>   PrimeCurveAffinePtr;

} // namespace ECC
} // namespace MikeySakkeCrypto

#endif // MSCRYPTO_ECC_FWD_H
