#if 0
ROOT=$(dirname $0)/../../../../
${CROSS_PREFIX}g++ -D TEST_MSCRYPTO_ECC_CURVE $(sh $ROOT/build/test-flags.sh $0) $@ \
      $ROOT/util/src/util/bigint-ssl.cpp
exit $?
#endif

// XXX: This implements what's necessary for MIKEY-SAKKE, it is
// XXX: incomplete.  Don't be surprised if you get link errors.
// XXX: Feel free to complete! :o)

#include <memory>
#include <mscrypto/ecc/curve.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <util/bigint-ssl.h>

namespace MikeySakkeCrypto {
namespace ECC {

template <>
struct PrimeCurve<bigint_ssl>::Detail {
    Detail(bigint_ssl const& p, bigint_ssl const& a, bigint_ssl const& h, bigint_ssl const& b, bigint_ssl const& r, bigint_ssl const& Gx,
           bigint_ssl const& Gy, OctetString const& S)
        : p(p), a(a), h(h), b(b), r(r), Gx(Gx), Gy(Gy),
          curve(EC_GROUP_new_curve_GFp(p, a, b, bigint_ssl_scratch::get()), [](EC_GROUP* p) { EC_GROUP_free(p); }),
          P(EC_POINT_new(curve.get()), [](EC_POINT* p) { EC_POINT_free(p); }) {
        // EC_GROUP_set_point_conversion_form(curve, POINT_CONVERSION_UNCOMPRESSED);
        if (!EC_POINT_set_affine_coordinates(curve.get(), P.get(), Gx, Gy, bigint_ssl_scratch::get()))
            throw std::invalid_argument("Failed to set P to affine coordinates of (Gx,Gy) curve");
        if (!EC_POINT_is_on_curve(curve.get(), P.get(), bigint_ssl_scratch::get()))
            throw std::invalid_argument("Point P is not on curve.");
        if (!EC_GROUP_set_generator(curve.get(), P.get(), r, h))
            throw std::invalid_argument("Failed to set P as the generator.");
        if (!S.empty())
            EC_GROUP_set_seed(curve.get(), S.raw(), S.size());
    }

    bigint_ssl p, a, h, b, r, Gx, Gy;

    std::shared_ptr<EC_GROUP> curve;
    std::shared_ptr<EC_POINT> P;
};

template <>
PrimeCurve<bigint_ssl>::PrimeCurve(std::string const& nist) {
    if (nist != "P-256")
        throw std::runtime_error("ECC::PrimeCurve only predefines P-256 at this time.");

    detail.reset(new Detail(std::move(bigint_ssl("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10)),
                            -3l, 1ul, std::move(bigint_ssl("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)),
                            std::move(bigint_ssl("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10)),
                            std::move(bigint_ssl("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)),
                            std::move(bigint_ssl("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)),
                            std::string("c49d360886e704936a6678e1139d26b7819f7e90")));
}

template <>
PrimeCurve<bigint_ssl>::PrimeCurve(bigint_ssl const& p, bigint_ssl const& a, bigint_ssl const& h, bigint_ssl const& b, bigint_ssl const& r,
                                   bigint_ssl const& Gx, bigint_ssl const& Gy, OctetString const& S)
    : detail(new Detail(p, a, h, b, r, Gx, Gy, S)) {}

template <>
bigint_ssl const& PrimeCurve<bigint_ssl>::field_order() const {
    return detail->p;
}
template <>
bigint_ssl const& PrimeCurve<bigint_ssl>::cofactor() const {
    return detail->h;
}
template <>
bigint_ssl const& PrimeCurve<bigint_ssl>::point_order() const {
    return detail->r;
}
template <>
bigint_ssl const& PrimeCurve<bigint_ssl>::base_x() const {
    return detail->Gx;
}
template <>
bigint_ssl const& PrimeCurve<bigint_ssl>::base_y() const {
    return detail->Gy;
}

template <>
struct Point<bigint_ssl>::Detail {
    explicit Detail(PrimeCurveJacobianPtr const& curve)
        : curve(curve), p(EC_POINT_new(curve->detail->curve.get()), [](EC_POINT* p) { EC_POINT_free(p); }), x(bigint_ssl::dont_own),
          y(bigint_ssl::dont_own), insync(false) {}
    Detail(PrimeCurveJacobianPtr const& curve, uint8_t const* uncompressed_octets, size_t uncompressed_len)
        : curve(curve), p(EC_POINT_new(curve->detail->curve.get()), [](EC_POINT* p) { EC_POINT_free(p); }), x(bigint_ssl::dont_own),
          y(bigint_ssl::dont_own), insync(false) {
        if (!EC_POINT_oct2point(curve->detail->curve.get(), p.get(), uncompressed_octets, uncompressed_len, bigint_ssl_scratch::get()))
            throw std::runtime_error("EC point was invalid or not on curve.");
    }
    Detail(Detail const& other)
        : curve(other.curve), p(EC_POINT_dup(other.p.get(), other.curve->detail->curve.get()), [](EC_POINT* p) { EC_POINT_free(p); }),
          x(bigint_ssl::dont_own), y(bigint_ssl::dont_own), insync(false) {}
    void cache_affine() {
        if (!insync) {
            if (!x.ptr())
                x.reset(BN_new());
            if (!y.ptr())
                y.reset(BN_new());
            EC_POINT_get_affine_coordinates(curve->detail->curve.get(), p.get(), x, y, bigint_ssl_scratch::get());
            insync = true;
        }
    }
    void invalidate_cache() {
        insync = false;
    }
    PrimeCurveJacobianPtr     curve;
    std::shared_ptr<EC_POINT> p;
    bigint_ssl                x, y;
    bool                      insync;
};

template <>
Point<bigint_ssl>::Point(PrimeCurveJacobianPtr const& curve, uint8_t const* uncompressed_octets, size_t uncompressed_len)
    : detail(new Detail(curve, uncompressed_octets, uncompressed_len)) {}

template <>
Point<bigint_ssl>::Point(PrimeCurveJacobianPtr const& curve, OctetString const& uncompressed)
    : detail(new Detail(curve, uncompressed.raw(), uncompressed.size())) {}

template <>
Point<bigint_ssl>::Point(PrimeCurveJacobianPtr const& curve): detail(new Detail(curve)) {}

template <>
Point<bigint_ssl>::Point(Point const& other): detail(new Detail(*other.detail)) {}

template <>
bool Point<bigint_ssl>::operator==(Point const& other) const {
    return EC_POINT_cmp(detail->curve->detail->curve.get(), detail->p.get(), other.detail->p.get(), bigint_ssl_scratch::get()) == 0;
}

template <>
Point<bigint_ssl>& Point<bigint_ssl>::add(Point const& other) {
    if (!EC_POINT_add(detail->curve->detail->curve.get(), detail->p.get(), detail->p.get(), other.detail->p.get(),
                      bigint_ssl_scratch::get()))
        throw std::invalid_argument("EC point addition failed.");
    return *this;
}

template <>
Point<bigint_ssl>& Point<bigint_ssl>::multiply(bigint_ssl const& scalar) {
    if (!EC_POINT_mul(detail->curve->detail->curve.get(), detail->p.get(), nullptr, detail->p.get(), scalar, bigint_ssl_scratch::get()))
        throw std::invalid_argument("EC point scalar multiplication failed.");
    return *this;
}

template <>
template <>
EC_POINT const* Point<bigint_ssl>::read_internal() const {
    return detail->p.get();
}
template <>
template <>
EC_POINT* Point<bigint_ssl>::readwrite_internal() {
    detail->invalidate_cache();
    return detail->p.get();
}

template <>
template <>
EC_GROUP const* PrimeCurve<bigint_ssl>::read_internal() const {
    return detail->curve.get();
}
template <>
template <>
EC_POINT const* PrimeCurve<bigint_ssl>::read_internal() const {
    return detail->P.get();
}

template <>
bigint_ssl const& Point<bigint_ssl>::x() const {
    detail->cache_affine();
    return detail->x;
}
template <>
bigint_ssl const& Point<bigint_ssl>::y() const {
    detail->cache_affine();
    return detail->y;
}

template <>
Point<bigint_ssl>& Point<bigint_ssl>::assign(bigint_ssl const& x, bigint_ssl const& y) {
    detail->x = x;
    detail->y = y;
    return *this;
}

// template <> void add_self() { EC_POINT_dbl
// template <> void multiply(bigint const& scalar);
// template <> void add(Point const& other);
// template <> void inverse();

template class PrimeCurve<bigint_ssl>;
template class Point<bigint_ssl>;

} // namespace ECC
} // namespace MikeySakkeCrypto

#if TEST_MSCRYPTO_ECC_CURVE
#include <iostream>
using namespace MikeySakkeCrypto;
int main() {
    ECC::PrimeCurveJacobianPtr p256(new ECC::PrimeCurveJacobian("P-256"));

    std::cout << "field_order " << p256->field_order()
              << "\n"
                 "cofactor    "
              << p256->cofactor()
              << "\n"
                 "point_order "
              << p256->point_order()
              << "\n"
                 "base_x      "
              << p256->base_x()
              << "\n"
                 "base_y      "
              << p256->base_y() << "\n";

    ECC::Point<bigint_ssl> p(p256, OctetString::skipws("04                                 "
                                                       "758A1427 79BE89E8 29E71984 CB40EF75"
                                                       "8CC4AD77 5FC5B9A3 E1C8ED52 F6FA36D9"
                                                       "A79D2476 92F4EDA3 A6BDAB77 D6AA6474"
                                                       "A464AE49 34663C52 65BA7018 BA091F79"));

    std::cout << "x: " << p.x() << "\n";
    std::cout << "y: " << p.y() << "\n";

    std::cout << "degen-cmp: " << (p == p) << "\n";

    EC_POINT const* ecp = p.read_internal<EC_POINT>();
    bigint_ssl      x2, y2;
    EC_POINT_get_affine_coordinates_GFp(p256->read_internal<EC_GROUP>(), ecp, x2, y2, bigint_ssl_scratch::get());

    std::cout << "x2: " << x2 << "\n";
    std::cout << "y2: " << y2 << "\n";
}
#endif // TEST_MSCRYPTO_ECC_CURVE
