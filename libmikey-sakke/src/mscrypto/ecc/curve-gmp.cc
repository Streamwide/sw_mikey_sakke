#include <mscrypto/ecc/curve.h>

#include <utility>

namespace MikeySakkeCrypto {
namespace ECC {

template <>
struct PrimeCurve<bigint>::Detail {
    Detail() = default;
    Detail(bigint p, bigint a, bigint h, bigint b, bigint r, bigint Gx, bigint Gy)
        : p(std::move(p)), a(std::move(a)), h(std::move(h)), b(std::move(b)), r(std::move(r)), Gx(std::move(Gx)), Gy(std::move(Gy)) {}
    bigint p, a, h, b, r, Gx, Gy;
};

template <>
PrimeCurve<bigint>::PrimeCurve(std::string const& nist): detail(new Detail) {
    if (nist != "P-256")
        throw std::runtime_error("ECC::PrimeCurve only predefines P-256 at this time.");

    Detail& d = *detail;

    d.p.set_str("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10);
    d.a = -3;
    d.h = 1;
    d.b.set_str("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
    d.r.set_str("115792089210356248762697446949407573529996955224135760342422259061068512044369", 10);
    d.Gx.set_str("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
    d.Gy.set_str("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);
}

template <>
PrimeCurve<bigint>::PrimeCurve(bigint const& p, bigint const& a, bigint const& h, bigint const& b, bigint const& r, bigint const& Gx,
                               bigint const& Gy, [[maybe_unused]] OctetString const& S)
    : detail(new Detail(p, a, h, b, r, Gx, Gy)) {}

template <>
bigint const& PrimeCurve<bigint>::field_order() const {
    return detail->p;
}
template <>
bigint const& PrimeCurve<bigint>::cofactor() const {
    return detail->h;
}
template <>
bigint const& PrimeCurve<bigint>::point_order() const {
    return detail->r;
}
template <>
bigint const& PrimeCurve<bigint>::base_x() const {
    return detail->Gx;
}
template <>
bigint const& PrimeCurve<bigint>::base_y() const {
    return detail->Gy;
}

template <>
struct Point<bigint>::Detail {
    explicit Detail(PrimeCurveAffinePtr curve): curve(std::move(curve)) {}
    Detail(PrimeCurveAffinePtr curve, uint8_t const* uncompressed_octets, size_t uncompressed_len): curve(std::move(curve)) {
        if (uncompressed_len == 0)
            throw std::invalid_argument("Cannot create EC point, no values specified.");
        if (*uncompressed_octets++ != 4)
            throw std::invalid_argument("Cannot create EC point, only uncompressed octet strings are supported.");
        --uncompressed_len;
        if (uncompressed_len & 1)
            throw std::invalid_argument("Cannot create EC point, odd number of octets in value.");
        uncompressed_len >>= 1;
        to_bigint(x, uncompressed_octets, uncompressed_len);
        uncompressed_octets += uncompressed_len;
        to_bigint(y, uncompressed_octets, uncompressed_len);
    }
    Detail(Detail const& other): curve(other.curve) {}
    PrimeCurveAffinePtr curve;
    bigint              x, y;
};

template <>
Point<bigint>::Point(PrimeCurveAffinePtr const& curve, uint8_t const* uncompressed_octets, size_t uncompressed_len)
    : detail(new Detail(curve, uncompressed_octets, uncompressed_len)) {}

template <>
Point<bigint>::Point(PrimeCurveAffinePtr const& curve, OctetString const& uncompressed)
    : detail(new Detail(curve, uncompressed.raw(), uncompressed.size())) {}

template <>
Point<bigint>::Point(PrimeCurveAffinePtr const& curve): detail(new Detail(curve)) {}

template <>
bool Point<bigint>::operator==(Point const& other) const {
    return detail->x == other.detail->x && detail->y == other.detail->y;
}

template <>
bigint const& Point<bigint>::x() const {
    return detail->x;
}
template <>
bigint const& Point<bigint>::y() const {
    return detail->y;
}

template <>
Point<bigint>& Point<bigint>::add([[maybe_unused]] Point const& other) {
    return *this;
}

template <>
Point<bigint>& Point<bigint>::multiply([[maybe_unused]] bigint const& scalar) {
    return *this;
}

template <>
Point<bigint>& Point<bigint>::assign(bigint const& x, bigint const& y) {
    detail->x = x;
    detail->y = y;
    return *this;
}

} // namespace ECC
} // namespace MikeySakkeCrypto
