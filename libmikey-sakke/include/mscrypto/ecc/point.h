#ifndef MSCRYPTO_ECC_POINT_H
#define MSCRYPTO_ECC_POINT_H

#include <mscrypto/ecc/fwd.h>

namespace MikeySakkeCrypto {
namespace ECC {

template <typename BigInt>
class Point // TODO: make moveable
{
  public:
    Point(std::shared_ptr<PrimeCurve<BigInt> const> const&);
    Point(std::shared_ptr<PrimeCurve<BigInt> const> const&, uint8_t const* uncompressed_octets, size_t uncompressed_len);
    Point(std::shared_ptr<PrimeCurve<BigInt> const> const&, BigInt const& x, BigInt const& y);
    Point(std::shared_ptr<PrimeCurve<BigInt> const> const&, OctetString const& uncompressed);
    Point(Point const&);

  public:
    Point& assign(BigInt const& x, BigInt const& y);

    // Checked operations (all return *this)
    //
    Point& add_self();
    Point& multiply(BigInt const& scalar);
    Point& add(Point const& other);
    Point& inverse();

    // Optimal operations for when the client can guarantee
    // that no referenced points are at infinity.
    // (all return *this)
    //
    Point& ninf_add_self();
    Point& ninf_multiply(BigInt const& scalar);
    Point& ninf_add(Point const& other);
    Point& ninf_inverse();

    bool operator==(Point const& other) const;

    // access internal data for mutation This will invalidate
    // any cache that the object has created.
    template <typename T> T*       readwrite_internal();
    template <typename T> T const* read_internal() const;

    BigInt const& x() const;
    BigInt const& y() const;

    OctetString octets() const {
        OctetString rc("4");
        rc.concat(as_octet_string(x()));
        rc.concat(as_octet_string(y()));
        return rc;
    }

  private:
    struct Detail;
    std::shared_ptr<Detail> detail;
    friend class PrimeCurve<BigInt>;
};

} // namespace ECC
} // namespace MikeySakkeCrypto

#endif // MSCRYPTO_ECC_POINT_H
