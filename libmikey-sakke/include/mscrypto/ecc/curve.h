#ifndef MSCRYPTO_ECC_CURVE_H
#define MSCRYPTO_ECC_CURVE_H

#include <mscrypto/ecc/point.h>
#include <string>

namespace MikeySakkeCrypto {
namespace ECC {

template <typename BigInt>
class PrimeCurve
{
public:

   PrimeCurve(std::string const& nist);
   PrimeCurve(BigInt const& p,
              BigInt const& a,
              BigInt const& h,
              BigInt const& b,
              BigInt const& r,
              BigInt const& Gx,
              BigInt const& Gy,
              OctetString const& S = OctetString());

public:

   BigInt const& field_order() const; // p
   BigInt const& cofactor() const;    // h
   BigInt const& point_order() const; // r
   BigInt const& base_x() const;      // Gx
   BigInt const& base_y() const;      // Gy

   OctetString base_point_octets() const
   {
      OctetString rc("4");
      rc.concat(as_octet_string(base_x()));
      rc.concat(as_octet_string(base_y()));
      return rc;
   }

   bool is_on_curve(BigInt const& x,
                    BigInt const& y);


   template <typename T>
   T* readwrite_internal();
   template <typename T>
   T const* read_internal() const;

private:

   struct Detail;
   std::shared_ptr<Detail> detail;
   friend class Point<BigInt>;
};


}} // MikeySakkeCrypto::ECC

#endif//MSCRYPTO_ECC_CURVE_H

