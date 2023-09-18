#ifndef UTIL_BIGINT_H
#define UTIL_BIGINT_H

#include <gmpxx.h>
#include <list>
#include <stdexcept>
#include <util/octet-string.h>

// XXX: for now just typedef; ideally want a moveable opaque type;
typedef mpz_class bigint;

class bigint_scratch_pool;
class bigint_scratch {
  public:
    bigint_scratch();
    ~bigint_scratch() {
        release_all();
    }

  public:
    void    release_all();
    bigint& get();

  private:
    std::list<bigint>::iterator begin;
    std::list<bigint>::iterator end;
    bigint_scratch_pool&        pool;
};

inline size_t bits(bigint const& i) {
    return mpz_sizeinbase(i.get_mpz_t(), 2);
}

inline bool is_zero(bigint const& i) {
    return mpz_cmp_ui(i.get_mpz_t(), 0) == 0;
}

// For some reason using mpz_mod gets a different (signedness?)
// result to using operator%.  Not sure why.  mpz_mod yields the
// expected value though.  This overload makes using the lower-level
// function with bigint clearer.
//
inline void mpz_mod(bigint& r, bigint const& a, bigint const& m) {
    mpz_mod(r.get_mpz_t(), a.get_mpz_t(), m.get_mpz_t());
}
inline int mpz_invert(bigint& r, bigint const& a, bigint const& m) {
    return mpz_invert(r.get_mpz_t(), a.get_mpz_t(), m.get_mpz_t());
}
inline void mpz_powm(bigint& r, bigint const& b, bigint const& e, bigint const& m) {
    return mpz_powm(r.get_mpz_t(), b.get_mpz_t(), e.get_mpz_t(), m.get_mpz_t());
}
inline void mpz_powm_ui(bigint& r, bigint const& b, unsigned long e, bigint const& m) {
    return mpz_powm_ui(r.get_mpz_t(), b.get_mpz_t(), e, m.get_mpz_t());
}
inline void mpz_addmul(bigint& r, bigint const& a, bigint const& b) {
    return mpz_addmul(r.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t());
}
inline void mpz_addmul_ui(bigint& r, bigint const& a, unsigned long b) {
    return mpz_addmul_ui(r.get_mpz_t(), a.get_mpz_t(), b);
}
inline void mpz_submul(bigint& r, bigint const& a, bigint const& b) {
    return mpz_submul(r.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t());
}
inline void mpz_submul_ui(bigint& r, bigint const& a, unsigned long b) {
    return mpz_submul_ui(r.get_mpz_t(), a.get_mpz_t(), b);
}
inline int mpz_tstbit(bigint const& i, mp_bitcnt_t n) {
    return mpz_tstbit(i.get_mpz_t(), n);
}

inline bigint& to_bigint(bigint& out, uint8_t const* octet_string, size_t octet_count) {
    mpz_import(out.get_mpz_t(), octet_count, 1, 1, 1, 0, octet_string);
    return out;
}

inline bigint& to_bigint(bigint& out, OctetString const& s) {
    return to_bigint(out, s.raw(), s.size());
}

inline bigint as_bigint(uint8_t const* octet_string, size_t octet_count) {
    bigint rc;
    return to_bigint(rc, octet_string, octet_count);
}

inline bigint as_bigint(OctetString const& s) {
    return as_bigint(s.raw(), s.size());
}

template <typename T> T  as(bigint const&);
template <typename T> T  as(bigint const&, size_t);
template <typename T> T& to(T&, bigint const&);
template <typename T> T& to(T&, bigint const&, size_t);

template <> inline OctetString& to(OctetString& rc, bigint const& i) {
    rc.octets.resize((bits(i) + 7) >> 3);
    mpz_export(rc.raw(), nullptr, 1, 1, 1, 0, i.get_mpz_t());
    return rc;
}

template <> inline OctetString& to(OctetString& rc, bigint const& i, size_t fixed_size) {
    rc.octets.resize(fixed_size);
    size_t occupied = (bits(i) + 7) >> 3;
    if (occupied > fixed_size)
        throw std::range_error("bigint too large to fit into constrained OctetString");
    mpz_export(rc.raw() + fixed_size - occupied, nullptr, 1, 1, 1, 0, i.get_mpz_t());
    return rc;
}

inline OctetString as_octet_string(bigint const& i) {
    OctetString rc((bits(i) + 7) >> 3);
    mpz_export(rc.raw(), nullptr, 1, 1, 1, 0, i.get_mpz_t());
    return rc;
}

inline OctetString as_octet_string(bigint const& i, size_t fixed_size) {
    OctetString rc(fixed_size);
    size_t      occupied = (bits(i) + 7) >> 3;
    if (occupied > fixed_size)
        throw std::range_error("bigint too large to fit into constrained OctetString");
    mpz_export(rc.raw() + fixed_size - occupied, nullptr, 1, 1, 1, 0, i.get_mpz_t());
    return rc;
}

template <> inline OctetString as(bigint const& i) {
    return as_octet_string(i);
}
template <> inline OctetString as(bigint const& i, size_t fixed_size) {
    return as_octet_string(i, fixed_size);
}

#endif // UTIL_BIGINT_H
