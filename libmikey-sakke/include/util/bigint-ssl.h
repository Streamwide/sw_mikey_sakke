#ifndef UTIL_BIGINT_OPENSSL_H
#define UTIL_BIGINT_OPENSSL_H

#include <algorithm>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <util/octet-string.h>
#ifndef OPENSSL_ONLY
#include <util/bigint.h>
#endif

class bigint_ssl_scratch {
  public:
    static bigint_ssl_scratch& get();
    ~bigint_ssl_scratch();

  public:
    operator BN_CTX*() {
        return ctx;
    }

  private:
    bigint_ssl_scratch(bigint_ssl_scratch const&);
    bigint_ssl_scratch& operator=(bigint_ssl_scratch const&);
    bigint_ssl_scratch();
    BN_CTX* ctx;
};

// TODO: improve functionality; e.g. operators
// TODO: improve efficiency; e.g. expression chaining
//
class bigint_ssl {
  public:
    enum dont_own { dont_own };

    bigint_ssl(enum dont_own, BIGNUM* bn = nullptr): bn(bn), owned(false) {}

    bigint_ssl(): bn(BN_new()), owned(true) {}
    bigint_ssl(bigint_ssl const& other): bn(BN_dup(other.bn)), owned(true) {}
    bigint_ssl(char const* text, int radix, bool stripws = true): bn(nullptr), owned(true) {
        if (radix != 16 && radix != 10) {
            throw std::invalid_argument("bigint_ssl text constructor supports only hex(16) and dec(10) radices.");
        }

        // since bigint {aka mpz_class}'s text constructor skips
        // whitespace by default, this does the same.
        //
        char* tmp = NULL;
        if (stripws) {
            tmp = (char*)calloc(1, std::strlen(text) + 1);
            if (!tmp) {
                throw std::runtime_error("Could not allocate enough memory");
            }
            char* o = tmp;
            for (char const* t = text; *t != 0; ++t) {
                switch (*t) {
                    case '\t':
                    case '\n':
                    case '\r':
                    case ' ':
                        break;
                    default:
                        *o++ = *t;
                }
            }
            text = tmp;
        }
        if (radix == 16){
            BN_hex2bn(&bn, text);
        } else if (radix == 10){
            BN_dec2bn(&bn, text);
        }
        if (tmp) {
            free(tmp);
        }
    }
    bigint_ssl(long value): bn(BN_new()), owned(true) {
        if (value < 0) {
            BN_set_word(bn, -value);
            BN_set_negative(bn, 1);
        } else
            BN_set_word(bn, value);
    }
    bigint_ssl(unsigned long value): bn(BN_new()), owned(true) {
        BN_set_word(bn, value);
    }

    ~bigint_ssl() {
        reset();
    }

    class ref // for move emulation
    {
        bigint_ssl& src;
        friend class bigint_ssl;
        explicit ref(bigint_ssl& i): src(i) {}
    };

    friend std::ostream& operator<<(std::ostream& out, bigint_ssl const& i) {
        char* dec = BN_bn2hex(i);
        out << dec;
        OPENSSL_free(dec);
        return out;
    }

  public: // query
    bool is_zero() const {
        return !bn || BN_is_zero(bn);
    }

  public: // direct access
    operator BIGNUM*() {
        return bn;
    }
    operator BIGNUM const*() const {
        return bn;
    }
    BIGNUM* ptr() {
        return bn;
    }

  public: // update
    bigint_ssl& operator=(bigint_ssl const& other) {
        reset(other.bn);
        return *this;
    }
    bigint_ssl& operator=(BIGNUM* other) {
        reset(other);
        return *this;
    }
    bigint_ssl& operator=(ref r) {
        std::swap(*this, r.src);
        return *this;
    }

    void reset(BIGNUM* bn = nullptr) {
        if (this->bn == bn)
            return;
        if (bn == nullptr && owned && this->bn)
            BN_free(this->bn);
        if (bn)
            if (this->bn == nullptr)
                this->bn = bn;
            else
                this->bn = BN_copy(this->bn, bn);
        else
            this->bn = nullptr;
        owned = true;
    }
    void reset(enum dont_own, BIGNUM* bn) {
        if (this->bn == bn)
            return;
        if (bn == nullptr && owned && this->bn)
            BN_free(this->bn);
        this->bn = bn;
        owned    = false;
    }

  public: // move emulation (TODO: provide proper move ctor for C++11)
    operator ref() {
        return ref(*this);
    }
    bigint_ssl(ref r): bn(r.src.bn) {
        r.src.bn = nullptr;
    }

  private:
    void    reset(bigint_ssl const&);
    BIGNUM* bn;
    bool    owned;
};

namespace std {
inline bigint_ssl::ref move(bigint_ssl const& i) {
    return const_cast<bigint_ssl&>(i);
}
} // namespace std

#ifndef OPENSSL_ONLY
bigint& to_bigint(bigint& out, BIGNUM const* in);
BIGNUM* to_BIGNUM(BIGNUM* out, bigint const& in);
#endif

inline bigint_ssl& to_bigint_ssl(bigint_ssl& out, uint8_t const* octets, size_t octet_count) {
    BN_bin2bn(octets, octet_count, out);
    return out;
}
inline bigint_ssl& to_bigint_ssl(bigint_ssl& out, OctetString const& in) {
    return to_bigint_ssl(out, in.raw(), in.size());
}

inline bigint_ssl as_bigint_ssl(uint8_t const* octet_string, size_t octet_count) {
    bigint_ssl rc;
    return to_bigint_ssl(rc, octet_string, octet_count);
}
inline bigint_ssl as_bigint_ssl(OctetString const& s) {
    bigint_ssl rc;
    return to_bigint_ssl(rc, s.raw(), s.size());
}

template <typename T> T as(bigint_ssl const&);
template <typename T> T as(bigint_ssl const&, size_t);

inline OctetString as_octet_string(bigint_ssl const& i) {
    OctetString rc(BN_num_bytes(i));
    BN_bn2bin(i, rc.raw());
    return rc;
}

inline OctetString as_octet_string(bigint_ssl const& i, size_t fixed_size) {
    OctetString rc(fixed_size);
    size_t      occupied = BN_num_bytes(i);
    if (occupied > fixed_size)
        throw std::range_error("bigint_ssl too large to fit into constrained OctetString");
    BN_bn2bin(i, rc.raw() + fixed_size - occupied);
    return rc;
}

#endif // UTIL_BIGINT_OPENSSL_H
