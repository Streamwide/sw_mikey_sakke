#ifndef UTIL_OCTET_STRING_H
#define UTIL_OCTET_STRING_H

#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

#include <stdint.h>

struct OctetString {
    enum Translation {
        Untranslated,
        AsciiBase16,
        // AsciiBase64,
    };

    std::vector<uint8_t> octets;

    OctetString() = default;
    OctetString(std::string const& ascii_hex);
    OctetString(std::string const& s, Translation t);
    OctetString(size_t n, uint8_t const* p);
    OctetString(size_t n);
    OctetString(std::vector<uint8_t> o);


    std::string translate(Translation t = AsciiBase16) const;
    std::string untranslated() const;

    operator std::string() const {
        return untranslated();
    }

    bool operator==(OctetString const& other) const {
        return octets == other.octets;
    }

    friend std::ostream& operator<<(std::ostream& out, OctetString const& v) {
        using namespace std;
        ios::fmtflags fmt(out.flags());
        out << hex << setfill('0');
        for (uint8_t const *p = v.raw(), *e = p + v.size(); p < e; ++p)
            out << setw(2) << +*p;
        out.flags(fmt);
        return out;
    }

    static void    throw_not_ascii_hex();
    static uint8_t from_ascii_hex(char c);

    void deposit_bigendian(uint8_t* out, size_t len);

    OctetString& clear();

    bool empty() const;

    OctetString& assign(std::string const& s, Translation t = AsciiBase16);
    OctetString& assign(size_t n, uint8_t* p);

    static std::string skipws(std::string s);

    OctetString& concat(OctetString const& other);
    OctetString& concat(std::string const& s, Translation t = AsciiBase16);
    OctetString& concat(size_t octet_count, uint8_t const* octets);
    OctetString& concat(uint8_t octet);

    bool equals(const OctetString& other) const;

    uint8_t const* raw() const;
    uint8_t*       raw();

    size_t size() const;
    void   reserve(size_t new_size);

    void swap(OctetString& other);

    bool to_c(uint8_t** data, size_t* len) const;
};

#endif // UTIL_OCTET_STRING_H
