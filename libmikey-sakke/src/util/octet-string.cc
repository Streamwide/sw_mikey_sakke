#include <util/octet-string.h>

OctetString::OctetString(std::string const& ascii_hex) {
    assign(ascii_hex, AsciiBase16);
}

OctetString::OctetString(std::string const& s, Translation t) {
    assign(s, t);
}

OctetString::OctetString(size_t n, uint8_t const* p): octets(p, p + n) {}
OctetString::OctetString(size_t n): octets(n) {}
OctetString::OctetString(std::vector<uint8_t> o): octets(std::move(o)) {}

std::string OctetString::translate(Translation t) const {
    if (t == AsciiBase16) {
        std::ostringstream oss;
        oss << *this;
        return oss.str();
    }

    if (t == Untranslated)
        return untranslated();

    return {};
}

std::string OctetString::untranslated() const {
    return std::string(reinterpret_cast<char const*>(raw()), size());
}

void OctetString::deposit_bigendian(uint8_t* out, size_t len) {
    size_t this_len = size();
    if (len < this_len)
        throw std::range_error("OctetString to large to deposit into given region");

    if (this_len < len) {
        len -= this_len; // len ==> prefix-len
        std::memset(out, 0, len);
        std::memcpy(out + len, raw(), this_len);
    } else
        std::memcpy(out, raw(), this_len);
}

OctetString& OctetString::clear() {
    octets.clear();
    return *this;
}

bool OctetString::empty() const {
    return octets.empty();
}

OctetString& OctetString::assign(std::string const& s, Translation t) {
    octets.clear();
    return concat(s, t);
}

OctetString& OctetString::assign(size_t n, uint8_t* p) {
    octets.assign(p, p + n);
    return *this;
}

std::string OctetString::skipws(std::string s) {
    size_t o = s.find_first_of("\t\r\n ");
    if (o == std::string::npos)
        return s;
    for (size_t i = o + 1, e = s.size(); i != e; ++i) {
        switch (s[i]) {
            case '\t':
            case '\r':
            case '\n':
            case ' ':
                continue;
            default:
                s[o++] = s[i];
        }
    }
    s.resize(o);
    return s;
}

OctetString& OctetString::concat(OctetString const& other) {
    octets.insert(octets.end(), other.octets.begin(), other.octets.end());
    return *this;
}
OctetString& OctetString::concat(std::string const& s, Translation t) {
    if (t == Untranslated) {
        octets.insert(octets.end(), s.begin(), s.end());
    } else if (t == AsciiBase16) {
        size_t b = octets.size();
        size_t n = s.length();
        octets.resize(b + (n + 1) / 2);
        std::string::const_iterator in = s.begin(), end = s.end();
        auto                        out = octets.begin() + b;
        if (n & 1)
            *out++ = from_ascii_hex(*in++);
        while (in < end) {
            uint8_t o = from_ascii_hex(*in++) << 4;
            o |= from_ascii_hex(*in++);
            *out++ = o;
        }
    }
    return *this;
}
OctetString& OctetString::concat(size_t octet_count, uint8_t const* octets) {
    this->octets.insert(this->octets.end(), octets, octets + octet_count);
    return *this;
}
OctetString& OctetString::concat(uint8_t octet) {
    octets.push_back(octet);
    return *this;
}

bool OctetString::equals(const OctetString& other) const {
    return (translate() == other.translate());
}

void OctetString::throw_not_ascii_hex() {
    throw std::invalid_argument("Character not in [0-9A-Fa-f] when attempting translation.");
}
uint8_t OctetString::from_ascii_hex(char c) {
    return c >= '0' && c <= '9'   ? (c - '0')
           : c >= 'a' && c <= 'f' ? (10 + c - 'a')
           : c >= 'A' && c <= 'F' ? (10 + c - 'A')
                                  : (throw_not_ascii_hex(), 15);
}

uint8_t const* OctetString::raw() const {
    if (octets.empty())
        return nullptr;
    return &octets.at(0);
}
uint8_t* OctetString::raw() {
    if (octets.empty())
        return nullptr;
    return &octets.at(0);
}
size_t OctetString::size() const {
    return octets.size();
}
void OctetString::reserve(size_t new_size) {
    octets.reserve(new_size);
};

void OctetString::swap(OctetString& other) {
    octets.swap(other.octets);
}

bool OctetString::to_c(uint8_t** data, size_t* len) const {
    if (!octets.size()) {
        *data = nullptr;
        *len  = 0;
        return true;
    }
    auto* d = (uint8_t*)malloc(octets.size());
    if (!d) {
        return false;
    }
    memcpy(d, raw(), size());
    *data = d;
    *len  = size();
    return true;
}