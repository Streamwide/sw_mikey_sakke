#if 0
ROOT=$(dirname $0)/../../../
${CROSS_PREFIX}g++ -D TEST_BIGINT_SSL $(sh $ROOT/build/test-flags.sh $0) $@
exit $?
#endif

#include <util/bigint-ssl.h>
#if !BIGINT_SINGLE_THREAD
#include <pthread.h>
#endif

#if TEST_BIGINT_SSL
#include <iostream>
#define TRACE(x) std::cerr << x << "\n"
#else
#define TRACE(x)
#endif

#if !BIGINT_SINGLE_THREAD
static pthread_key_t  ssl_ctx_key;
static pthread_once_t ssl_ctx_key_once = PTHREAD_ONCE_INIT;
static void           free_thread_specific_ctx(bigint_ssl_scratch* scratch) {
              delete scratch;
}
static void ssl_ctx_make_key() {
    pthread_key_create(&ssl_ctx_key, (void (*)(void*))free_thread_specific_ctx);
}
#endif

bigint_ssl_scratch& bigint_ssl_scratch::get() {
#if BIGINT_SINGLE_THREAD
    static bigint_ssl_scratch s;
    return s;
#else
    pthread_once(&ssl_ctx_key_once, ssl_ctx_make_key);
    if (void* p = pthread_getspecific(ssl_ctx_key))
        return *reinterpret_cast<bigint_ssl_scratch*>(p);

    auto* scratch = new bigint_ssl_scratch;
    pthread_setspecific(ssl_ctx_key, scratch);
    return *scratch;
#endif
}

bigint_ssl_scratch::bigint_ssl_scratch(): ctx(BN_CTX_new()) {
    TRACE("Create TSS context");
}
bigint_ssl_scratch::~bigint_ssl_scratch() {
    BN_CTX_free(ctx);
    TRACE("Free TSS context");
}

#ifndef OPENSSL_ONLY
bigint& to_bigint(bigint& out, BIGNUM const* in) {
    // TODO : this looks deprecated. Find out what it was used for and if there's a new/better way to do it
    //  bn_check_top(in);

    // Optimistically hope that component word size is
    // compatible between OpenSSL and GMP ...
    /// TODO : Find an equivalent way of doing this with openssl 1.1.1
    // if ((sizeof(BN_ULONG) * 8 == GMP_NUMB_BITS) && (BN_BITS2 == GMP_NUMB_BITS))
    // {
    //    mpz_ptr mpz = out.get_mpz_t();

    //    if (!_mpz_realloc(mpz, in->top))
    //       throw std::runtime_error("Could not reallocate mpz to hold given BIGNUM.");

    //    std::memcpy(mpz->_mp_d, in->d, in->top * sizeof(BN_ULONG));
    //    mpz->_mp_size = in->top;
    //    if (BN_is_negative(in))
    //       mpz->_mp_size = -mpz->_mp_size;

    //    return out;
    // }

    TRACE("Warning: using slow octet conversion for BIGNUM -> mpz");

    // ... if word sizes differ go via octet representation (slower)
    //
    uint8_t* octets = (uint8_t*)calloc(1, BN_num_bytes(in));
    if (octets) {
        BN_bn2bin(in, octets);
        mpz_import(out.get_mpz_t(), sizeof octets, 1, 1, 1, 0, octets);
        free(octets);
    }

    // XXX: erase 'octets' securely?  Maybe pass user param.
    return out;
}

BIGNUM* to_BIGNUM(BIGNUM* out, bigint const& in) {
    // Optimistically hope that component word size is
    // compatible between OpenSSL and GMP ...
    /// TODO : Find an equivalent way of doing this with openssl 1.1.1
    // if ((sizeof(BN_ULONG) * 8 == GMP_NUMB_BITS) && (BN_BITS2 == GMP_NUMB_BITS))
    // {
    //    mpz_srcptr mpz = in.get_mpz_t();

    //    bool neg;
    //    int size = mpz->_mp_size;
    //    if (size < 0)
    //    {
    //       neg = true;
    //       size = -size;
    //    }
    //    else
    //       neg = false;

    //    BN_zero(out); // may speed up expand
    //    if (bn_expand2(out, size) == 0)
    //       throw std::runtime_error("Could not expand BIGNUM to hold given mpz.");

    //    out->top = size;
    //    std::memcpy(out->d, mpz->_mp_d, size * sizeof(BN_ULONG));
    //    bn_correct_top(out);
    //    out->neg = neg;
    //    return out;
    // }

    TRACE("Warning: using slow octet conversion for mpz -> BIGNUM");

    // ... if word sizes differ go via octet representation (slower)
    //
    size_t  octet_count = (bits(in) + 7) >> 3;
    uint8_t* octets = (uint8_t*)calloc(1, octet_count);
    if (octets) {
        mpz_export(octets, nullptr, 1, 1, 1, 0, in.get_mpz_t());
        BN_bin2bn(octets, octet_count, out);
        free(octets);
    }

    // XXX: erase 'octets' securely?  Maybe pass user param.
    return out;
}
#endif