#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/wire/types.hpp>
#include <yanterm-ssh/crypto/provider.hpp>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>

#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <span>

namespace yanterm::ssh::crypto {

// Shared OpenSSL primitives and helpers used by both openssl3.hpp and
// openssl11.hpp. Everything in this header must compile cleanly on OpenSSL
// 1.1.1+ AND without deprecation warnings on OpenSSL 3.0+.

namespace detail {

[[nodiscard]] inline const EVP_MD* evp_md(hash_id id) noexcept {
    switch (id) {
    case hash_id::sha1:   return EVP_sha1();
    case hash_id::sha256: return EVP_sha256();
    case hash_id::sha384: return EVP_sha384();
    case hash_id::sha512: return EVP_sha512();
    case hash_id::sm3:    return EVP_sm3();
    }
    return nullptr;
}

// EVP_MD_CTX plus the digest type needed to re-initialise after Final.
// Cache md at create time — do not query the context's md after Final.
struct openssl_hash {
    EVP_MD_CTX* ctx = nullptr;
    const EVP_MD* md = nullptr;
};

[[nodiscard]] inline const EVP_CIPHER* evp_stream_cipher(cipher_id id) noexcept {
    switch (id) {
    case cipher_id::aes128_ctr: return EVP_aes_128_ctr();
    case cipher_id::aes192_ctr: return EVP_aes_192_ctr();
    case cipher_id::aes256_ctr: return EVP_aes_256_ctr();
    case cipher_id::chacha20:   return EVP_chacha20();
    case cipher_id::sm4_ctr:    return EVP_sm4_ctr();
    case cipher_id::aes128_cbc:
    case cipher_id::aes192_cbc:
    case cipher_id::aes256_cbc:
    case cipher_id::sm4_cbc:
    case cipher_id::aes128_gcm:
    case cipher_id::aes256_gcm: return nullptr;
    }
    return nullptr;
}

[[nodiscard]] inline const EVP_CIPHER* evp_aead_cipher(cipher_id id) noexcept {
    switch (id) {
    case cipher_id::aes128_gcm: return EVP_aes_128_gcm();
    case cipher_id::aes256_gcm: return EVP_aes_256_gcm();
    default: return nullptr;
    }
}

[[nodiscard]] inline const EVP_CIPHER* evp_cbc_cipher(cipher_id id) noexcept {
    switch (id) {
    case cipher_id::aes128_cbc: return EVP_aes_128_cbc();
    case cipher_id::aes192_cbc: return EVP_aes_192_cbc();
    case cipher_id::aes256_cbc: return EVP_aes_256_cbc();
    case cipher_id::sm4_cbc:    return EVP_sm4_cbc();
    default: return nullptr;
    }
}

// An AEAD context keeps the key so begin can re-initialise per packet with a
// fresh IV without re-deriving the key schedule.
struct openssl_aead {
    EVP_CIPHER_CTX* ctx = nullptr;
    bool encrypt = false;
};

struct openssl_cipher {
    EVP_CIPHER_CTX* ctx = nullptr;
    bool encrypt = false;
    cipher_id id{};
};


[[nodiscard]] inline int ec_curve_nid(kex_id id) noexcept {
    switch (id) {
    case kex_id::ecdh_nistp256: return NID_X9_62_prime256v1;
    case kex_id::ecdh_nistp384: return NID_secp384r1;
    case kex_id::ecdh_nistp521: return NID_secp521r1;
    case kex_id::ecdh_sm2:
    case kex_id::sm2_kap:
    case kex_id::sm2_kap_server: return NID_sm2;
    default: return NID_undef;
    }
}

[[nodiscard]] inline const char* ec_kex_group_name(kex_id id) noexcept {
    switch (id) {
    case kex_id::ecdh_nistp256: return "prime256v1";
    case kex_id::ecdh_nistp384: return "secp384r1";
    case kex_id::ecdh_nistp521: return "secp521r1";
    case kex_id::ecdh_sm2:
    case kex_id::sm2_kap:
    case kex_id::sm2_kap_server: return "SM2";
    default: return nullptr;
    }
}

// RFC 3526 MODP groups, which is what SSH uses. These are NOT the RFC 7919
// ffdhe groups.
[[nodiscard]] inline const char* dh_kex_group_name(kex_id id) noexcept {
    switch (id) {
    case kex_id::dh_group14: return "modp_2048";
    case kex_id::dh_group16: return "modp_4096";
    case kex_id::dh_group18: return "modp_8192";
    default: return nullptr;
    }
}

// RFC 5656 section 6.2.1 ties the digest to the curve.
[[nodiscard]] inline const EVP_MD* ecdsa_md(sig_id id) noexcept {
    switch (id) {
    case sig_id::ecdsa_nistp256: return EVP_sha256();
    case sig_id::ecdsa_nistp384: return EVP_sha384();
    case sig_id::ecdsa_nistp521: return EVP_sha512();
    case sig_id::sm2_ecdsa:      return EVP_sm3();
    default: return nullptr;
    }
}

[[nodiscard]] inline const char* ec_sig_group_name(sig_id id) noexcept {
    switch (id) {
    case sig_id::ecdsa_nistp256: return "prime256v1";
    case sig_id::ecdsa_nistp384: return "secp384r1";
    case sig_id::ecdsa_nistp521: return "secp521r1";
    case sig_id::sm2_za:
    case sig_id::sm2_ecdsa:      return "SM2";
    default: return nullptr;
    }
}

[[nodiscard]] inline int ec_sig_curve_nid(sig_id id) noexcept {
    switch (id) {
    case sig_id::ecdsa_nistp256: return NID_X9_62_prime256v1;
    case sig_id::ecdsa_nistp384: return NID_secp384r1;
    case sig_id::ecdsa_nistp521: return NID_secp521r1;
    case sig_id::sm2_za:
    case sig_id::sm2_ecdsa:      return NID_sm2;
    default: return NID_undef;
    }
}

[[nodiscard]] inline const char* ec_sig_keytype(sig_id id) noexcept {
    return id == sig_id::sm2_za ? "SM2" : "EC";
}

[[nodiscard]] inline const EVP_MD* rsa_md(sig_id id) noexcept {
    switch (id) {
    case sig_id::rsa_pkcs1_sha1:   return EVP_sha1();
    case sig_id::rsa_pkcs1_sha256: return EVP_sha256();
    case sig_id::rsa_pkcs1_sha512: return EVP_sha512();
    default: return nullptr;
    }
}

struct openssl_signing_key {
    sig_id algorithm{};
    EVP_PKEY* pkey = nullptr;
};

[[nodiscard]] inline bool append_bytes(std::byte* storage, std::size_t cap, std::size_t& used,
                                       const unsigned char* src, std::size_t n,
                                       std::span<const std::byte>& dest) noexcept {
    if (n != 0 && src == nullptr) return false;
    if (used > cap || n > cap - used) return false;
    if (n != 0) std::memcpy(storage + used, src, n);
    dest = {storage + used, n};
    used += n;
    return true;
}

[[nodiscard]] inline bool append_bn(std::byte* storage, std::size_t cap, std::size_t& used,
                                    const BIGNUM* bn, std::span<const std::byte>& dest) noexcept {
    if (bn == nullptr) return false;
    const int n = BN_num_bytes(bn);
    if (n < 0) return false;
    if (used > cap || static_cast<std::size_t>(n) > cap - used) return false;
    if (n > 0) {
        BN_bn2bin(bn, reinterpret_cast<unsigned char*>(storage + used));
    }
    dest = {storage + used, static_cast<std::size_t>(n)};
    used += static_cast<std::size_t>(n);
    return true;
}

[[nodiscard]] inline BIGNUM* bn_from_span(std::span<const std::byte> s) noexcept {
    if (s.empty()) return nullptr;
    return BN_bin2bn(reinterpret_cast<const unsigned char*>(s.data()),
                     static_cast<int>(s.size()), nullptr);
}

// BN_FLG_SECURE makes BN_clear_free and OSSL_PARAM_BLD_push_BN wipe this copy.
// Without a secure heap, OpenSSL still allocates normally and cleanses on free.
[[nodiscard]] inline BIGNUM* bn_secret_from_span(std::span<const std::byte> s) noexcept {
    if (s.empty()) return nullptr;
    BIGNUM* bn = BN_secure_new();
    if (bn == nullptr) return nullptr;
    if (BN_bin2bn(reinterpret_cast<const unsigned char*>(s.data()),
                  static_cast<int>(s.size()), bn) == nullptr) {
        BN_clear_free(bn);
        return nullptr;
    }
    return bn;
}

// Left-pads a BIGNUM into a fixed-width big-endian buffer, which is what
// the DH public value and shared secret need.
[[nodiscard]] inline bool bn_to_fixed(const BIGNUM* bn, std::byte* out,
                                      std::size_t width) noexcept {
    return BN_bn2binpad(bn, reinterpret_cast<unsigned char*>(out),
                        static_cast<int>(width)) == static_cast<int>(width);
}

[[nodiscard]] inline void* wrap_signing_key(sig_id id, EVP_PKEY* pkey) noexcept {
    if (pkey == nullptr) return nullptr;
    auto* sk = new (std::nothrow) openssl_signing_key{};
    if (sk == nullptr) {
        EVP_PKEY_free(pkey);
        return nullptr;
    }
    sk->algorithm = id;
    sk->pkey = pkey;
    return sk;
}

// Computes RSA CRT exponents dmp1 = d mod (p - 1) and dmq1 = d mod (q - 1).
// On true, caller owns *dmp1_out and *dmq1_out.
[[nodiscard]] inline bool rsa_derive_crt_exponents(const BIGNUM* d, const BIGNUM* p,
                                                   const BIGNUM* q, BIGNUM** dmp1_out,
                                                   BIGNUM** dmq1_out) noexcept {
    if (d == nullptr || p == nullptr || q == nullptr || dmp1_out == nullptr
        || dmq1_out == nullptr) {
        return false;
    }
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* p1 = BN_dup(p);
    BIGNUM* q1 = BN_dup(q);
    BIGNUM* dmp1 = BN_secure_new();
    BIGNUM* dmq1 = BN_secure_new();
    bool ok = false;
    if (ctx != nullptr && p1 != nullptr && q1 != nullptr && dmp1 != nullptr && dmq1 != nullptr
        && BN_sub_word(p1, 1) == 1 && BN_sub_word(q1, 1) == 1
        && BN_mod(dmp1, d, p1, ctx) == 1 && BN_mod(dmq1, d, q1, ctx) == 1) {
        *dmp1_out = dmp1;
        *dmq1_out = dmq1;
        dmp1 = nullptr;
        dmq1 = nullptr;
        ok = true;
    }
    // p-1 and q-1 expose the factors. dmp1/dmq1 are the CRT exponents.
    BN_clear_free(dmq1);
    BN_clear_free(dmp1);
    BN_clear_free(q1);
    BN_clear_free(p1);
    BN_CTX_free(ctx);
    return ok;
}

// RFC 4253 §8: require 1 < f < p - 1 for finite-field DH peer public values.
[[nodiscard]] inline bool dh_peer_in_range(const BIGNUM* f, const BIGNUM* p) noexcept {
    if (f == nullptr || p == nullptr) return false;
    BIGNUM* one = BN_new();
    BIGNUM* pm1 = BN_dup(p);
    const bool ok = one != nullptr && pm1 != nullptr
                    && BN_set_word(one, 1) == 1
                    && BN_sub_word(pm1, 1) == 1
                    && BN_cmp(f, one) > 0
                    && BN_cmp(f, pm1) < 0;
    BN_free(pm1);
    BN_free(one);
    return ok;
}

[[nodiscard]] inline bool ecdsa_rs_to_der(std::span<const std::byte> r,
                                          std::span<const std::byte> s,
                                          unsigned char* der, std::size_t cap,
                                          std::size_t* der_len) noexcept {
    if (r.empty() || s.empty() || der == nullptr || der_len == nullptr) return false;
    BIGNUM* rb = BN_bin2bn(reinterpret_cast<const unsigned char*>(r.data()),
                           static_cast<int>(r.size()), nullptr);
    BIGNUM* sb = BN_bin2bn(reinterpret_cast<const unsigned char*>(s.data()),
                           static_cast<int>(s.size()), nullptr);
    ECDSA_SIG* esig = ECDSA_SIG_new();
    bool ok = false;
    if (rb != nullptr && sb != nullptr && esig != nullptr && ECDSA_SIG_set0(esig, rb, sb) == 1) {
        rb = nullptr;
        sb = nullptr;
        const int n = i2d_ECDSA_SIG(esig, nullptr);
        if (n > 0 && static_cast<std::size_t>(n) <= cap) {
            unsigned char* p = der;
            if (i2d_ECDSA_SIG(esig, &p) == n) {
                *der_len = static_cast<std::size_t>(n);
                ok = true;
            }
        }
    }
    ECDSA_SIG_free(esig);
    BN_free(rb);
    BN_free(sb);
    return ok;
}

[[nodiscard]] inline bool ecdsa_sig_to_mpint(const ECDSA_SIG* esig, std::byte* out,
                                             std::size_t cap, std::size_t* out_len) noexcept {
    if (esig == nullptr || out == nullptr || out_len == nullptr) return false;
    const BIGNUM* r = nullptr;
    const BIGNUM* s = nullptr;
    ECDSA_SIG_get0(esig, &r, &s);
    unsigned char rraw[66];
    unsigned char sraw[66];
    const int rbytes = (r != nullptr) ? BN_num_bytes(r) : -1;
    const int sbytes = (s != nullptr) ? BN_num_bytes(s) : -1;
    if (rbytes <= 0 || rbytes > static_cast<int>(sizeof(rraw))
        || sbytes <= 0 || sbytes > static_cast<int>(sizeof(sraw))) {
        return false;
    }
    const int rn = BN_bn2bin(r, rraw);
    const int sn = BN_bn2bin(s, sraw);
    if (rn <= 0 || sn <= 0) return false;
    wire::writer w;
    w.write_mpint(std::span<const std::byte>{reinterpret_cast<const std::byte*>(rraw),
                                             static_cast<std::size_t>(rn)});
    w.write_mpint(std::span<const std::byte>{reinterpret_cast<const std::byte*>(sraw),
                                             static_cast<std::size_t>(sn)});
    if (w.size() > cap) return false;
    std::memcpy(out, w.data().data(), w.size());
    *out_len = w.size();
    return true;
}

[[nodiscard]] inline bool ecdsa_der_to_mpint(const unsigned char* der, std::size_t der_len,
                                             std::byte* out, std::size_t cap,
                                             std::size_t* out_len) noexcept {
    if (der == nullptr || der_len == 0 || out == nullptr || out_len == nullptr) return false;
    const unsigned char* p = der;
    ECDSA_SIG* esig = d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der_len));
    if (esig == nullptr) return false;
    const bool ok = ecdsa_sig_to_mpint(esig, out, cap, out_len);
    ECDSA_SIG_free(esig);
    return ok;
}

inline constexpr std::uint8_t sm2_kap_id[16] = {
    1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
};

inline constexpr char sm2_sign_id[] = "1234567812345678";
inline constexpr std::size_t sm2_sign_id_len = 16;
inline constexpr std::size_t sm2_field_bytes = 32;

[[nodiscard]] inline bool sm2_z_digest(unsigned char out[32], const unsigned char* id,
                                       std::size_t id_len, const EC_GROUP* group,
                                       const EC_POINT* pub) noexcept {
    if (out == nullptr || group == nullptr || pub == nullptr || (id_len != 0 && id == nullptr)) {
        return false;
    }
    if (id_len >= (65535u / 8u)) return false;

    BN_CTX* ctx = BN_CTX_new();
    EVP_MD_CTX* hash = EVP_MD_CTX_new();
    unsigned char* buf = nullptr;
    BIGNUM* p = nullptr;
    BIGNUM* a = nullptr;
    BIGNUM* b = nullptr;
    BIGNUM* xG = nullptr;
    BIGNUM* yG = nullptr;
    BIGNUM* xA = nullptr;
    BIGNUM* yA = nullptr;
    int p_bytes = 0;
    int ok = 0;
    if (ctx == nullptr || hash == nullptr) goto done;
    BN_CTX_start(ctx);
    p = BN_CTX_get(ctx);
    a = BN_CTX_get(ctx);
    b = BN_CTX_get(ctx);
    xG = BN_CTX_get(ctx);
    yG = BN_CTX_get(ctx);
    xA = BN_CTX_get(ctx);
    yA = BN_CTX_get(ctx);
    if (yA == nullptr || EVP_DigestInit_ex(hash, EVP_sm3(), nullptr) != 1) goto done;

    {
        const auto entl = static_cast<std::uint16_t>(8u * id_len);
        unsigned char be[2]{static_cast<unsigned char>(entl >> 8),
                            static_cast<unsigned char>(entl & 0xffu)};
        if (EVP_DigestUpdate(hash, be, 2) != 1) goto done;
        if (id_len != 0 && EVP_DigestUpdate(hash, id, id_len) != 1) goto done;
    }

    if (EC_GROUP_get_curve(group, p, a, b, ctx) != 1) goto done;
    p_bytes = BN_num_bytes(p);
    if (p_bytes <= 0) goto done;
    buf = static_cast<unsigned char*>(OPENSSL_zalloc(static_cast<std::size_t>(p_bytes)));
    if (buf == nullptr) goto done;

    if (BN_bn2binpad(a, buf, p_bytes) < 0
        || EVP_DigestUpdate(hash, buf, static_cast<std::size_t>(p_bytes)) != 1
        || BN_bn2binpad(b, buf, p_bytes) < 0
        || EVP_DigestUpdate(hash, buf, static_cast<std::size_t>(p_bytes)) != 1
        || EC_POINT_get_affine_coordinates(group, EC_GROUP_get0_generator(group), xG, yG, ctx) != 1
        || BN_bn2binpad(xG, buf, p_bytes) < 0
        || EVP_DigestUpdate(hash, buf, static_cast<std::size_t>(p_bytes)) != 1
        || BN_bn2binpad(yG, buf, p_bytes) < 0
        || EVP_DigestUpdate(hash, buf, static_cast<std::size_t>(p_bytes)) != 1
        || EC_POINT_get_affine_coordinates(group, pub, xA, yA, ctx) != 1
        || BN_bn2binpad(xA, buf, p_bytes) < 0
        || EVP_DigestUpdate(hash, buf, static_cast<std::size_t>(p_bytes)) != 1
        || BN_bn2binpad(yA, buf, p_bytes) < 0
        || EVP_DigestUpdate(hash, buf, static_cast<std::size_t>(p_bytes)) != 1
        || EVP_DigestFinal_ex(hash, out, nullptr) != 1) {
        goto done;
    }
    ok = 1;
done:
    OPENSSL_free(buf);
    if (ctx != nullptr) BN_CTX_end(ctx);
    BN_CTX_free(ctx);
    EVP_MD_CTX_free(hash);
    return ok == 1;
}

[[nodiscard]] inline bool sm2_kdf_gmt0003(unsigned char* out, std::size_t outlen,
                                          const unsigned char* z, std::size_t zlen) noexcept {
    if (out == nullptr || (outlen != 0 && z == nullptr && zlen != 0)) return false;
    EVP_MD_CTX* m = EVP_MD_CTX_new();
    if (m == nullptr) return false;
    unsigned char dgst[32];
    unsigned char ctr[4];
    unsigned int counter = 1;
    int ok = 0;
    for (;;) {
        ctr[0] = static_cast<unsigned char>(counter >> 24);
        ctr[1] = static_cast<unsigned char>(counter >> 16);
        ctr[2] = static_cast<unsigned char>(counter >> 8);
        ctr[3] = static_cast<unsigned char>(counter);
        if (EVP_DigestInit_ex(m, EVP_sm3(), nullptr) != 1
            || EVP_DigestUpdate(m, z, zlen) != 1
            || EVP_DigestUpdate(m, ctr, 4) != 1
            || EVP_DigestFinal_ex(m, dgst, nullptr) != 1) {
            break;
        }
        if (outlen > 32) {
            std::memcpy(out, dgst, 32);
            out += 32;
            outlen -= 32;
            ++counter;
            continue;
        }
        std::memcpy(out, dgst, outlen);
        ok = 1;
        break;
    }
    OPENSSL_cleanse(dgst, sizeof(dgst));
    EVP_MD_CTX_free(m);
    return ok == 1;
}

// Core GM/T 0003 KAP point arithmetic shared by OpenSSL 1.1.1 and 3.x.
// Identity key = ephemeral key. is_server: client=0, server=1.
[[nodiscard]] inline bool sm2_ssh_kap_points(unsigned char* out, std::size_t outlen, int is_server,
                                             const EC_GROUP* group, const BIGNUM* d,
                                             const EC_POINT* rs, const EC_POINT* rp) noexcept {
    if (out == nullptr || outlen == 0 || group == nullptr || d == nullptr || rs == nullptr
        || rp == nullptr) {
        return false;
    }

    BN_CTX* ctx = BN_CTX_new();
    EC_POINT* U = EC_POINT_new(group);
    BIGNUM* xs = BN_new();
    BIGNUM* xp = BN_new();
    BIGNUM* h = BN_new();
    BIGNUM* t = BN_new();
    BIGNUM* two_w = BN_new();
    BIGNUM* order = BN_new();
    unsigned char* buf = nullptr;
    std::size_t buf_len = 0;
    int ret = 0;

    if (ctx == nullptr || U == nullptr || xs == nullptr || xp == nullptr || h == nullptr
        || t == nullptr || two_w == nullptr || order == nullptr) {
        goto err;
    }
    if (EC_GROUP_get_order(group, order, ctx) != 1 || EC_GROUP_get_cofactor(group, h, ctx) != 1) {
        goto err;
    }
    {
        const int w = (BN_num_bits(order) + 1) / 2 - 1;
        if (BN_lshift(two_w, BN_value_one(), w) != 1) goto err;
    }
    if (EC_POINT_is_on_curve(group, rp, ctx) != 1) goto err;
    if (EC_POINT_get_affine_coordinates(group, rs, xs, nullptr, ctx) != 1) goto err;
    if (EC_POINT_get_affine_coordinates(group, rp, xp, nullptr, ctx) != 1) goto err;
    if (BN_nnmod(xs, xs, two_w, ctx) != 1 || BN_add(xs, xs, two_w) != 1) goto err;
    if (BN_nnmod(xp, xp, two_w, ctx) != 1 || BN_add(xp, xp, two_w) != 1) goto err;
    if (BN_mod_mul(t, xs, d, order, ctx) != 1 || BN_mod_add(t, t, d, order, ctx) != 1) goto err;
    if (BN_mul(t, t, h, ctx) != 1) goto err;
    if (EC_POINT_mul(group, U, nullptr, rp, xp, ctx) != 1) goto err;
    if (EC_POINT_add(group, U, U, rp, ctx) != 1) goto err;
    if (EC_POINT_mul(group, U, nullptr, U, t, ctx) != 1) goto err;
    if (EC_POINT_is_at_infinity(group, U) == 1) goto err;

    {
        const std::size_t elem =
            static_cast<std::size_t>((EC_GROUP_get_degree(group) + 7) / 8);
        const std::size_t buflen = elem * 2 + 32 * 2 + 1;
        buf_len = buflen + 8;
        buf = static_cast<unsigned char*>(OPENSSL_zalloc(buf_len));
        if (buf == nullptr) goto err;
        std::size_t idx = EC_POINT_point2oct(group, U, POINT_CONVERSION_UNCOMPRESSED, buf, buflen,
                                             ctx);
        if (idx == 0) goto err;
        if (!is_server) {
            if (!sm2_z_digest(buf + idx, sm2_kap_id, sizeof(sm2_kap_id), group, rs)) goto err;
            idx += 32;
        }
        if (!sm2_z_digest(buf + idx, sm2_kap_id, sizeof(sm2_kap_id), group, rp)) goto err;
        idx += 32;
        if (is_server) {
            if (!sm2_z_digest(buf + idx, sm2_kap_id, sizeof(sm2_kap_id), group, rs)) goto err;
            idx += 32;
        }
        if (!sm2_kdf_gmt0003(out, outlen, buf + 1, idx - 1)) {
            OPENSSL_cleanse(out, outlen);
            goto err;
        }
    }
    ret = 1;
err:
    OPENSSL_clear_free(buf, buf_len);
    BN_free(xs);
    BN_free(xp);
    BN_free(h);
    BN_clear_free(t);
    BN_free(two_w);
    BN_free(order);
    EC_POINT_clear_free(U);
    BN_CTX_free(ctx);
    return ret == 1;
}

[[nodiscard]] inline bool generate_ed25519(private_key_material* out, std::byte* storage,
                                           std::size_t cap, std::size_t& used) noexcept {
    EVP_PKEY_CTX* c = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    EVP_PKEY* pkey = nullptr;
    bool ok = false;
    if (c != nullptr && EVP_PKEY_keygen_init(c) == 1 && EVP_PKEY_keygen(c, &pkey) == 1) {
        unsigned char seed[32];
        unsigned char pub[32];
        std::size_t slen = 32;
        std::size_t plen = 32;
        if (EVP_PKEY_get_raw_private_key(pkey, seed, &slen) == 1 && slen == 32
            && EVP_PKEY_get_raw_public_key(pkey, pub, &plen) == 1 && plen == 32
            && append_bytes(storage, cap, used, seed, 32, out->seed)
            && append_bytes(storage, cap, used, pub, 32, out->public_key)) {
            ok = true;
        }
        OPENSSL_cleanse(seed, sizeof(seed));
    }
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(pkey);
    return ok;
}

[[nodiscard]] inline void* ed25519_signing_key_new(const private_key_material* key) noexcept {
    if (key == nullptr || key->seed.size() != 32) return nullptr;
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_ED25519, nullptr,
        reinterpret_cast<const unsigned char*>(key->seed.data()), 32);
    return wrap_signing_key(key->algorithm, pkey);
}

[[nodiscard]] inline bool sign_ed25519(EVP_PKEY* pkey, const std::byte* msg, std::size_t msglen,
                                       std::byte* out, std::size_t cap,
                                       std::size_t* out_len) noexcept {
    if (pkey == nullptr || out_len == nullptr || cap < 64) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) return false;
    bool ok = false;
    std::size_t len = cap;
    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) == 1
        && EVP_DigestSign(ctx, reinterpret_cast<unsigned char*>(out), &len,
                          reinterpret_cast<const unsigned char*>(msg), msglen) == 1
        && len == 64) {
        *out_len = len;
        ok = true;
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

[[nodiscard]] inline bool verify_ed25519(std::span<const std::byte> pub, const std::byte* msg,
                                         std::size_t msglen,
                                         std::span<const std::byte> sig) noexcept {
    if (pub.size() != 32 || sig.size() != 64) return false;
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_ED25519, nullptr,
        reinterpret_cast<const unsigned char*>(pub.data()), 32);
    if (pkey == nullptr) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = false;
    if (ctx != nullptr && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
        ok = EVP_DigestVerify(ctx, reinterpret_cast<const unsigned char*>(sig.data()),
                              sig.size(), reinterpret_cast<const unsigned char*>(msg),
                              msglen) == 1;
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

[[nodiscard]] inline bool sign_ecdsa(openssl_signing_key* sk, const std::byte* msg,
                                     std::size_t msglen, std::byte* out, std::size_t cap,
                                     std::size_t* out_len) noexcept {
    const EVP_MD* md = ecdsa_md(sk->algorithm);
    if (md == nullptr || sk->pkey == nullptr) return false;
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if (mctx == nullptr) return false;
    unsigned char der[256];
    std::size_t der_len = sizeof(der);
    bool ok = false;
    if (EVP_DigestSignInit(mctx, nullptr, md, nullptr, sk->pkey) == 1
        && EVP_DigestSign(mctx, der, &der_len,
                          reinterpret_cast<const unsigned char*>(msg), msglen) == 1) {
        ok = ecdsa_der_to_mpint(der, der_len, out, cap, out_len);
    }
    EVP_MD_CTX_free(mctx);
    return ok;
}

[[nodiscard]] inline bool verify_ecdsa(EVP_PKEY* pkey, const EVP_MD* md,
                                       const std::byte* msg, std::size_t msglen,
                                       std::span<const std::byte> r,
                                       std::span<const std::byte> s) noexcept {
    if (pkey == nullptr || md == nullptr) return false;
    unsigned char der[256];
    std::size_t der_len = 0;
    if (!ecdsa_rs_to_der(r, s, der, sizeof(der), &der_len)) return false;
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if (mctx == nullptr) return false;
    const bool ok = EVP_DigestVerifyInit(mctx, nullptr, md, nullptr, pkey) == 1
                    && EVP_DigestVerify(mctx, der, der_len,
                                        reinterpret_cast<const unsigned char*>(msg), msglen) == 1;
    EVP_MD_CTX_free(mctx);
    return ok;
}

[[nodiscard]] inline EVP_PKEY* x25519_keygen() noexcept {
    EVP_PKEY_CTX* c = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    EVP_PKEY* pkey = nullptr;
    if (c == nullptr || EVP_PKEY_keygen_init(c) != 1 || EVP_PKEY_keygen(c, &pkey) != 1) {
        EVP_PKEY_free(pkey);
        pkey = nullptr;
    }
    EVP_PKEY_CTX_free(c);
    return pkey;
}

[[nodiscard]] inline bool x25519_public(EVP_PKEY* pkey, std::byte* out, std::size_t want,
                                        std::size_t* out_len) noexcept {
    if (pkey == nullptr || out_len == nullptr) return false;
    std::size_t len = want;
    if (EVP_PKEY_get_raw_public_key(pkey, reinterpret_cast<unsigned char*>(out), &len) != 1
        || len != want) {
        return false;
    }
    *out_len = want;
    return true;
}

[[nodiscard]] inline bool evp_pkey_derive_shared(EVP_PKEY* self_pkey, EVP_PKEY* peer_key,
                                                 std::byte* out, std::size_t want,
                                                 std::size_t* out_len) noexcept {
    if (self_pkey == nullptr || peer_key == nullptr || out == nullptr || out_len == nullptr) {
        return false;
    }
    EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(self_pkey, nullptr);
    bool ok = false;
    std::size_t len = want;
    if (dctx != nullptr
        && EVP_PKEY_derive_init(dctx) == 1
        && EVP_PKEY_derive_set_peer(dctx, peer_key) == 1
        && EVP_PKEY_derive(dctx, reinterpret_cast<unsigned char*>(out), &len) == 1) {
        if (len == want) {
            *out_len = want;
            ok = true;
        } else {
            OPENSSL_cleanse(out, want);
        }
    }
    EVP_PKEY_CTX_free(dctx);
    return ok;
}

[[nodiscard]] inline bool x25519_agree(EVP_PKEY* self_pkey, const std::byte* peer,
                                       std::size_t peerlen, std::byte* out, std::size_t want,
                                       std::size_t* out_len) noexcept {
    if (self_pkey == nullptr || peer == nullptr || peerlen != 32 || out_len == nullptr) {
        return false;
    }
    EVP_PKEY* peer_key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, nullptr, reinterpret_cast<const unsigned char*>(peer), peerlen);
    if (peer_key == nullptr) return false;
    std::size_t len = 0;
    bool ok = false;
    if (evp_pkey_derive_shared(self_pkey, peer_key, out, want, &len)) {
        // RFC 8731 §3: reject the all-zero shared secret.
        unsigned char zeros[32]{};
        if (CRYPTO_memcmp(out, zeros, 32) != 0) {
            *out_len = want;
            ok = true;
        }
    }
    EVP_PKEY_free(peer_key);
    return ok;
}

[[nodiscard]] inline bool openssl_supports_common(bool sm2_avail, primitive_kind kind,
                                                  std::uint8_t id) noexcept {
    switch (kind) {
    case primitive_kind::hash:
        switch (static_cast<hash_id>(id)) {
        case hash_id::sha1:
        case hash_id::sha256:
        case hash_id::sha384:
        case hash_id::sha512: return true;
        case hash_id::sm3: return sm2_avail;
        }
        return false;
    case primitive_kind::mac:
        switch (static_cast<mac_id>(id)) {
        case mac_id::hmac_sha1:
        case mac_id::hmac_sha256:
        case mac_id::hmac_sha512:
        case mac_id::poly1305: return true;
        case mac_id::hmac_sm3: return sm2_avail;
        }
        return false;
    case primitive_kind::cipher:
        switch (static_cast<cipher_id>(id)) {
        case cipher_id::aes128_ctr:
        case cipher_id::aes192_ctr:
        case cipher_id::aes256_ctr:
        case cipher_id::aes128_cbc:
        case cipher_id::aes192_cbc:
        case cipher_id::aes256_cbc:
        case cipher_id::aes128_gcm:
        case cipher_id::aes256_gcm:
        case cipher_id::chacha20: return true;
        case cipher_id::sm4_ctr:
        case cipher_id::sm4_cbc: return sm2_avail;
        }
        return false;
    case primitive_kind::kex:
        switch (static_cast<kex_id>(id)) {
        case kex_id::curve25519:
        case kex_id::ecdh_nistp256:
        case kex_id::ecdh_nistp384:
        case kex_id::ecdh_nistp521:
        case kex_id::dh_group14:
        case kex_id::dh_group16:
        case kex_id::dh_group18: return true;
        case kex_id::ecdh_sm2:
        case kex_id::sm2_kap:
        case kex_id::sm2_kap_server: return sm2_avail;
        }
        return false;
    case primitive_kind::signature:
        switch (static_cast<sig_id>(id)) {
        case sig_id::ed25519:
        case sig_id::ecdsa_nistp256:
        case sig_id::ecdsa_nistp384:
        case sig_id::ecdsa_nistp521:
        case sig_id::rsa_pkcs1_sha1:
        case sig_id::rsa_pkcs1_sha256:
        case sig_id::rsa_pkcs1_sha512: return true;
        case sig_id::sm2_za:
        case sig_id::sm2_ecdsa: return sm2_avail;
        }
        return false;
    }
    return false;
}

// Members both OpenSSL API generations implement identically; ossl3 and
// ossl1_1 openssl_backend derive from it. Stateless: OpenSSL keeps its own
// global state. The derived types exist so callers own an object whose
// lifetime bounds the provider handle.
struct openssl_backend_base {
    bool random_bytes(std::byte* out, std::size_t len) noexcept {
        return RAND_bytes(reinterpret_cast<unsigned char*>(out),
                          static_cast<int>(len)) == 1;
    }

    bool constant_time_eq(const std::byte* a, const std::byte* b, std::size_t len) noexcept {
        return CRYPTO_memcmp(a, b, len) == 0;
    }

    void* hash_new(hash_id id) noexcept {
        const EVP_MD* md = evp_md(id);
        if (md == nullptr) return nullptr;
        auto* h = new (std::nothrow) openssl_hash{};
        if (h == nullptr) return nullptr;
        h->ctx = EVP_MD_CTX_new();
        h->md = md;
        if (h->ctx == nullptr || EVP_DigestInit_ex(h->ctx, md, nullptr) != 1) {
            if (h->ctx != nullptr) EVP_MD_CTX_free(h->ctx);
            delete h;
            return nullptr;
        }
        return h;
    }

    void hash_free(void* ctx) noexcept {
        auto* h = static_cast<openssl_hash*>(ctx);
        if (h == nullptr) return;
        if (h->ctx != nullptr) EVP_MD_CTX_free(h->ctx);
        delete h;
    }

    void hash_update(void* ctx, const std::byte* in, std::size_t len) noexcept {
        auto* h = static_cast<openssl_hash*>(ctx);
        EVP_DigestUpdate(h->ctx, in, len);
    }

    bool hash_final(void* ctx, std::byte* out) noexcept {
        auto* h = static_cast<openssl_hash*>(ctx);
        unsigned int n = 0;
        if (EVP_DigestFinal_ex(h->ctx, reinterpret_cast<unsigned char*>(out), &n) != 1) {
            return false;
        }
        // EVP_DigestFinal_ex leaves the context unusable; re-init with the
        // cached md so the handle can hash again.
        return EVP_DigestInit_ex(h->ctx, h->md, nullptr) == 1;
    }

    void* cipher_new(cipher_id id, const std::byte* key, std::size_t keylen,
                     bool encrypt) noexcept {
        const EVP_CIPHER* stream = evp_stream_cipher(id);
        const EVP_CIPHER* cbc_evp = evp_cbc_cipher(id);
        const EVP_CIPHER* c = stream != nullptr ? stream : cbc_evp;
        if (c == nullptr || keylen != cipher_key_size(id)) return nullptr;
        auto* st = new (std::nothrow) openssl_cipher{};
        if (st == nullptr) return nullptr;
        st->ctx = EVP_CIPHER_CTX_new();
        st->encrypt = encrypt;
        st->id = id;
        const auto* k = reinterpret_cast<const unsigned char*>(key);
        const bool cbc = cbc_evp != nullptr;
        const int ok = (cbc ? (encrypt ? EVP_EncryptInit_ex(st->ctx, c, nullptr, k, nullptr)
                                       : EVP_DecryptInit_ex(st->ctx, c, nullptr, k, nullptr))
                            : EVP_EncryptInit_ex(st->ctx, c, nullptr, k, nullptr));
        if (st->ctx == nullptr || ok != 1 || EVP_CIPHER_CTX_set_padding(st->ctx, 0) != 1) {
            if (st->ctx != nullptr) EVP_CIPHER_CTX_free(st->ctx);
            delete st;
            return nullptr;
        }
        return st;
    }

    void cipher_free(void* ctx) noexcept {
        auto* st = static_cast<openssl_cipher*>(ctx);
        if (st == nullptr) return;
        if (st->ctx != nullptr) EVP_CIPHER_CTX_free(st->ctx);
        delete st;
    }

    bool cipher_set_iv(void* ctx, const std::byte* iv, std::size_t ivlen) noexcept {
        auto* st = static_cast<openssl_cipher*>(ctx);
        if (st == nullptr || st->ctx == nullptr || ivlen != 16) return false;
        const auto* ivp = reinterpret_cast<const unsigned char*>(iv);
        const bool cbc = evp_cbc_cipher(st->id) != nullptr;
        if (cbc && !st->encrypt) {
            return EVP_DecryptInit_ex(st->ctx, nullptr, nullptr, nullptr, ivp) == 1;
        }
        return EVP_EncryptInit_ex(st->ctx, nullptr, nullptr, nullptr, ivp) == 1;
    }

    bool cipher_update(void* ctx, const std::byte* in, std::byte* out,
                       std::size_t len) noexcept {
        auto* st = static_cast<openssl_cipher*>(ctx);
        if (st == nullptr || st->ctx == nullptr) return false;
        if (len == 0) return true;
        if (len > static_cast<std::size_t>(INT_MAX)) return false;
        if (evp_cbc_cipher(st->id) != nullptr && len % 16u != 0) return false;
        int n = 0;
        auto* outp = reinterpret_cast<unsigned char*>(out);
        const auto* inp = reinterpret_cast<const unsigned char*>(in);
        const bool cbc_dec = evp_cbc_cipher(st->id) != nullptr && !st->encrypt;
        const int ok = cbc_dec
                           ? EVP_DecryptUpdate(st->ctx, outp, &n, inp, static_cast<int>(len))
                           : EVP_EncryptUpdate(st->ctx, outp, &n, inp, static_cast<int>(len));
        return ok == 1 && static_cast<std::size_t>(n) == len;
    }

    void aead_free(void* ctx) noexcept {
        auto* a = static_cast<openssl_aead*>(ctx);
        if (a == nullptr) return;
        if (a->ctx != nullptr) EVP_CIPHER_CTX_free(a->ctx);
        delete a;
    }

    bool aead_begin(void* ctx, const std::byte* iv, std::size_t ivlen,
                    const std::byte* aad, std::size_t aadlen) noexcept {
        auto* a = static_cast<openssl_aead*>(ctx);
        if (a == nullptr || a->ctx == nullptr || ivlen != 12) return false;
        if (aadlen > static_cast<std::size_t>(INT_MAX)) return false;
        const auto* ivp = reinterpret_cast<const unsigned char*>(iv);
        if (a->encrypt) {
            if (EVP_EncryptInit_ex(a->ctx, nullptr, nullptr, nullptr, ivp) != 1) return false;
        } else if (EVP_DecryptInit_ex(a->ctx, nullptr, nullptr, nullptr, ivp) != 1) {
            return false;
        }
        if (aadlen == 0) return true;
        int aad_outl = 0;
        const auto* aadp = reinterpret_cast<const unsigned char*>(aad);
        const int aadn = static_cast<int>(aadlen);
        return (a->encrypt ? EVP_EncryptUpdate(a->ctx, nullptr, &aad_outl, aadp, aadn)
                           : EVP_DecryptUpdate(a->ctx, nullptr, &aad_outl, aadp, aadn)) == 1;
    }

    bool aead_update(void* ctx, const std::byte* in, std::byte* out,
                     std::size_t len) noexcept {
        auto* a = static_cast<openssl_aead*>(ctx);
        if (a == nullptr || a->ctx == nullptr) return false;
        if (len == 0) return true;
        if (len > static_cast<std::size_t>(INT_MAX)) return false;
        int n = 0;
        auto* outp = reinterpret_cast<unsigned char*>(out);
        const auto* inp = reinterpret_cast<const unsigned char*>(in);
        const int ok = a->encrypt
                           ? EVP_EncryptUpdate(a->ctx, outp, &n, inp, static_cast<int>(len))
                           : EVP_DecryptUpdate(a->ctx, outp, &n, inp, static_cast<int>(len));
        return ok == 1 && static_cast<std::size_t>(n) == len;
    }

    void signing_key_free(void* handle) noexcept {
        auto* sk = static_cast<openssl_signing_key*>(handle);
        if (sk == nullptr) return;
        if (sk->pkey != nullptr) EVP_PKEY_free(sk->pkey);
        delete sk;
    }
};

}  // namespace detail
}  // namespace yanterm::ssh::crypto
