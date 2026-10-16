#pragma once

#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "crypto/detail/ossl3.hpp requires OpenSSL 3.0 or newer. Include <yanterm-ssh/crypto/openssl.hpp>."
#endif

#include <yanterm-ssh/crypto/detail/ossl_common.hpp>

#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/params.h>

namespace yanterm::ssh::crypto::detail::ossl3 {

using detail::openssl_signing_key;
using detail::sm2_field_bytes;
using detail::sm2_kap_id;
using detail::sm2_kdf_gmt0003;
using detail::sm2_sign_id;
using detail::sm2_sign_id_len;
using detail::sm2_z_digest;

// EVP_MAC_CTX plus the key needed to re-initialise after EVP_MAC_final,
// so that hmac_ctx can be reused across packets without reallocating.
struct openssl_hmac {
    EVP_MAC_CTX* ctx = nullptr;
    unsigned char key[128]{};
    std::size_t key_len = 0;
};

[[nodiscard]] inline void* hmac_new(hash_id id, const std::byte* key,
                                    std::size_t keylen) noexcept {
    const EVP_MD* md = evp_md(id);
    if (md == nullptr || keylen > sizeof(openssl_hmac::key)) return nullptr;
    const char* md_name = EVP_MD_get0_name(md);
    if (md_name == nullptr) return nullptr;
    auto* h = new (std::nothrow) openssl_hmac{};
    if (h == nullptr) return nullptr;
    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (mac != nullptr) {
        h->ctx = EVP_MAC_CTX_new(mac);
        EVP_MAC_free(mac);
    }
    h->key_len = keylen;
    if (keylen != 0) std::memcpy(h->key, key, keylen);
    OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char*>(md_name), 0),
        OSSL_PARAM_construct_end(),
    };
    if (h->ctx == nullptr || EVP_MAC_init(h->ctx, h->key, keylen, params) != 1) {
        if (h->ctx != nullptr) EVP_MAC_CTX_free(h->ctx);
        OPENSSL_cleanse(h->key, sizeof(h->key));
        delete h;
        return nullptr;
    }
    return h;
}

inline void hmac_free(void* ctx) noexcept {
    auto* h = static_cast<openssl_hmac*>(ctx);
    if (h == nullptr) return;
    if (h->ctx != nullptr) EVP_MAC_CTX_free(h->ctx);
    OPENSSL_cleanse(h->key, sizeof(h->key));
    delete h;
}

inline void hmac_update(void* ctx, const std::byte* in, std::size_t len) noexcept {
    auto* h = static_cast<openssl_hmac*>(ctx);
    EVP_MAC_update(h->ctx, reinterpret_cast<const unsigned char*>(in), len);
}

[[nodiscard]] inline bool hmac_final(void* ctx, std::byte* out) noexcept {
    auto* h = static_cast<openssl_hmac*>(ctx);
    std::size_t n = 0;
    if (EVP_MAC_final(h->ctx, reinterpret_cast<unsigned char*>(out), &n, EVP_MAX_MD_SIZE) != 1) {
        return false;
    }
    return EVP_MAC_init(h->ctx, h->key, h->key_len, nullptr) == 1;
}

[[nodiscard]] inline bool poly1305(const std::byte* key32, const std::byte* in, std::size_t len,
                                   std::byte* out16) noexcept {
    if (key32 == nullptr || out16 == nullptr || (len != 0 && in == nullptr)) return false;
    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "POLY1305", nullptr);
    if (mac == nullptr) return false;
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    if (ctx == nullptr) return false;
    std::size_t outlen = 0;
    const bool ok = EVP_MAC_init(ctx, reinterpret_cast<const unsigned char*>(key32), 32,
                                 nullptr) == 1
                    && EVP_MAC_update(ctx, reinterpret_cast<const unsigned char*>(in), len) == 1
                    && EVP_MAC_final(ctx, reinterpret_cast<unsigned char*>(out16), &outlen,
                                     16) == 1
                    && outlen == 16;
    EVP_MAC_CTX_free(ctx);
    return ok;
}

[[nodiscard]] inline bool aead_init_cipher(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* c,
                                           const unsigned char* key, bool encrypt) noexcept {
    if (ctx == nullptr || c == nullptr || key == nullptr) return false;
    std::size_t ivlen = 12;
    OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &ivlen),
        OSSL_PARAM_construct_end(),
    };
    const int ok = encrypt ? EVP_EncryptInit_ex2(ctx, c, key, nullptr, params)
                           : EVP_DecryptInit_ex2(ctx, c, key, nullptr, params);
    return ok == 1;
}

[[nodiscard]] inline bool aead_get_tag(EVP_CIPHER_CTX* ctx, std::byte* tag_out) noexcept {
    OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag_out, 16),
        OSSL_PARAM_construct_end(),
    };
    return EVP_CIPHER_CTX_get_params(ctx, params) == 1;
}

[[nodiscard]] inline bool aead_set_tag(EVP_CIPHER_CTX* ctx, std::byte* tag) noexcept {
    OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, 16),
        OSSL_PARAM_construct_end(),
    };
    return EVP_CIPHER_CTX_set_params(ctx, params) == 1;
}

[[nodiscard]] inline bool sm2_primitives_available() noexcept {
    static const bool avail = []() noexcept {
        EVP_MD* sm3 = EVP_MD_fetch(nullptr, "SM3", nullptr);
        EVP_CIPHER* sm4_ctr = EVP_CIPHER_fetch(nullptr, "SM4-CTR", nullptr);
        EVP_CIPHER* sm4_cbc = EVP_CIPHER_fetch(nullptr, "SM4-CBC", nullptr);
        EC_GROUP* g = (NID_sm2 != NID_undef) ? EC_GROUP_new_by_curve_name(NID_sm2) : nullptr;
        const bool ok = sm3 != nullptr && sm4_ctr != nullptr && sm4_cbc != nullptr && g != nullptr;
        EVP_MD_free(sm3);
        EVP_CIPHER_free(sm4_ctr);
        EVP_CIPHER_free(sm4_cbc);
        EC_GROUP_free(g);
        return ok;
    }();
    return avail;
}

[[nodiscard]] inline bool openssl_supports(primitive_kind kind, std::uint8_t id) noexcept {
    return openssl_supports_common(sm2_primitives_available(), kind, id);
}

// SSH simplified GM/T 0003 KAP. Identity key = ephemeral key. is_server: client=0, server=1.
[[nodiscard]] inline bool sm2_ssh_kap(unsigned char* out, std::size_t outlen, int is_server,
                                      std::span<const std::byte> peer_pub,
                                      const EVP_PKEY* self_pkey) noexcept {
    if (out == nullptr || outlen == 0 || peer_pub.size() != 65 || self_pkey == nullptr) {
        return false;
    }
    unsigned char self_pub_oct[65];
    std::size_t self_pub_len = 0;
    if (EVP_PKEY_get_octet_string_param(self_pkey, OSSL_PKEY_PARAM_PUB_KEY, self_pub_oct,
                                        sizeof(self_pub_oct), &self_pub_len) != 1
        || self_pub_len != 65) {
        return false;
    }
    BIGNUM* d = nullptr;
    if (EVP_PKEY_get_bn_param(self_pkey, OSSL_PKEY_PARAM_PRIV_KEY, &d) != 1 || d == nullptr) {
        BN_clear_free(d);
        return false;
    }

    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_sm2);
    EC_POINT* rs = group != nullptr ? EC_POINT_new(group) : nullptr;
    EC_POINT* rp = group != nullptr ? EC_POINT_new(group) : nullptr;
    bool ok = false;
    if (group != nullptr && rs != nullptr && rp != nullptr
        && EC_POINT_oct2point(group, rs, self_pub_oct, self_pub_len, nullptr) == 1
        && EC_POINT_oct2point(group, rp, reinterpret_cast<const unsigned char*>(peer_pub.data()),
                              peer_pub.size(), nullptr) == 1) {
        ok = sm2_ssh_kap_points(out, outlen, is_server, group, d, rs, rp);
    }
    EC_POINT_free(rp);
    EC_POINT_free(rs);
    EC_GROUP_free(group);
    BN_clear_free(d);
    return ok;
}

[[nodiscard]] inline bool sm2_za_digest_init(EVP_MD_CTX* mctx, EVP_PKEY* pkey, bool sign,
                                             EVP_PKEY_CTX** detached) noexcept {
    if (detached != nullptr) *detached = nullptr;
    if (mctx == nullptr || pkey == nullptr) return false;
    EVP_PKEY_CTX* pctx = nullptr;
    const int rc = sign ? EVP_DigestSignInit(mctx, &pctx, EVP_sm3(), nullptr, pkey)
                        : EVP_DigestVerifyInit(mctx, &pctx, EVP_sm3(), nullptr, pkey);
    // OpenSSL 3.x already defaults the SM2 dist_id, so it does not need to be set again.
    return rc == 1;
}

[[nodiscard]] inline bool append_pkey_bn(const EVP_PKEY* pkey, const char* name,
                                         std::byte* storage, std::size_t cap, std::size_t& used,
                                         std::span<const std::byte>& dest) noexcept {
    BIGNUM* bn = nullptr;
    const bool ok = EVP_PKEY_get_bn_param(pkey, name, &bn) == 1
                    && append_bn(storage, cap, used, bn, dest);
    BN_clear_free(bn);
    return ok;
}

[[nodiscard]] inline EVP_PKEY* ec_keygen(const char* keytype, const char* group) noexcept {
    EVP_PKEY_CTX* c = EVP_PKEY_CTX_new_from_name(nullptr, keytype, nullptr);
    EVP_PKEY* pkey = nullptr;
    const char* conv = OSSL_PKEY_EC_POINT_CONVERSION_FORMAT_UNCOMPRESSED;
    OSSL_PARAM params[3] = {
        OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char*>(group), 0),
        OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_EC_POINT_CONVERSION_FORMAT, const_cast<char*>(conv), 0),
        OSSL_PARAM_construct_end(),
    };
    if (c == nullptr || EVP_PKEY_keygen_init(c) != 1
        || EVP_PKEY_CTX_set_params(c, params) != 1
        || EVP_PKEY_generate(c, &pkey) != 1) {
        EVP_PKEY_free(pkey);
        pkey = nullptr;
    }
    EVP_PKEY_CTX_free(c);
    return pkey;
}

[[nodiscard]] inline EVP_PKEY* ec_from_public(const char* keytype, const char* group,
                                              std::span<const std::byte> pub) noexcept {
    if (group == nullptr || pub.empty()) return nullptr;
    EVP_PKEY_CTX* c = EVP_PKEY_CTX_new_from_name(nullptr, keytype, nullptr);
    EVP_PKEY* pkey = nullptr;
    OSSL_PARAM params[3] = {
        OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char*>(group), 0),
        OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY, const_cast<std::byte*>(pub.data()), pub.size()),
        OSSL_PARAM_construct_end(),
    };
    if (c == nullptr || EVP_PKEY_fromdata_init(c) != 1
        || EVP_PKEY_fromdata(c, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        EVP_PKEY_free(pkey);
        pkey = nullptr;
    }
    EVP_PKEY_CTX_free(c);
    return pkey;
}

[[nodiscard]] inline bool generate_ecdsa(sig_id id, private_key_material* out, std::byte* storage,
                                         std::size_t cap, std::size_t& used) noexcept {
    const char* group = ec_sig_group_name(id);
    if (group == nullptr) return false;
    EVP_PKEY* pkey = ec_keygen(ec_sig_keytype(id), group);
    bool ok = false;
    if (pkey != nullptr
        && append_pkey_bn(pkey, OSSL_PKEY_PARAM_PRIV_KEY, storage, cap, used, out->seed)) {
        unsigned char pub[133];
        std::size_t publen = 0;
        if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, pub, sizeof(pub),
                                            &publen) == 1
            && publen != 0
            && append_bytes(storage, cap, used, pub, publen, out->public_key)) {
            ok = true;
        }
    }
    EVP_PKEY_free(pkey);
    return ok;
}

[[nodiscard]] inline bool generate_rsa(std::uint32_t bits, private_key_material* out,
                                       std::byte* storage, std::size_t cap,
                                       std::size_t& used) noexcept {
    if (bits == 0) bits = 3072;
    if (bits < 2048 || bits > 8192) return false;
    EVP_PKEY* pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", static_cast<std::size_t>(bits));
    const bool ok = pkey != nullptr
                    && append_pkey_bn(pkey, OSSL_PKEY_PARAM_RSA_N, storage, cap, used, out->n)
                    && append_pkey_bn(pkey, OSSL_PKEY_PARAM_RSA_E, storage, cap, used, out->e)
                    && append_pkey_bn(pkey, OSSL_PKEY_PARAM_RSA_D, storage, cap, used, out->d)
                    && append_pkey_bn(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, storage, cap, used, out->p)
                    && append_pkey_bn(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, storage, cap, used, out->q)
                    && append_pkey_bn(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, storage, cap, used,
                                      out->iqmp);
    EVP_PKEY_free(pkey);
    return ok;
}

[[nodiscard]] inline void* ecdsa_signing_key_new(const private_key_material* key) noexcept {
    const char* group_name = ec_sig_group_name(key->algorithm);
    const int nid = ec_sig_curve_nid(key->algorithm);
    if (group_name == nullptr || nid == NID_undef || key->seed.empty()) return nullptr;

    BIGNUM* d = bn_secret_from_span(key->seed);
    if (d == nullptr) return nullptr;

    unsigned char pub_buf[133];
    const unsigned char* pub_ptr = nullptr;
    std::size_t pub_len = 0;
    if (!key->public_key.empty()) {
        pub_ptr = reinterpret_cast<const unsigned char*>(key->public_key.data());
        pub_len = key->public_key.size();
    } else {
        // EVP_PKEY_fromdata does not derive the public point from the private scalar.
        pub_len = ec_derive_uncompressed_pub(nid, d, pub_buf, sizeof(pub_buf));
        if (pub_len != 0) pub_ptr = pub_buf;
    }

    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM* params = nullptr;
    EVP_PKEY_CTX* c = nullptr;
    EVP_PKEY* pkey = nullptr;
    if (pub_ptr != nullptr && bld != nullptr
        && OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0) == 1
        && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, d) == 1
        && OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub_ptr, pub_len) == 1) {
        params = OSSL_PARAM_BLD_to_param(bld);
        c = EVP_PKEY_CTX_new_from_name(nullptr, ec_sig_keytype(key->algorithm), nullptr);
        if (params != nullptr && c != nullptr && EVP_PKEY_fromdata_init(c) == 1
            && EVP_PKEY_fromdata(c, &pkey, EVP_PKEY_KEYPAIR, params) != 1) {
            EVP_PKEY_free(pkey);
            pkey = nullptr;
        }
    }
    EVP_PKEY_CTX_free(c);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_clear_free(d);
    return wrap_signing_key(key->algorithm, pkey);
}

[[nodiscard]] inline void* rsa_signing_key_new(const private_key_material* key) noexcept {
    if (rsa_md(key->algorithm) == nullptr) return nullptr;
    if (key->n.empty() || key->e.empty() || key->d.empty() || key->p.empty() || key->q.empty()
        || key->iqmp.empty()) {
        return nullptr;
    }
    BIGNUM* n = bn_from_span(key->n);
    BIGNUM* e = bn_from_span(key->e);
    BIGNUM* d = bn_secret_from_span(key->d);
    BIGNUM* p = bn_secret_from_span(key->p);
    BIGNUM* q = bn_secret_from_span(key->q);
    BIGNUM* iq = bn_secret_from_span(key->iqmp);
    BIGNUM* dmp1 = nullptr;
    BIGNUM* dmq1 = nullptr;
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM* params = nullptr;
    EVP_PKEY_CTX* c = nullptr;
    EVP_PKEY* pkey = nullptr;

    if (n != nullptr && e != nullptr && d != nullptr && p != nullptr && q != nullptr
        && iq != nullptr && bld != nullptr
        && rsa_derive_crt_exponents(d, p, q, &dmp1, &dmq1)
        && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) == 1
        && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e) == 1
        && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, d) == 1
        && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, p) == 1
        && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, q) == 1
        && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, dmp1) == 1
        && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, dmq1) == 1
        && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, iq) == 1) {
        params = OSSL_PARAM_BLD_to_param(bld);
        c = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
        if (params != nullptr && c != nullptr && EVP_PKEY_fromdata_init(c) == 1
            && EVP_PKEY_fromdata(c, &pkey, EVP_PKEY_KEYPAIR, params) != 1) {
            EVP_PKEY_free(pkey);
            pkey = nullptr;
        }
    }

    EVP_PKEY_CTX_free(c);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_clear_free(dmq1);
    BN_clear_free(dmp1);
    BN_clear_free(iq);
    BN_clear_free(q);
    BN_clear_free(p);
    BN_clear_free(d);
    BN_free(e);
    BN_free(n);
    return wrap_signing_key(key->algorithm, pkey);
}

[[nodiscard]] inline EVP_PKEY* rsa_from_public(std::span<const std::byte> n_span,
                                               std::span<const std::byte> e_span) noexcept {
    BIGNUM* n = bn_from_span(n_span);
    BIGNUM* e = bn_from_span(e_span);
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM* params = nullptr;
    EVP_PKEY_CTX* c = nullptr;
    EVP_PKEY* pkey = nullptr;
    if (n != nullptr && e != nullptr && bld != nullptr
        && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) == 1
        && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e) == 1) {
        params = OSSL_PARAM_BLD_to_param(bld);
        c = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
        if (params != nullptr && c != nullptr && EVP_PKEY_fromdata_init(c) == 1
            && EVP_PKEY_fromdata(c, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
            EVP_PKEY_free(pkey);
            pkey = nullptr;
        }
    }
    EVP_PKEY_CTX_free(c);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(e);
    BN_free(n);
    return pkey;
}

[[nodiscard]] inline bool set_rsa_pkcs1_pad(EVP_PKEY_CTX* pctx) noexcept {
    if (pctx == nullptr) return false;
    const char* pad = OSSL_PKEY_RSA_PAD_MODE_PKCSV15;
    OSSL_PARAM params[2] = {
        OSSL_PARAM_construct_utf8_string(
            OSSL_SIGNATURE_PARAM_PAD_MODE, const_cast<char*>(pad), 0),
        OSSL_PARAM_construct_end(),
    };
    return EVP_PKEY_CTX_set_params(pctx, params) == 1;
}

[[nodiscard]] inline EVP_PKEY* ec_sig_from_public(sig_id id,
                                                  std::span<const std::byte> pub) noexcept {
    const char* group = ec_sig_group_name(id);
    if (group == nullptr) return nullptr;
    return ec_from_public(ec_sig_keytype(id), group, pub);
}

[[nodiscard]] inline bool verify_sm2_ecdsa(std::span<const std::byte> pub, const std::byte* msg,
                                           std::size_t msglen, std::span<const std::byte> r,
                                           std::span<const std::byte> s) noexcept {
    EVP_PKEY* pkey = ec_from_public("EC", "SM2", pub);
    if (pkey == nullptr) return false;
    const bool ok = verify_ecdsa(pkey, EVP_sm3(), msg, msglen, r, s);
    EVP_PKEY_free(pkey);
    return ok;
}

[[nodiscard]] inline bool sign_sm2_ecdsa(openssl_signing_key* sk, const std::byte* msg,
                                         std::size_t msglen, std::byte* out, std::size_t cap,
                                         std::size_t* out_len) noexcept {
    return sign_ecdsa(sk, msg, msglen, out, cap, out_len);
}

struct openssl_kex {
    kex_id id{};
    EVP_PKEY* pkey = nullptr;
};

[[nodiscard]] inline bool kex_init_group(openssl_kex* k, kex_id id) noexcept {
    if (const char* group = ec_kex_group_name(id); group != nullptr) {
        // Plain ecdh_sm2 MUST use key type "EC" so Tongsuo does not dispatch to SM2DH.
        k->pkey = ec_keygen("EC", group);
        return k->pkey != nullptr;
    }
    if (const char* dh_group = dh_kex_group_name(id); dh_group != nullptr) {
        EVP_PKEY_CTX* c = EVP_PKEY_CTX_new_from_name(nullptr, "DH", nullptr);
        OSSL_PARAM params[2] = {
            OSSL_PARAM_construct_utf8_string(
                OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char*>(dh_group), 0),
            OSSL_PARAM_construct_end(),
        };
        const bool ok = c != nullptr && EVP_PKEY_keygen_init(c) == 1
                        && EVP_PKEY_CTX_set_params(c, params) == 1
                        && EVP_PKEY_generate(c, &k->pkey) == 1;
        EVP_PKEY_CTX_free(c);
        return ok;
    }
    return false;
}

inline void kex_cleanup(openssl_kex* k) noexcept {
    if (k->pkey != nullptr) EVP_PKEY_free(k->pkey);
}

[[nodiscard]] inline bool kex_group_public(openssl_kex* k, std::byte* out, std::size_t want,
                                           std::size_t* out_len) noexcept {
    if (k->pkey == nullptr) return false;
    if (ec_kex_group_name(k->id) != nullptr) {
        std::size_t len = 0;
        if (EVP_PKEY_get_octet_string_param(
                k->pkey, OSSL_PKEY_PARAM_PUB_KEY,
                reinterpret_cast<unsigned char*>(out), want, &len) != 1
            || len != want) {
            return false;
        }
        *out_len = want;
        return true;
    }
    if (dh_kex_group_name(k->id) != nullptr) {
        BIGNUM* pub = nullptr;
        const bool ok = EVP_PKEY_get_bn_param(k->pkey, OSSL_PKEY_PARAM_PUB_KEY, &pub) == 1
                        && bn_to_fixed(pub, out, want);
        BN_free(pub);
        if (!ok) return false;
        *out_len = want;
        return true;
    }
    return false;
}

[[nodiscard]] inline bool kex_group_agree(openssl_kex* k, const std::byte* peer,
                                          std::size_t peerlen, std::byte* out, std::size_t want,
                                          std::size_t* out_len) noexcept {
    if (k->pkey == nullptr) return false;
    if (k->id == kex_id::sm2_kap || k->id == kex_id::sm2_kap_server) {
        if (peerlen != kex_public_size(k->id)) return false;
        const bool ok = sm2_ssh_kap(
            reinterpret_cast<unsigned char*>(out), want,
            k->id == kex_id::sm2_kap_server ? 1 : 0,
            std::span<const std::byte>{peer, peerlen}, k->pkey);
        if (ok) *out_len = want;
        return ok;
    }
    if (const char* group = ec_kex_group_name(k->id); group != nullptr) {
        if (peerlen != kex_public_size(k->id)) return false;
        EVP_PKEY* peer_key = ec_from_public("EC", group, std::span<const std::byte>{peer, peerlen});
        if (peer_key == nullptr) return false;
        const bool ok = evp_pkey_derive_shared(k->pkey, peer_key, out, want, out_len);
        EVP_PKEY_free(peer_key);
        return ok;
    }
    // Finite-field DH: require 1 < f < p-1 (RFC 4253 §8).
    const char* dh_group = dh_kex_group_name(k->id);
    if (dh_group == nullptr || peerlen == 0) return false;
    BIGNUM* f = BN_bin2bn(reinterpret_cast<const unsigned char*>(peer),
                          static_cast<int>(peerlen), nullptr);
    BIGNUM* p = nullptr;
    if (f == nullptr || EVP_PKEY_get_bn_param(k->pkey, OSSL_PKEY_PARAM_FFC_P, &p) != 1
        || p == nullptr) {
        BN_free(f);
        BN_free(p);
        return false;
    }
    OSSL_PARAM_BLD* bld = nullptr;
    OSSL_PARAM* peer_params = nullptr;
    EVP_PKEY_CTX* fctx = nullptr;
    EVP_PKEY* peer_key = nullptr;
    EVP_PKEY_CTX* dctx = nullptr;
    bool ok = false;
    if (dh_peer_in_range(f, p)) {
        bld = OSSL_PARAM_BLD_new();
        if (bld != nullptr
            && OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, dh_group, 0) == 1
            && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, f) == 1) {
            peer_params = OSSL_PARAM_BLD_to_param(bld);
            fctx = EVP_PKEY_CTX_new_from_name(nullptr, "DH", nullptr);
            if (peer_params != nullptr && fctx != nullptr
                && EVP_PKEY_fromdata_init(fctx) == 1
                && EVP_PKEY_fromdata(fctx, &peer_key, EVP_PKEY_PUBLIC_KEY, peer_params) == 1) {
                dctx = EVP_PKEY_CTX_new_from_pkey(nullptr, k->pkey, nullptr);
                unsigned int pad = 1;
                OSSL_PARAM dparams[2] = {
                    OSSL_PARAM_construct_uint(OSSL_EXCHANGE_PARAM_PAD, &pad),
                    OSSL_PARAM_construct_end(),
                };
                std::size_t len = want;
                if (dctx != nullptr
                    && EVP_PKEY_derive_init_ex(dctx, dparams) == 1
                    && EVP_PKEY_derive_set_peer(dctx, peer_key) == 1
                    && EVP_PKEY_derive(dctx, reinterpret_cast<unsigned char*>(out), &len) == 1) {
                    if (len == want) {
                        *out_len = want;
                        ok = true;
                    } else {
                        OPENSSL_cleanse(out, want);
                    }
                }
            }
        }
    }
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(peer_key);
    EVP_PKEY_CTX_free(fctx);
    OSSL_PARAM_free(peer_params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(p);
    BN_free(f);
    return ok;
}

YANTERM_SSH_ASSERT_OPENSSL_OPS(yanterm::ssh::crypto::detail::ossl3);

}  // namespace yanterm::ssh::crypto::detail::ossl3
