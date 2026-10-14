#pragma once

#include <yanterm-ssh/crypto/detail/ossl_common.hpp>

#include <openssl/dh.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>

namespace yanterm::ssh::crypto::detail::ossl1_1 {

using detail::openssl_signing_key;
using detail::sm2_field_bytes;
using detail::sm2_kap_id;
using detail::sm2_kdf_gmt0003;
using detail::sm2_sign_id;
using detail::sm2_sign_id_len;
using detail::sm2_z_digest;

// HMAC_CTX plus the parameters needed to re-initialise it after HMAC_Final,
// so that hmac_ctx can be reused across packets without reallocating.
struct openssl_hmac {
    HMAC_CTX* ctx = nullptr;
    const EVP_MD* md = nullptr;
    unsigned char key[128]{};
    std::size_t key_len = 0;
};

[[nodiscard]] inline void* hmac_new(hash_id id, const std::byte* key,
                                    std::size_t keylen) noexcept {
    const EVP_MD* md = evp_md(id);
    if (md == nullptr || keylen > sizeof(openssl_hmac::key)) return nullptr;
    auto* h = new (std::nothrow) openssl_hmac{};
    if (h == nullptr) return nullptr;
    h->ctx = HMAC_CTX_new();
    h->md = md;
    h->key_len = keylen;
    if (keylen != 0) std::memcpy(h->key, key, keylen);
    if (h->ctx == nullptr || HMAC_Init_ex(h->ctx, h->key, static_cast<int>(keylen),
                                          md, nullptr) != 1) {
        if (h->ctx != nullptr) HMAC_CTX_free(h->ctx);
        OPENSSL_cleanse(h->key, sizeof(h->key));
        delete h;
        return nullptr;
    }
    return h;
}

inline void hmac_free(void* ctx) noexcept {
    auto* h = static_cast<openssl_hmac*>(ctx);
    if (h == nullptr) return;
    if (h->ctx != nullptr) HMAC_CTX_free(h->ctx);
    OPENSSL_cleanse(h->key, sizeof(h->key));
    delete h;
}

inline void hmac_update(void* ctx, const std::byte* in, std::size_t len) noexcept {
    auto* h = static_cast<openssl_hmac*>(ctx);
    HMAC_Update(h->ctx, reinterpret_cast<const unsigned char*>(in), len);
}

[[nodiscard]] inline bool hmac_final(void* ctx, std::byte* out) noexcept {
    auto* h = static_cast<openssl_hmac*>(ctx);
    unsigned int n = 0;
    if (HMAC_Final(h->ctx, reinterpret_cast<unsigned char*>(out), &n) != 1) return false;
    return HMAC_Init_ex(h->ctx, h->key, static_cast<int>(h->key_len), h->md, nullptr) == 1;
}

[[nodiscard]] inline bool poly1305(const std::byte* key32, const std::byte* in, std::size_t len,
                                   std::byte* out16) noexcept {
    if (key32 == nullptr || out16 == nullptr || (len != 0 && in == nullptr)) return false;
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_POLY1305, nullptr, reinterpret_cast<const unsigned char*>(key32), 32);
    if (pkey == nullptr) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    bool ok = false;
    if (ctx != nullptr && EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pkey) == 1) {
        std::size_t outlen = 16;
        ok = EVP_DigestSign(ctx, reinterpret_cast<unsigned char*>(out16), &outlen,
                            reinterpret_cast<const unsigned char*>(in), len) == 1
             && outlen == 16;
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

[[nodiscard]] inline bool aead_init_cipher(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* c,
                                           const unsigned char* key, bool encrypt) noexcept {
    if (ctx == nullptr || c == nullptr || key == nullptr) return false;
    const int ok = encrypt ? EVP_EncryptInit_ex(ctx, c, nullptr, key, nullptr)
                           : EVP_DecryptInit_ex(ctx, c, nullptr, key, nullptr);
    return ok == 1 && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) == 1;
}

[[nodiscard]] inline bool aead_get_tag(EVP_CIPHER_CTX* ctx, std::byte* tag_out) noexcept {
    return EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag_out) == 1;
}

[[nodiscard]] inline bool aead_set_tag(EVP_CIPHER_CTX* ctx, std::byte* tag) noexcept {
    return EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) == 1;
}

[[nodiscard]] inline bool sm2_primitives_available() noexcept {
    if (NID_sm2 == NID_undef) return false;
    if (EVP_sm3() == nullptr) return false;
    if (EVP_sm4_ctr() == nullptr || EVP_sm4_cbc() == nullptr) return false;
    EC_GROUP* g = EC_GROUP_new_by_curve_name(NID_sm2);
    if (g == nullptr) return false;
    EC_GROUP_free(g);
    return true;
}

[[nodiscard]] inline bool openssl_supports(primitive_kind kind, std::uint8_t id) noexcept {
    return openssl_supports_common(sm2_primitives_available(), kind, id);
}

[[nodiscard]] inline EC_KEY* ec_key_from_public(int nid, std::span<const std::byte> q) noexcept {
    if (nid == NID_undef || q.empty()) return nullptr;
    EC_KEY* ec = EC_KEY_new_by_curve_name(nid);
    if (ec == nullptr) return nullptr;
    const EC_GROUP* group = EC_KEY_get0_group(ec);
    EC_POINT* point = group != nullptr ? EC_POINT_new(group) : nullptr;
    const bool ok = point != nullptr
                    && EC_POINT_oct2point(group, point,
                                          reinterpret_cast<const unsigned char*>(q.data()),
                                          q.size(), nullptr) == 1
                    && EC_KEY_set_public_key(ec, point) == 1;
    EC_POINT_free(point);
    if (!ok) {
        EC_KEY_free(ec);
        return nullptr;
    }
    return ec;
}

[[nodiscard]] inline EVP_PKEY* pkey_from_ec(EC_KEY* ec) noexcept {
    if (ec == nullptr) return nullptr;
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (pkey == nullptr || EVP_PKEY_set1_EC_KEY(pkey, ec) != 1) {
        EVP_PKEY_free(pkey);
        return nullptr;
    }
    return pkey;
}

[[nodiscard]] inline EVP_PKEY* ec_from_public(int nid, std::span<const std::byte> q) noexcept {
    EC_KEY* ec = ec_key_from_public(nid, q);
    if (ec == nullptr) return nullptr;
    EVP_PKEY* pkey = pkey_from_ec(ec);
    EC_KEY_free(ec);
    return pkey;
}

// SSH simplified GM/T 0003 KAP. Identity key = ephemeral key. is_server: client=0, server=1.
[[nodiscard]] inline bool sm2_ssh_kap(unsigned char* out, std::size_t outlen, int is_server,
                                      std::span<const std::byte> peer_pub,
                                      const EVP_PKEY* self_pkey) noexcept {
    if (out == nullptr || outlen == 0 || peer_pub.size() != 65 || self_pkey == nullptr) {
        return false;
    }
    // OpenSSL 1.1.1's EVP_PKEY_get0_EC_KEY takes a non-const EVP_PKEY*.
    const EC_KEY* self = EVP_PKEY_get0_EC_KEY(const_cast<EVP_PKEY*>(self_pkey));
    if (self == nullptr) return false;
    EC_KEY* peer = ec_key_from_public(NID_sm2, peer_pub);
    if (peer == nullptr) return false;
    const bool ok = sm2_ssh_kap_points(out, outlen, is_server, EC_KEY_get0_group(self),
                                       EC_KEY_get0_private_key(self),
                                       EC_KEY_get0_public_key(self),
                                       EC_KEY_get0_public_key(peer));
    EC_KEY_free(peer);
    return ok;
}

[[nodiscard]] inline bool sm2_za_digest_init(EVP_MD_CTX* mctx, EVP_PKEY* pkey, bool sign,
                                             EVP_PKEY_CTX** detached) noexcept {
    if (detached != nullptr) *detached = nullptr;
    if (mctx == nullptr || pkey == nullptr) return false;
#if defined(TONGSUO_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x30000000L
    if (EVP_PKEY_id(pkey) != EVP_PKEY_SM2) {
        if (EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2) != 1) return false;
    }
#endif
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(pkey, nullptr);
    if (pctx == nullptr) return false;
    if (EVP_PKEY_CTX_set1_id(pctx, sm2_sign_id, static_cast<int>(sm2_sign_id_len)) != 1) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
    const int rc = sign ? EVP_DigestSignInit(mctx, nullptr, EVP_sm3(), nullptr, pkey)
                        : EVP_DigestVerifyInit(mctx, nullptr, EVP_sm3(), nullptr, pkey);
    if (rc != 1) {
        EVP_MD_CTX_set_pkey_ctx(mctx, nullptr);
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    if (detached != nullptr) *detached = pctx;
    return true;
}

[[nodiscard]] inline EVP_PKEY* ec_sig_from_public(sig_id id,
                                                  std::span<const std::byte> pub) noexcept {
    const int nid = ec_sig_curve_nid(id);
    if (nid == NID_undef) return nullptr;
    return ec_from_public(nid, pub);
}

[[nodiscard]] inline bool verify_sm2_ecdsa(std::span<const std::byte> pub, const std::byte* msg,
                                           std::size_t msglen, std::span<const std::byte> r,
                                           std::span<const std::byte> s) noexcept {
    if (pub.size() != 65 || r.empty() || s.empty()) return false;
    if (msglen != 0 && msg == nullptr) return false;
    EC_KEY* ec = ec_key_from_public(NID_sm2, pub);
    if (ec == nullptr) return false;
    unsigned char digest[32];
    unsigned int dlen = 0;
    bool ok = false;
    if (EVP_Digest(reinterpret_cast<const unsigned char*>(msg), msglen, digest, &dlen, EVP_sm3(),
                   nullptr) == 1) {
        BIGNUM* rb = bn_from_span(r);
        BIGNUM* sb = bn_from_span(s);
        ECDSA_SIG* esig = ECDSA_SIG_new();
        if (rb != nullptr && sb != nullptr && esig != nullptr
            && ECDSA_SIG_set0(esig, rb, sb) == 1) {
            rb = nullptr;
            sb = nullptr;
            ok = ECDSA_do_verify(digest, static_cast<int>(dlen), esig, ec) == 1;
        }
        ECDSA_SIG_free(esig);
        BN_free(rb);
        BN_free(sb);
    }
    EC_KEY_free(ec);
    return ok;
}

[[nodiscard]] inline bool sign_sm2_ecdsa(openssl_signing_key* sk, const std::byte* msg,
                                         std::size_t msglen, std::byte* out, std::size_t cap,
                                         std::size_t* out_len) noexcept {
    if (sk == nullptr || sk->pkey == nullptr || out == nullptr || out_len == nullptr) return false;
    if (msglen != 0 && msg == nullptr) return false;
    const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(sk->pkey);
    if (ec == nullptr) return false;
    unsigned char digest[32];
    unsigned int dlen = 0;
    if (EVP_Digest(reinterpret_cast<const unsigned char*>(msg), msglen, digest, &dlen, EVP_sm3(),
                   nullptr) != 1) {
        return false;
    }
    ECDSA_SIG* esig = ECDSA_do_sign(digest, static_cast<int>(dlen), const_cast<EC_KEY*>(ec));
    if (esig == nullptr) return false;
    const bool ok = ecdsa_sig_to_mpint(esig, out, cap, out_len);
    ECDSA_SIG_free(esig);
    return ok;
}

[[nodiscard]] inline bool generate_ecdsa(sig_id id, private_key_material* out, std::byte* storage,
                                         std::size_t cap, std::size_t& used) noexcept {
    const int nid = ec_sig_curve_nid(id);
    if (nid == NID_undef) return false;
    EVP_PKEY_CTX* c = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY* pkey = nullptr;
    bool ok = false;
    if (c != nullptr && EVP_PKEY_keygen_init(c) == 1
        && EVP_PKEY_CTX_set_ec_paramgen_curve_nid(c, nid) == 1
        && EVP_PKEY_keygen(c, &pkey) == 1) {
        const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(pkey);
        const BIGNUM* d = (ec != nullptr) ? EC_KEY_get0_private_key(ec) : nullptr;
        const EC_GROUP* group = (ec != nullptr) ? EC_KEY_get0_group(ec) : nullptr;
        const EC_POINT* pub = (ec != nullptr) ? EC_KEY_get0_public_key(ec) : nullptr;
        if (d != nullptr && group != nullptr && pub != nullptr
            && append_bn(storage, cap, used, d, out->seed)) {
            const std::size_t publen = EC_POINT_point2oct(
                group, pub, POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
            if (publen != 0 && used <= cap && publen <= cap - used) {
                const std::size_t n = EC_POINT_point2oct(
                    group, pub, POINT_CONVERSION_UNCOMPRESSED,
                    reinterpret_cast<unsigned char*>(storage + used), cap - used, nullptr);
                if (n == publen) {
                    out->public_key = {storage + used, n};
                    used += n;
                    ok = true;
                }
            }
        }
    }
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(pkey);
    return ok;
}

[[nodiscard]] inline bool generate_rsa(std::uint32_t bits, private_key_material* out,
                                       std::byte* storage, std::size_t cap,
                                       std::size_t& used) noexcept {
    if (bits == 0) bits = 3072;
    if (bits < 2048 || bits > 8192) return false;
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    bool ok = false;
    if (rsa != nullptr && e != nullptr && BN_set_word(e, RSA_F4) == 1
        && RSA_generate_key_ex(rsa, static_cast<int>(bits), e, nullptr) == 1) {
        const BIGNUM* n = nullptr;
        const BIGNUM* e_bn = nullptr;
        const BIGNUM* d = nullptr;
        const BIGNUM* p = nullptr;
        const BIGNUM* q = nullptr;
        const BIGNUM* iqmp = nullptr;
        RSA_get0_key(rsa, &n, &e_bn, &d);
        RSA_get0_factors(rsa, &p, &q);
        RSA_get0_crt_params(rsa, nullptr, nullptr, &iqmp);
        ok = append_bn(storage, cap, used, n, out->n)
             && append_bn(storage, cap, used, e_bn, out->e)
             && append_bn(storage, cap, used, d, out->d)
             && append_bn(storage, cap, used, p, out->p)
             && append_bn(storage, cap, used, q, out->q)
             && append_bn(storage, cap, used, iqmp, out->iqmp);
    }
    BN_free(e);
    RSA_free(rsa);
    return ok;
}

[[nodiscard]] inline void* ecdsa_signing_key_new(const private_key_material* key) noexcept {
    const int nid = ec_sig_curve_nid(key->algorithm);
    if (nid == NID_undef || key->seed.empty()) return nullptr;
    EC_KEY* ec = EC_KEY_new_by_curve_name(nid);
    BIGNUM* d = bn_from_span(key->seed);
    if (ec == nullptr || d == nullptr || EC_KEY_set_private_key(ec, d) != 1) {
        BN_free(d);
        EC_KEY_free(ec);
        return nullptr;
    }
    BN_free(d);
    const EC_GROUP* group = EC_KEY_get0_group(ec);
    EC_POINT* point = EC_POINT_new(group);
    bool pub_ok = false;
    if (point != nullptr) {
        if (!key->public_key.empty()) {
            pub_ok = EC_POINT_oct2point(
                         group, point,
                         reinterpret_cast<const unsigned char*>(key->public_key.data()),
                         key->public_key.size(), nullptr) == 1;
        } else {
            pub_ok = EC_POINT_mul(group, point, EC_KEY_get0_private_key(ec), nullptr, nullptr,
                                  nullptr) == 1;
        }
        pub_ok = pub_ok && EC_KEY_set_public_key(ec, point) == 1;
    }
    EC_POINT_free(point);
    if (!pub_ok) {
        EC_KEY_free(ec);
        return nullptr;
    }
    EVP_PKEY* pkey = pkey_from_ec(ec);
    EC_KEY_free(ec);
    return wrap_signing_key(key->algorithm, pkey);
}

[[nodiscard]] inline bool rsa_install_crt(RSA* rsa, std::span<const std::byte> iqmp) noexcept {
    const BIGNUM* d = nullptr;
    const BIGNUM* p = nullptr;
    const BIGNUM* q = nullptr;
    RSA_get0_key(rsa, nullptr, nullptr, &d);
    RSA_get0_factors(rsa, &p, &q);
    BIGNUM* dmp1 = nullptr;
    BIGNUM* dmq1 = nullptr;
    BIGNUM* iq = bn_from_span(iqmp);
    bool ok = false;
    if (iq != nullptr && rsa_derive_crt_exponents(d, p, q, &dmp1, &dmq1)
        && RSA_set0_crt_params(rsa, dmp1, dmq1, iq) == 1) {
        dmp1 = nullptr;
        dmq1 = nullptr;
        iq = nullptr;
        ok = true;
    }
    BN_free(dmp1);
    BN_free(dmq1);
    BN_free(iq);
    return ok;
}

[[nodiscard]] inline void* rsa_signing_key_new(const private_key_material* key) noexcept {
    if (rsa_md(key->algorithm) == nullptr) return nullptr;
    if (key->n.empty() || key->e.empty() || key->d.empty() || key->p.empty() || key->q.empty()
        || key->iqmp.empty()) {
        return nullptr;
    }
    BIGNUM* n = bn_from_span(key->n);
    BIGNUM* e = bn_from_span(key->e);
    BIGNUM* d = bn_from_span(key->d);
    RSA* rsa = RSA_new();
    if (n == nullptr || e == nullptr || d == nullptr || rsa == nullptr
        || RSA_set0_key(rsa, n, e, d) != 1) {
        BN_free(n);
        BN_free(e);
        BN_free(d);
        RSA_free(rsa);
        return nullptr;
    }
    BIGNUM* p = bn_from_span(key->p);
    BIGNUM* q = bn_from_span(key->q);
    if (p == nullptr || q == nullptr || RSA_set0_factors(rsa, p, q) != 1) {
        BN_free(p);
        BN_free(q);
        RSA_free(rsa);
        return nullptr;
    }
    if (!rsa_install_crt(rsa, key->iqmp)) {
        RSA_free(rsa);
        return nullptr;
    }
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (pkey == nullptr || EVP_PKEY_set1_RSA(pkey, rsa) != 1) {
        EVP_PKEY_free(pkey);
        RSA_free(rsa);
        return nullptr;
    }
    RSA_free(rsa);
    return wrap_signing_key(key->algorithm, pkey);
}

[[nodiscard]] inline EVP_PKEY* rsa_from_public(std::span<const std::byte> n_span,
                                               std::span<const std::byte> e_span) noexcept {
    BIGNUM* n = bn_from_span(n_span);
    BIGNUM* e = bn_from_span(e_span);
    RSA* rsa = RSA_new();
    if (n == nullptr || e == nullptr || rsa == nullptr || RSA_set0_key(rsa, n, e, nullptr) != 1) {
        BN_free(n);
        BN_free(e);
        RSA_free(rsa);
        return nullptr;
    }
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (pkey == nullptr || EVP_PKEY_set1_RSA(pkey, rsa) != 1) {
        EVP_PKEY_free(pkey);
        RSA_free(rsa);
        return nullptr;
    }
    RSA_free(rsa);
    return pkey;
}

[[nodiscard]] inline bool set_rsa_pkcs1_pad(EVP_PKEY_CTX* pctx) noexcept {
    return pctx != nullptr && EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) == 1;
}

// RFC 3526 MODP groups, which is what SSH uses. These are NOT the RFC 7919
// ffdhe groups that DH_new_by_nid provides.
[[nodiscard]] inline BIGNUM* rfc3526_prime(kex_id id) noexcept {
    switch (id) {
    case kex_id::dh_group14: return BN_get_rfc3526_prime_2048(nullptr);
    case kex_id::dh_group16: return BN_get_rfc3526_prime_4096(nullptr);
    case kex_id::dh_group18: return BN_get_rfc3526_prime_8192(nullptr);
    default: return nullptr;
    }
}

struct openssl_kex {
    kex_id id{};
    EVP_PKEY* pkey = nullptr;   // curve25519 and NIST/SM2 ECDH
    DH* dh = nullptr;           // finite field groups
};

[[nodiscard]] inline bool kex_init_group(openssl_kex* k, kex_id id) noexcept {
    if (const int nid = ec_curve_nid(id); nid != NID_undef) {
        EVP_PKEY_CTX* c = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
        const bool ok = c != nullptr && EVP_PKEY_keygen_init(c) == 1
                        && EVP_PKEY_CTX_set_ec_paramgen_curve_nid(c, nid) == 1
                        && EVP_PKEY_keygen(c, &k->pkey) == 1;
        EVP_PKEY_CTX_free(c);
        return ok;
    }
    // Finite-field DH (RFC 3526 MODP). Free p/g ourselves until
    // DH_set0_pqg takes ownership — DH_free alone does not free them
    // before that transfer.
    BIGNUM* p = rfc3526_prime(id);
    BIGNUM* g = BN_new();
    k->dh = DH_new();
    if (p == nullptr || g == nullptr || k->dh == nullptr || BN_set_word(g, 2) != 1
        || DH_set0_pqg(k->dh, p, nullptr, g) != 1) {
        BN_free(p);
        BN_free(g);
        DH_free(k->dh);
        k->dh = nullptr;
        return false;
    }
    // p and g are now owned by k->dh.
    return DH_generate_key(k->dh) == 1;
}

inline void kex_cleanup(openssl_kex* k) noexcept {
    if (k->pkey != nullptr) EVP_PKEY_free(k->pkey);
    if (k->dh != nullptr) DH_free(k->dh);
}

[[nodiscard]] inline bool kex_group_public(openssl_kex* k, std::byte* out, std::size_t want,
                                           std::size_t* out_len) noexcept {
    if (ec_curve_nid(k->id) != NID_undef) {
        if (k->pkey == nullptr) return false;
        const EC_KEY* ec = EVP_PKEY_get0_EC_KEY(k->pkey);
        if (ec == nullptr) return false;
        const EC_GROUP* group = EC_KEY_get0_group(ec);
        const EC_POINT* pub = EC_KEY_get0_public_key(ec);
        if (group == nullptr || pub == nullptr) return false;
        const std::size_t n = EC_POINT_point2oct(
            group, pub, POINT_CONVERSION_UNCOMPRESSED,
            reinterpret_cast<unsigned char*>(out), want, nullptr);
        if (n != want) return false;
        *out_len = want;
        return true;
    }

    if (k->dh == nullptr) return false;
    const BIGNUM* pub = DH_get0_pub_key(k->dh);
    if (pub == nullptr || !bn_to_fixed(pub, out, want)) return false;
    *out_len = want;
    return true;
}

[[nodiscard]] inline bool kex_group_agree(openssl_kex* k, const std::byte* peer,
                                          std::size_t peerlen, std::byte* out, std::size_t want,
                                          std::size_t* out_len) noexcept {
    if (k->id == kex_id::sm2_kap || k->id == kex_id::sm2_kap_server) {
        if (k->pkey == nullptr || peerlen != kex_public_size(k->id)) return false;
        const bool ok = sm2_ssh_kap(
            reinterpret_cast<unsigned char*>(out), want,
            k->id == kex_id::sm2_kap_server ? 1 : 0,
            std::span<const std::byte>{peer, peerlen}, k->pkey);
        if (ok) *out_len = want;
        return ok;
    }

    if (k->id == kex_id::ecdh_sm2) {
        if (k->pkey == nullptr || peerlen != kex_public_size(k->id)) return false;
        const EC_KEY* self_ec = EVP_PKEY_get0_EC_KEY(k->pkey);
        const EC_GROUP* group = self_ec != nullptr ? EC_KEY_get0_group(self_ec) : nullptr;
        const BIGNUM* d = self_ec != nullptr ? EC_KEY_get0_private_key(self_ec) : nullptr;
        EC_POINT* peer_pt = group != nullptr ? EC_POINT_new(group) : nullptr;
        const bool ok = peer_pt != nullptr && d != nullptr
                        && EC_POINT_oct2point(group, peer_pt,
                                              reinterpret_cast<const unsigned char*>(peer),
                                              peerlen, nullptr) == 1
                        && sm2_ecdh_x_points(reinterpret_cast<unsigned char*>(out), group, d,
                                             peer_pt);
        EC_POINT_free(peer_pt);
        if (ok) *out_len = want;
        return ok;
    }

    if (const int nid = ec_curve_nid(k->id); nid != NID_undef) {
        if (k->pkey == nullptr || peerlen != kex_public_size(k->id)) return false;
        EVP_PKEY* peer_key = ec_from_public(nid, std::span<const std::byte>{peer, peerlen});
        if (peer_key == nullptr) return false;
        const bool ok = evp_pkey_derive_shared(k->pkey, peer_key, out, want, out_len);
        EVP_PKEY_free(peer_key);
        return ok;
    }

    // Finite-field DH: require 1 < f < p-1 (RFC 4253 §8).
    if (k->dh == nullptr || peerlen == 0) return false;
    BIGNUM* f = BN_bin2bn(reinterpret_cast<const unsigned char*>(peer),
                          static_cast<int>(peerlen), nullptr);
    if (f == nullptr) return false;
    const BIGNUM* p = nullptr;
    DH_get0_pqg(k->dh, &p, nullptr, nullptr);
    bool ok = false;
    if (dh_peer_in_range(f, p)) {
        const int n = DH_compute_key_padded(reinterpret_cast<unsigned char*>(out), f, k->dh);
        if (n == static_cast<int>(want)) {
            *out_len = want;
            ok = true;
        }
    }
    BN_free(f);
    return ok;
}

YANTERM_SSH_ASSERT_OPENSSL_OPS(yanterm::ssh::crypto::detail::ossl1_1);

}  // namespace yanterm::ssh::crypto::detail::ossl1_1
