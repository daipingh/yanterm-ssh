#pragma once

#include <yanterm-ssh/detail/config.hpp>

#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "yanterm-ssh/crypto/openssl3.hpp requires OpenSSL 3.0 or newer."
#endif

#include <yanterm-ssh/crypto/detail/ossl_common.hpp>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <openssl/params.h>

namespace yanterm::ssh::crypto::detail::ossl3 {

// EVP_MAC_CTX plus the key needed to re-initialise after EVP_MAC_final,
// so that hmac_ctx can be reused across packets without reallocating.
struct openssl_hmac {
    EVP_MAC_CTX* ctx = nullptr;
    unsigned char key[128]{};
    std::size_t key_len = 0;
};

struct openssl_kex {
    kex_id id{};
    EVP_PKEY* pkey = nullptr;
};

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

// SSH simplified GM/T 0003 KAP. Identity key = ephemeral key. is_server: client=0, server=1.
[[nodiscard]] inline bool sm2_ssh_kap(unsigned char* out, std::size_t outlen, int is_server,
                                      std::span<const std::byte> peer_pub,
                                      const EVP_PKEY* self_pkey) noexcept {
    if (out == nullptr || outlen == 0 || peer_pub.size() != 65 || self_pkey == nullptr) {
        return false;
    }
    unsigned char self_pub_oct[65];
    std::size_t self_pub_len = 0;
    if (EVP_PKEY_get_octet_string_param(self_pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, self_pub_oct,
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

// ecdh_sm2 and sm2_ecdsa need "EC" keys on the SM2 curve. Upstream OpenSSL 3.x
// only imports SM2-curve keys into the "SM2" keymgmt, which offers neither ECDH
// nor plain ECDSA; Tongsuo also accepts them in "EC".
[[nodiscard]] inline bool sm2_curve_ec_keys_available() noexcept {
    static const bool avail = []() noexcept {
        if (!sm2_primitives_available()) return false;
        EC_GROUP* g = EC_GROUP_new_by_curve_name(NID_sm2);
        unsigned char gen[65];
        const std::size_t len =
            g != nullptr ? EC_POINT_point2oct(g, EC_GROUP_get0_generator(g),
                                              POINT_CONVERSION_UNCOMPRESSED, gen, sizeof(gen),
                                              nullptr)
                         : 0;
        EC_GROUP_free(g);
        if (len != sizeof(gen)) return false;
        ERR_set_mark();
        EVP_PKEY* pkey =
            ec_from_public("EC", "SM2", std::span{reinterpret_cast<const std::byte*>(gen), len});
        ERR_pop_to_mark();
        const bool ok = pkey != nullptr;
        EVP_PKEY_free(pkey);
        return ok;
    }();
    return avail;
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
        if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, pub, sizeof(pub),
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

// Caller keeps ownership of bld.
[[nodiscard]] inline EVP_PKEY* pkey_fromdata(const char* keytype, int selection,
                                             OSSL_PARAM_BLD* bld) noexcept {
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, keytype, nullptr);
    EVP_PKEY* pkey = nullptr;
    if (params == nullptr || ctx == nullptr || EVP_PKEY_fromdata_init(ctx) != 1
        || EVP_PKEY_fromdata(ctx, &pkey, selection, params) != 1) {
        EVP_PKEY_free(pkey);
        pkey = nullptr;
    }
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    return pkey;
}

// Derives uncompressed EC public point bytes from private scalar d on curve nid.
[[nodiscard]] inline std::size_t ec_derive_uncompressed_pub(int nid, const BIGNUM* d,
                                                            unsigned char* out,
                                                            std::size_t cap) noexcept {
    if (nid == NID_undef || d == nullptr || out == nullptr) return 0;
    EC_GROUP* group = EC_GROUP_new_by_curve_name(nid);
    EC_POINT* point = group != nullptr ? EC_POINT_new(group) : nullptr;
    std::size_t pub_len = 0;
    if (group != nullptr && point != nullptr
        && EC_POINT_mul(group, point, d, nullptr, nullptr, nullptr) == 1) {
        pub_len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                                     out, cap, nullptr);
    }
    EC_POINT_free(point);
    EC_GROUP_free(group);
    return pub_len;
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
    EVP_PKEY* pkey = nullptr;
    if (pub_ptr != nullptr && bld != nullptr
        && OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, group_name, 0) == 1
        && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, d) == 1
        && OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pub_ptr, pub_len) == 1) {
        pkey = pkey_fromdata(ec_sig_keytype(key->algorithm), EVP_PKEY_KEYPAIR, bld);
    }
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
        pkey = pkey_fromdata("RSA", EVP_PKEY_KEYPAIR, bld);
    }

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
    EVP_PKEY* pkey = nullptr;
    if (n != nullptr && e != nullptr && bld != nullptr
        && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) == 1
        && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e) == 1) {
        pkey = pkey_fromdata("RSA", EVP_PKEY_PUBLIC_KEY, bld);
    }
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

[[nodiscard]] inline bool sign_rsa(openssl_signing_key* sk, const std::byte* msg,
                                   std::size_t msglen, std::byte* out, std::size_t cap,
                                   std::size_t* out_len) noexcept {
    const EVP_MD* md = rsa_md(sk->algorithm);
    if (md == nullptr || sk->pkey == nullptr) return false;
    const int rsa_bytes = EVP_PKEY_size(sk->pkey);
    if (rsa_bytes <= 0 || cap < static_cast<std::size_t>(rsa_bytes)) return false;
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if (mctx == nullptr) return false;
    EVP_PKEY_CTX* pctx = nullptr;
    std::size_t siglen = cap;
    bool ok = false;
    if (EVP_DigestSignInit(mctx, &pctx, md, nullptr, sk->pkey) == 1
        && set_rsa_pkcs1_pad(pctx)
        && EVP_DigestSign(mctx, reinterpret_cast<unsigned char*>(out), &siglen,
                          reinterpret_cast<const unsigned char*>(msg), msglen) == 1
        && siglen == static_cast<std::size_t>(rsa_bytes)) {
        *out_len = siglen;
        ok = true;
    }
    EVP_MD_CTX_free(mctx);
    return ok;
}

[[nodiscard]] inline bool verify_rsa(const public_key_material* key, const EVP_MD* md,
                                     const std::byte* msg, std::size_t msglen,
                                     const signature_material* sig) noexcept {
    if (key->a.empty() || key->b.empty() || sig->a.empty()) return false;
    EVP_PKEY* pkey = rsa_from_public(key->a, key->b);
    if (pkey == nullptr) return false;
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx = nullptr;
    bool ok = false;
    if (mctx != nullptr
        && EVP_DigestVerifyInit(mctx, &pctx, md, nullptr, pkey) == 1
        && set_rsa_pkcs1_pad(pctx)
        && EVP_DigestVerify(mctx, reinterpret_cast<const unsigned char*>(sig->a.data()),
                            sig->a.size(), reinterpret_cast<const unsigned char*>(msg),
                            msglen) == 1) {
        ok = true;
    }
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return ok;
}

// The SM2 keymgmt prepends Z_A with the default distinguishing ID itself.
[[nodiscard]] inline bool sign_sm2_za(EVP_PKEY* pkey, const std::byte* msg, std::size_t msglen,
                                      std::byte* out, std::size_t cap,
                                      std::size_t* out_len) noexcept {
    if (pkey == nullptr || out == nullptr || out_len == nullptr) return false;
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if (mctx == nullptr) return false;
    bool ok = false;
    std::size_t len = cap;
    if (EVP_DigestSignInit(mctx, nullptr, EVP_sm3(), nullptr, pkey) == 1
        && EVP_DigestSign(mctx, reinterpret_cast<unsigned char*>(out), &len,
                          reinterpret_cast<const unsigned char*>(msg), msglen) == 1
        && len > 0 && len <= cap) {
        *out_len = len;
        ok = true;
    }
    EVP_MD_CTX_free(mctx);
    return ok;
}

// Finite-field DH: require 1 < f < p-1 (RFC 4253 §8).
[[nodiscard]] inline bool dh_agree(const openssl_kex* k, const std::byte* peer,
                                   std::size_t peerlen, std::byte* out, std::size_t want,
                                   std::size_t* out_len) noexcept {
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
    EVP_PKEY* peer_key = nullptr;
    EVP_PKEY_CTX* dctx = nullptr;
    bool ok = false;
    if (dh_peer_in_range(f, p)) {
        bld = OSSL_PARAM_BLD_new();
        if (bld != nullptr
            && OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, dh_group, 0) == 1
            && OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PUB_KEY, f) == 1) {
            peer_key = pkey_fromdata("DH", EVP_PKEY_PUBLIC_KEY, bld);
            if (peer_key != nullptr) {
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
    OSSL_PARAM_BLD_free(bld);
    BN_free(p);
    BN_free(f);
    return ok;
}

// Upstream OpenSSL 3.x offers neither ecgm-sm2-sm3 nor sm2_ecdsa here; see
// ossl1_1::openssl_backend.
struct openssl_backend : openssl_backend_base {
    bool supports(primitive_kind kind, std::uint8_t id) noexcept {
        if ((kind == primitive_kind::kex && static_cast<kex_id>(id) == kex_id::ecdh_sm2)
            || (kind == primitive_kind::signature
                && static_cast<sig_id>(id) == sig_id::sm2_ecdsa)) {
            return sm2_curve_ec_keys_available();
        }
        return openssl_supports_common(sm2_primitives_available(), kind, id);
    }

    void* hmac_new(hash_id id, const std::byte* key, std::size_t keylen) noexcept {
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
            OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, const_cast<char*>(md_name),
                                             0),
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

    void hmac_free(void* ctx) noexcept {
        auto* h = static_cast<openssl_hmac*>(ctx);
        if (h == nullptr) return;
        if (h->ctx != nullptr) EVP_MAC_CTX_free(h->ctx);
        OPENSSL_cleanse(h->key, sizeof(h->key));
        delete h;
    }

    void hmac_update(void* ctx, const std::byte* in, std::size_t len) noexcept {
        auto* h = static_cast<openssl_hmac*>(ctx);
        EVP_MAC_update(h->ctx, reinterpret_cast<const unsigned char*>(in), len);
    }

    bool hmac_final(void* ctx, std::byte* out) noexcept {
        auto* h = static_cast<openssl_hmac*>(ctx);
        std::size_t n = 0;
        if (EVP_MAC_final(h->ctx, reinterpret_cast<unsigned char*>(out), &n, EVP_MAX_MD_SIZE)
            != 1) {
            return false;
        }
        return EVP_MAC_init(h->ctx, h->key, h->key_len, nullptr) == 1;
    }

    void* aead_new(cipher_id id, const std::byte* key, std::size_t keylen,
                   bool encrypt) noexcept {
        const EVP_CIPHER* c = evp_aead_cipher(id);
        if (c == nullptr || key == nullptr || keylen != cipher_key_size(id)) return nullptr;
        auto* a = new (std::nothrow) openssl_aead{};
        if (a == nullptr) return nullptr;
        a->ctx = EVP_CIPHER_CTX_new();
        a->encrypt = encrypt;
        const auto* k = reinterpret_cast<const unsigned char*>(key);
        std::size_t ivlen = 12;
        OSSL_PARAM params[2] = {
            OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN, &ivlen),
            OSSL_PARAM_construct_end(),
        };
        if (a->ctx == nullptr
            || (encrypt ? EVP_EncryptInit_ex2(a->ctx, c, k, nullptr, params)
                        : EVP_DecryptInit_ex2(a->ctx, c, k, nullptr, params)) != 1) {
            if (a->ctx != nullptr) EVP_CIPHER_CTX_free(a->ctx);
            delete a;
            return nullptr;
        }
        return a;
    }

    bool aead_final(void* ctx, std::byte* tag, std::size_t taglen) noexcept {
        auto* a = static_cast<openssl_aead*>(ctx);
        if (a == nullptr || a->ctx == nullptr || tag == nullptr || taglen != 16) return false;
        OSSL_PARAM params[2] = {
            OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag, 16),
            OSSL_PARAM_construct_end(),
        };
        unsigned char extra[EVP_MAX_BLOCK_LENGTH];
        int final_len = 0;
        if (a->encrypt) {
            return EVP_EncryptFinal_ex(a->ctx, extra, &final_len) == 1 && final_len == 0
                   && EVP_CIPHER_CTX_get_params(a->ctx, params) == 1;
        }
        return EVP_CIPHER_CTX_set_params(a->ctx, params) == 1
               && EVP_DecryptFinal_ex(a->ctx, extra, &final_len) == 1 && final_len == 0;
    }

    bool poly1305(const std::byte* key32, const std::byte* in, std::size_t len,
                  std::byte* out16) noexcept {
        if (key32 == nullptr || out16 == nullptr || (len != 0 && in == nullptr)) return false;
        EVP_MAC* mac = EVP_MAC_fetch(nullptr, "POLY1305", nullptr);
        if (mac == nullptr) return false;
        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
        EVP_MAC_free(mac);
        if (ctx == nullptr) return false;
        std::size_t outlen = 0;
        const bool ok =
            EVP_MAC_init(ctx, reinterpret_cast<const unsigned char*>(key32), 32, nullptr) == 1
            && EVP_MAC_update(ctx, reinterpret_cast<const unsigned char*>(in), len) == 1
            && EVP_MAC_final(ctx, reinterpret_cast<unsigned char*>(out16), &outlen, 16) == 1
            && outlen == 16;
        EVP_MAC_CTX_free(ctx);
        return ok;
    }

    void* kex_new(kex_id id) noexcept {
        auto* k = new (std::nothrow) openssl_kex{};
        if (k == nullptr) return nullptr;
        k->id = id;
        if (id == kex_id::curve25519) {
            k->pkey = x25519_keygen();
        } else if (const char* group = ec_kex_group_name(id); group != nullptr) {
            // Plain ecdh_sm2 MUST use key type "EC" so Tongsuo does not dispatch to SM2DH.
            k->pkey = ec_keygen("EC", group);
        } else if (const char* dh_group = dh_kex_group_name(id); dh_group != nullptr) {
            EVP_PKEY_CTX* c = EVP_PKEY_CTX_new_from_name(nullptr, "DH", nullptr);
            OSSL_PARAM params[2] = {
                OSSL_PARAM_construct_utf8_string(
                    OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char*>(dh_group), 0),
                OSSL_PARAM_construct_end(),
            };
            if (c == nullptr || EVP_PKEY_keygen_init(c) != 1
                || EVP_PKEY_CTX_set_params(c, params) != 1
                || EVP_PKEY_generate(c, &k->pkey) != 1) {
                EVP_PKEY_free(k->pkey);
                k->pkey = nullptr;
            }
            EVP_PKEY_CTX_free(c);
        }
        if (k->pkey == nullptr) {
            delete k;
            return nullptr;
        }
        return k;
    }

    void kex_free(void* ctx) noexcept {
        auto* k = static_cast<openssl_kex*>(ctx);
        if (k == nullptr) return;
        if (k->pkey != nullptr) EVP_PKEY_free(k->pkey);
        delete k;
    }

    bool kex_public(void* ctx, std::byte* out, std::size_t cap,
                    std::size_t* out_len) noexcept {
        auto* k = static_cast<openssl_kex*>(ctx);
        if (k == nullptr || k->pkey == nullptr || out_len == nullptr) return false;
        const std::size_t want = kex_public_size(k->id);
        if (cap < want) return false;
        if (k->id == kex_id::curve25519) {
            return x25519_public(k->pkey, out, want, out_len);
        }
        if (ec_kex_group_name(k->id) != nullptr) {
            std::size_t len = 0;
            if (EVP_PKEY_get_octet_string_param(
                    k->pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
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

    bool kex_agree(void* ctx, const std::byte* peer, std::size_t peerlen,
                   std::byte* out, std::size_t cap, std::size_t* out_len) noexcept {
        auto* k = static_cast<openssl_kex*>(ctx);
        if (k == nullptr || k->pkey == nullptr || peer == nullptr || out_len == nullptr) {
            return false;
        }
        const std::size_t want = kex_secret_size(k->id);
        if (cap < want) return false;
        if (k->id == kex_id::curve25519) {
            return x25519_agree(k->pkey, peer, peerlen, out, want, out_len);
        }
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
            EVP_PKEY* peer_key =
                ec_from_public("EC", group, std::span<const std::byte>{peer, peerlen});
            if (peer_key == nullptr) return false;
            const bool ok = evp_pkey_derive_shared(k->pkey, peer_key, out, want, out_len);
            EVP_PKEY_free(peer_key);
            return ok;
        }
        return dh_agree(k, peer, peerlen, out, want, out_len);
    }

    bool sig_verify(const public_key_material* key, const std::byte* msg,
                    std::size_t msglen, const signature_material* sig) noexcept {
        if (key == nullptr || sig == nullptr) return false;
        if (msglen != 0 && msg == nullptr) return false;

        if (key->algorithm == sig_id::ed25519) {
            return verify_ed25519(key->a, msg, msglen, sig->a);
        }

        // sm2_za keys live in the "SM2" keymgmt, which prepends Z_A itself.
        const EVP_MD* ec_md =
            key->algorithm == sig_id::sm2_za ? EVP_sm3() : ecdsa_md(key->algorithm);
        if (ec_md != nullptr) {
            if (key->a.empty() || sig->a.empty() || sig->b.empty()) return false;
            EVP_PKEY* pkey = ec_from_public(ec_sig_keytype(key->algorithm),
                                            ec_sig_group_name(key->algorithm), key->a);
            if (pkey == nullptr) return false;
            const bool ok = verify_ecdsa(pkey, ec_md, msg, msglen, sig->a, sig->b);
            EVP_PKEY_free(pkey);
            return ok;
        }

        if (const EVP_MD* md = rsa_md(key->algorithm); md != nullptr) {
            return verify_rsa(key, md, msg, msglen, sig);
        }

        return false;
    }

    void* signing_key_new(const private_key_material* key) noexcept {
        if (key == nullptr) return nullptr;
        if (key->algorithm == sig_id::ed25519) {
            return ed25519_signing_key_new(key);
        }
        if (is_sm2_sig(key->algorithm) || ecdsa_md(key->algorithm) != nullptr) {
            return ecdsa_signing_key_new(key);
        }
        if (rsa_md(key->algorithm) != nullptr) {
            return rsa_signing_key_new(key);
        }
        return nullptr;
    }

    bool sig_sign(void* handle, const std::byte* msg, std::size_t msglen,
                  std::byte* out, std::size_t cap, std::size_t* out_len) noexcept {
        auto* sk = static_cast<openssl_signing_key*>(handle);
        if (sk == nullptr || sk->pkey == nullptr || out_len == nullptr) return false;
        if (msglen != 0 && msg == nullptr) return false;
        if (sk->algorithm == sig_id::ed25519) {
            return sign_ed25519(sk->pkey, msg, msglen, out, cap, out_len);
        }
        if (sk->algorithm == sig_id::sm2_za) {
            return sign_sm2_za(sk->pkey, msg, msglen, out, cap, out_len);
        }
        if (ecdsa_md(sk->algorithm) != nullptr) {
            return sign_ecdsa(sk, msg, msglen, out, cap, out_len);
        }
        if (rsa_md(sk->algorithm) != nullptr) {
            return sign_rsa(sk, msg, msglen, out, cap, out_len);
        }
        return false;
    }

    bool generate_keypair(sig_id id, std::uint32_t bits, private_key_material* out,
                          std::byte* storage, std::size_t storage_cap,
                          std::size_t* storage_used) noexcept {
        if (out == nullptr || storage == nullptr || storage_used == nullptr) return false;
        *out = private_key_material{};
        out->algorithm = id;
        *storage_used = 0;
        std::size_t used = 0;
        bool ok = false;
        if (id == sig_id::ed25519) {
            ok = generate_ed25519(out, storage, storage_cap, used);
        } else if (is_sm2_sig(id) || ecdsa_md(id) != nullptr) {
            ok = generate_ecdsa(id, out, storage, storage_cap, used);
        } else if (rsa_md(id) != nullptr) {
            ok = generate_rsa(bits, out, storage, storage_cap, used);
        }
        if (!ok) {
            OPENSSL_cleanse(storage, storage_cap);
            *out = private_key_material{};
            *storage_used = 0;
            return false;
        }
        *storage_used = used;
        return true;
    }
};

}  // namespace yanterm::ssh::crypto::detail::ossl3

namespace yanterm::ssh::crypto::ossl3 {

using openssl_backend = detail::ossl3::openssl_backend;

}  // namespace yanterm::ssh::crypto::ossl3
