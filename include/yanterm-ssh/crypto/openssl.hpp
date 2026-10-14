#pragma once

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <yanterm-ssh/crypto/detail/ossl3.hpp>
namespace yanterm::ssh::crypto::detail {
namespace ossl = ossl3;
}  // namespace yanterm::ssh::crypto::detail
#else
#include <yanterm-ssh/crypto/detail/ossl1_1.hpp>
namespace yanterm::ssh::crypto::detail {
namespace ossl = ossl1_1;
}  // namespace yanterm::ssh::crypto::detail
#endif

namespace yanterm::ssh::crypto {

namespace detail {

[[nodiscard]] inline bool aead_seal_final(EVP_CIPHER_CTX* ctx, std::byte* tag_out,
                                          std::size_t taglen) noexcept {
    if (ctx == nullptr || tag_out == nullptr || taglen != 16) return false;
    unsigned char extra[EVP_MAX_BLOCK_LENGTH];
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, extra, &final_len) != 1) return false;
    if (final_len != 0) return false;
    return ossl::aead_get_tag(ctx, tag_out);
}

[[nodiscard]] inline bool aead_open_final(EVP_CIPHER_CTX* ctx, std::byte* tag,
                                          std::size_t taglen) noexcept {
    if (ctx == nullptr || tag == nullptr || taglen != 16) return false;
    if (!ossl::aead_set_tag(ctx, tag)) return false;
    unsigned char extra[EVP_MAX_BLOCK_LENGTH];
    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, extra, &final_len) != 1) return false;
    return final_len == 0;
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
        && ossl::set_rsa_pkcs1_pad(pctx)
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
    EVP_PKEY* pkey = ossl::rsa_from_public(key->a, key->b);
    if (pkey == nullptr) return false;
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX* pctx = nullptr;
    bool ok = false;
    if (mctx != nullptr
        && EVP_DigestVerifyInit(mctx, &pctx, md, nullptr, pkey) == 1
        && ossl::set_rsa_pkcs1_pad(pctx)
        && EVP_DigestVerify(mctx, reinterpret_cast<const unsigned char*>(sig->a.data()),
                            sig->a.size(), reinterpret_cast<const unsigned char*>(msg),
                            msglen) == 1) {
        ok = true;
    }
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_free(pkey);
    return ok;
}

[[nodiscard]] inline bool sm2_digest_sign_za(EVP_PKEY* pkey, const std::byte* msg,
                                             std::size_t msglen, std::byte* out, std::size_t cap,
                                             std::size_t* out_len) noexcept {
    if (pkey == nullptr || out == nullptr || out_len == nullptr) return false;
    if (msglen != 0 && msg == nullptr) return false;
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if (mctx == nullptr) return false;
    EVP_PKEY_CTX* detached = nullptr;
    bool ok = false;
    std::size_t len = cap;
    if (ossl::sm2_za_digest_init(mctx, pkey, true, &detached)
        && EVP_DigestSign(mctx, reinterpret_cast<unsigned char*>(out), &len,
                          reinterpret_cast<const unsigned char*>(msg), msglen) == 1
        && len > 0 && len <= cap) {
        *out_len = len;
        ok = true;
    }
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_CTX_free(detached);
    return ok;
}

[[nodiscard]] inline bool sm2_digest_verify_za(EVP_PKEY* pkey, const std::byte* msg,
                                               std::size_t msglen,
                                               std::span<const std::byte> r,
                                               std::span<const std::byte> s) noexcept {
    if (pkey == nullptr) return false;
    if (msglen != 0 && msg == nullptr) return false;
    unsigned char der[128];
    std::size_t der_len = 0;
    if (!ecdsa_rs_to_der(r, s, der, sizeof(der), &der_len)) return false;
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    if (mctx == nullptr) return false;
    EVP_PKEY_CTX* detached = nullptr;
    bool ok = false;
    if (ossl::sm2_za_digest_init(mctx, pkey, false, &detached)
        && EVP_DigestVerify(mctx, der, der_len,
                            reinterpret_cast<const unsigned char*>(msg), msglen) == 1) {
        ok = true;
    }
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_CTX_free(detached);
    return ok;
}

}  // namespace detail

struct openssl_backend {
    // Stateless: OpenSSL keeps its own global state. The type exists so callers
    // own an object whose lifetime bounds the provider handle.

    bool supports(primitive_kind kind, std::uint8_t id) noexcept {
        return detail::ossl::openssl_supports(kind, id);
    }

    bool random_bytes(std::byte* out, std::size_t len) noexcept {
        return RAND_bytes(reinterpret_cast<unsigned char*>(out),
                          static_cast<int>(len)) == 1;
    }

    bool constant_time_eq(const std::byte* a, const std::byte* b, std::size_t len) noexcept {
        return CRYPTO_memcmp(a, b, len) == 0;
    }

    void* hash_new(hash_id id) noexcept {
        const EVP_MD* md = detail::evp_md(id);
        if (md == nullptr) return nullptr;
        auto* h = new (std::nothrow) detail::openssl_hash{};
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
        auto* h = static_cast<detail::openssl_hash*>(ctx);
        if (h == nullptr) return;
        if (h->ctx != nullptr) EVP_MD_CTX_free(h->ctx);
        delete h;
    }

    void hash_update(void* ctx, const std::byte* in, std::size_t len) noexcept {
        auto* h = static_cast<detail::openssl_hash*>(ctx);
        EVP_DigestUpdate(h->ctx, in, len);
    }

    bool hash_final(void* ctx, std::byte* out) noexcept {
        auto* h = static_cast<detail::openssl_hash*>(ctx);
        unsigned int n = 0;
        if (EVP_DigestFinal_ex(h->ctx, reinterpret_cast<unsigned char*>(out), &n) != 1) {
            return false;
        }
        // EVP_DigestFinal_ex leaves the context unusable; re-init with the
        // cached md so the handle can hash again.
        return EVP_DigestInit_ex(h->ctx, h->md, nullptr) == 1;
    }

    void* hmac_new(hash_id id, const std::byte* key, std::size_t keylen) noexcept {
        return detail::ossl::hmac_new(id, key, keylen);
    }

    void hmac_free(void* ctx) noexcept {
        detail::ossl::hmac_free(ctx);
    }

    void hmac_update(void* ctx, const std::byte* in, std::size_t len) noexcept {
        detail::ossl::hmac_update(ctx, in, len);
    }

    bool hmac_final(void* ctx, std::byte* out) noexcept {
        return detail::ossl::hmac_final(ctx, out);
    }

    void* cipher_new(cipher_id id, const std::byte* key, std::size_t keylen,
                     bool encrypt) noexcept {
        const EVP_CIPHER* stream = detail::evp_stream_cipher(id);
        const EVP_CIPHER* cbc_evp = detail::evp_cbc_cipher(id);
        const EVP_CIPHER* c = stream != nullptr ? stream : cbc_evp;
        if (c == nullptr || keylen != cipher_key_size(id)) return nullptr;
        auto* st = new (std::nothrow) detail::openssl_cipher{};
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
        auto* st = static_cast<detail::openssl_cipher*>(ctx);
        if (st == nullptr) return;
        if (st->ctx != nullptr) EVP_CIPHER_CTX_free(st->ctx);
        delete st;
    }

    bool cipher_set_iv(void* ctx, const std::byte* iv, std::size_t ivlen) noexcept {
        auto* st = static_cast<detail::openssl_cipher*>(ctx);
        if (st == nullptr || st->ctx == nullptr || ivlen != 16) return false;
        const auto* ivp = reinterpret_cast<const unsigned char*>(iv);
        const bool cbc = detail::evp_cbc_cipher(st->id) != nullptr;
        if (cbc && !st->encrypt) {
            return EVP_DecryptInit_ex(st->ctx, nullptr, nullptr, nullptr, ivp) == 1;
        }
        return EVP_EncryptInit_ex(st->ctx, nullptr, nullptr, nullptr, ivp) == 1;
    }

    bool cipher_update(void* ctx, const std::byte* in, std::byte* out,
                       std::size_t len) noexcept {
        auto* st = static_cast<detail::openssl_cipher*>(ctx);
        if (st == nullptr || st->ctx == nullptr) return false;
        if (len == 0) return true;
        if (len > static_cast<std::size_t>(INT_MAX)) return false;
        if (detail::evp_cbc_cipher(st->id) != nullptr && len % 16u != 0) return false;
        if (detail::aead_partial_overlap(in, out, len)) return false;
        int n = 0;
        auto* outp = reinterpret_cast<unsigned char*>(out);
        const auto* inp = reinterpret_cast<const unsigned char*>(in);
        const bool cbc_dec = detail::evp_cbc_cipher(st->id) != nullptr && !st->encrypt;
        const int ok = cbc_dec
                           ? EVP_DecryptUpdate(st->ctx, outp, &n, inp, static_cast<int>(len))
                           : EVP_EncryptUpdate(st->ctx, outp, &n, inp, static_cast<int>(len));
        return ok == 1 && static_cast<std::size_t>(n) == len;
    }

    void* aead_new(cipher_id id, const std::byte* key, std::size_t keylen,
                   bool encrypt) noexcept {
        const EVP_CIPHER* c = detail::evp_aead_cipher(id);
        if (c == nullptr || keylen != cipher_key_size(id)) return nullptr;
        auto* a = new (std::nothrow) detail::openssl_aead{};
        if (a == nullptr) return nullptr;
        a->ctx = EVP_CIPHER_CTX_new();
        a->encrypt = encrypt;
        const auto* k = reinterpret_cast<const unsigned char*>(key);
        if (a->ctx == nullptr || !detail::ossl::aead_init_cipher(a->ctx, c, k, encrypt)) {
            if (a->ctx != nullptr) EVP_CIPHER_CTX_free(a->ctx);
            delete a;
            return nullptr;
        }
        return a;
    }

    void aead_free(void* ctx) noexcept {
        auto* a = static_cast<detail::openssl_aead*>(ctx);
        if (a == nullptr) return;
        if (a->ctx != nullptr) EVP_CIPHER_CTX_free(a->ctx);
        delete a;
    }

    bool aead_begin(void* ctx, const std::byte* iv, std::size_t ivlen,
                    const std::byte* aad, std::size_t aadlen) noexcept {
        auto* a = static_cast<detail::openssl_aead*>(ctx);
        return a != nullptr && detail::aead_begin(a->ctx, a->encrypt, iv, ivlen, aad, aadlen);
    }

    bool aead_update(void* ctx, const std::byte* in, std::byte* out,
                     std::size_t len) noexcept {
        auto* a = static_cast<detail::openssl_aead*>(ctx);
        return a != nullptr && detail::aead_update(a->ctx, a->encrypt, in, out, len);
    }

    bool aead_final(void* ctx, std::byte* tag, std::size_t taglen) noexcept {
        auto* a = static_cast<detail::openssl_aead*>(ctx);
        if (a == nullptr || a->ctx == nullptr) return false;
        return a->encrypt ? detail::aead_seal_final(a->ctx, tag, taglen)
                          : detail::aead_open_final(a->ctx, tag, taglen);
    }

    bool poly1305(const std::byte* key32, const std::byte* in, std::size_t len,
                  std::byte* out16) noexcept {
        return detail::ossl::poly1305(key32, in, len, out16);
    }

    void* kex_new(kex_id id) noexcept {
        auto* k = new (std::nothrow) detail::ossl::openssl_kex{};
        if (k == nullptr) return nullptr;
        k->id = id;
        const bool ok = (id == kex_id::curve25519)
                            ? ((k->pkey = detail::x25519_keygen()) != nullptr)
                            : detail::ossl::kex_init_group(k, id);
        if (!ok) {
            detail::ossl::kex_cleanup(k);
            delete k;
            return nullptr;
        }
        return k;
    }

    void kex_free(void* ctx) noexcept {
        auto* k = static_cast<detail::ossl::openssl_kex*>(ctx);
        if (k == nullptr) return;
        detail::ossl::kex_cleanup(k);
        delete k;
    }

    bool kex_public(void* ctx, std::byte* out, std::size_t cap,
                    std::size_t* out_len) noexcept {
        auto* k = static_cast<detail::ossl::openssl_kex*>(ctx);
        if (k == nullptr || out_len == nullptr) return false;
        const std::size_t want = kex_public_size(k->id);
        if (cap < want) return false;
        if (k->id == kex_id::curve25519) {
            return detail::x25519_public(k->pkey, out, want, out_len);
        }
        return detail::ossl::kex_group_public(k, out, want, out_len);
    }

    bool kex_agree(void* ctx, const std::byte* peer, std::size_t peerlen,
                   std::byte* out, std::size_t cap, std::size_t* out_len) noexcept {
        auto* k = static_cast<detail::ossl::openssl_kex*>(ctx);
        if (k == nullptr || peer == nullptr || out_len == nullptr) return false;
        const std::size_t want = kex_secret_size(k->id);
        if (cap < want) return false;
        if (k->id == kex_id::curve25519) {
            return detail::x25519_agree(k->pkey, peer, peerlen, out, want, out_len);
        }
        return detail::ossl::kex_group_agree(k, peer, peerlen, out, want, out_len);
    }

    bool sig_verify(const public_key_material* key, const std::byte* msg,
                    std::size_t msglen, const signature_material* sig) noexcept {
        if (key == nullptr || sig == nullptr) return false;
        if (msglen != 0 && msg == nullptr) return false;

        if (key->algorithm == sig_id::ed25519) {
            return detail::verify_ed25519(key->a, msg, msglen, sig->a);
        }

        if (key->algorithm == sig_id::sm2_za) {
            if (key->a.empty() || sig->a.empty() || sig->b.empty()) return false;
            EVP_PKEY* pkey = detail::ossl::ec_sig_from_public(sig_id::sm2_za, key->a);
            if (pkey == nullptr) return false;
            const bool ok = detail::sm2_digest_verify_za(pkey, msg, msglen, sig->a, sig->b);
            EVP_PKEY_free(pkey);
            return ok;
        }

        if (key->algorithm == sig_id::sm2_ecdsa) {
            if (key->a.empty() || sig->a.empty() || sig->b.empty()) return false;
            return detail::ossl::verify_sm2_ecdsa(key->a, msg, msglen, sig->a, sig->b);
        }

        if (const EVP_MD* md = detail::ecdsa_md(key->algorithm); md != nullptr) {
            if (key->a.empty() || sig->a.empty() || sig->b.empty()) return false;
            EVP_PKEY* pkey = detail::ossl::ec_sig_from_public(key->algorithm, key->a);
            if (pkey == nullptr) return false;
            const bool ok = detail::verify_ecdsa(pkey, md, msg, msglen, sig->a, sig->b);
            EVP_PKEY_free(pkey);
            return ok;
        }

        if (const EVP_MD* md = detail::rsa_md(key->algorithm); md != nullptr) {
            return detail::verify_rsa(key, md, msg, msglen, sig);
        }

        return false;
    }

    void* signing_key_new(const private_key_material* key) noexcept {
        if (key == nullptr) return nullptr;
        if (key->algorithm == sig_id::ed25519) {
            return detail::ed25519_signing_key_new(key);
        }
        if (is_sm2_sig(key->algorithm) || detail::ecdsa_md(key->algorithm) != nullptr) {
            return detail::ossl::ecdsa_signing_key_new(key);
        }
        if (detail::rsa_md(key->algorithm) != nullptr) {
            return detail::ossl::rsa_signing_key_new(key);
        }
        return nullptr;
    }

    void signing_key_free(void* handle) noexcept {
        auto* sk = static_cast<detail::openssl_signing_key*>(handle);
        if (sk == nullptr) return;
        if (sk->pkey != nullptr) EVP_PKEY_free(sk->pkey);
        delete sk;
    }

    bool sig_sign(void* handle, const std::byte* msg, std::size_t msglen,
                  std::byte* out, std::size_t cap, std::size_t* out_len) noexcept {
        auto* sk = static_cast<detail::openssl_signing_key*>(handle);
        if (sk == nullptr || sk->pkey == nullptr || out_len == nullptr) return false;
        if (msglen != 0 && msg == nullptr) return false;
        if (sk->algorithm == sig_id::ed25519) {
            return detail::sign_ed25519(sk->pkey, msg, msglen, out, cap, out_len);
        }
        if (sk->algorithm == sig_id::sm2_za) {
            return detail::sm2_digest_sign_za(sk->pkey, msg, msglen, out, cap, out_len);
        }
        if (sk->algorithm == sig_id::sm2_ecdsa) {
            return detail::ossl::sign_sm2_ecdsa(sk, msg, msglen, out, cap, out_len);
        }
        if (detail::ecdsa_md(sk->algorithm) != nullptr) {
            return detail::sign_ecdsa(sk, msg, msglen, out, cap, out_len);
        }
        if (detail::rsa_md(sk->algorithm) != nullptr) {
            return detail::sign_rsa(sk, msg, msglen, out, cap, out_len);
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
            ok = detail::generate_ed25519(out, storage, storage_cap, used);
        } else if (is_sm2_sig(id) || detail::ecdsa_md(id) != nullptr) {
            ok = detail::ossl::generate_ecdsa(id, out, storage, storage_cap, used);
        } else if (detail::rsa_md(id) != nullptr) {
            ok = detail::ossl::generate_rsa(bits, out, storage, storage_cap, used);
        }
        if (!ok) {
            *out = private_key_material{};
            *storage_used = 0;
            return false;
        }
        *storage_used = used;
        return true;
    }
};

}  // namespace yanterm::ssh::crypto
