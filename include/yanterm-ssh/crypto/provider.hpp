#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/crypto/algorithms.hpp>
#include <yanterm-ssh/detail/error.hpp>

#include <cstddef>
#include <span>
#include <utility>

namespace yanterm::ssh::crypto {

// Plain-old-data vtable plus a type-erased self pointer, mirroring the shape of
// auv::stream. Every entry is noexcept and reports failure by return value; the
// protocol core never sees an exception from a backend.
struct provider_vtable {
    // --- capability -------------------------------------------------------
    bool (*supports)(void* self, primitive_kind kind, std::uint8_t id) noexcept;

    // --- utility ----------------------------------------------------------
    bool (*random_bytes)(void* self, std::byte* out, std::size_t len) noexcept;
    bool (*constant_time_eq)(void* self, const std::byte* a, const std::byte* b,
                             std::size_t len) noexcept;

    // --- hash -------------------------------------------------------------
    void* (*hash_new)(void* self, hash_id id) noexcept;                // nullptr on failure
    void  (*hash_free)(void* self, void* ctx) noexcept;
    void  (*hash_update)(void* self, void* ctx, const std::byte* in, std::size_t len) noexcept;
    // Writes hash_output_size(id) bytes and resets the context for reuse.
    bool  (*hash_final)(void* self, void* ctx, std::byte* out) noexcept;

    // --- hmac -------------------------------------------------------------
    void* (*hmac_new)(void* self, hash_id id, const std::byte* key, std::size_t keylen) noexcept;
    void  (*hmac_free)(void* self, void* ctx) noexcept;
    void  (*hmac_update)(void* self, void* ctx, const std::byte* in, std::size_t len) noexcept;
    bool  (*hmac_final)(void* self, void* ctx, std::byte* out) noexcept;

    // --- cipher (AES-CTR, ChaCha20, AES-CBC) --------------------------------
    void* (*cipher_new)(void* self, cipher_id id, const std::byte* key, std::size_t keylen,
                        bool encrypt) noexcept;
    void  (*cipher_free)(void* self, void* ctx) noexcept;
    bool  (*cipher_set_iv)(void* self, void* ctx, const std::byte* iv, std::size_t ivlen) noexcept;
    // Equal-length. len==0 is a success no-op. Exact in==out allowed; partial
    // overlap forbidden. CBC requires len % block == 0.
    bool  (*cipher_update)(void* self, void* ctx, const std::byte* in, std::byte* out,
                           std::size_t len) noexcept;

    // --- AEAD (AES-GCM), incremental-only ---------------------------------
    // encrypt is fixed at new. begin starts one packet (IV+AAD). final: if the
    // handle was created with encrypt==true, writes tag; otherwise reads tag
    // and verifies. tag is never const. Open plaintext is unauthenticated
    // until final succeeds. After any failed begin/update/final, begin again
    // before further update/final.
    void* (*aead_new)(void* self, cipher_id id, const std::byte* key, std::size_t keylen,
                      bool encrypt) noexcept;
    void  (*aead_free)(void* self, void* ctx) noexcept;
    bool  (*aead_begin)(void* self, void* ctx,
                        const std::byte* iv, std::size_t ivlen,
                        const std::byte* aad, std::size_t aadlen) noexcept;
    bool  (*aead_update)(void* self, void* ctx,
                         const std::byte* in, std::byte* out, std::size_t len) noexcept;
    bool  (*aead_final)(void* self, void* ctx,
                        std::byte* tag, std::size_t taglen) noexcept;

    // --- one-shot MAC (Poly1305) ------------------------------------------
    bool (*poly1305)(void* self, const std::byte* key32,
                     const std::byte* in, std::size_t len, std::byte* out16) noexcept;

    // --- key agreement ----------------------------------------------------
    // Generates an ephemeral keypair. All randomness comes from this provider.
    void* (*kex_new)(void* self, kex_id id) noexcept;
    void  (*kex_free)(void* self, void* ctx) noexcept;
    bool  (*kex_public)(void* self, void* ctx, std::byte* out, std::size_t cap,
                        std::size_t* out_len) noexcept;
    // Produces the raw shared secret: X25519 output, the x-coordinate for NIST
    // ECDH, or the big-endian modular exponentiation result for finite-field DH.
    bool  (*kex_agree)(void* self, void* ctx, const std::byte* peer, std::size_t peerlen,
                       std::byte* out, std::size_t cap, std::size_t* out_len) noexcept;

    // --- signatures -------------------------------------------------------
    bool (*sig_verify)(void* self, const public_key_material* key,
                       const std::byte* msg, std::size_t msglen,
                       const signature_material* sig) noexcept;
    void* (*signing_key_new)(void* self, const private_key_material* key) noexcept;
    void  (*signing_key_free)(void* self, void* handle) noexcept;
    bool  (*sig_sign)(void* self, void* handle, const std::byte* msg, std::size_t msglen,
                      std::byte* out, std::size_t cap, std::size_t* out_len) noexcept;

    // Writes field bytes into `storage` and points `out` spans at them.
    // `bits` is 0 for default (ed25519/ecdsa ignore; rsa → 3072).
    bool (*generate_keypair)(void* self, sig_id id, std::uint32_t bits,
                             private_key_material* out,
                             std::byte* storage, std::size_t storage_cap,
                             std::size_t* storage_used) noexcept;

    // --- key encapsulation ------------------------------------------------
    // kem_new generates a decapsulation keypair (nullptr on failure); all
    // randomness comes from this provider.
    void* (*kem_new)(void* self, kem_id id) noexcept;
    // Frees the keypair and wipes its private part.
    void  (*kem_free)(void* self, void* ctx) noexcept;
    // Writes the encoded encapsulation key; false if cap is too small.
    bool  (*kem_public)(void* self, void* ctx, std::byte* out, std::size_t cap,
                        std::size_t* out_len) noexcept;
    // FIPS 203 implicit rejection: a ciphertext of the right length always
    // decapsulates, a tampered one to an unrelated secret.
    bool  (*kem_decaps)(void* self, void* ctx, const std::byte* ct, std::size_t ctlen,
                        std::byte* ss, std::size_t cap, std::size_t* ss_len) noexcept;
    // Stateless. Must run the FIPS 203 section 7.2 encapsulation key check and
    // fail when it does not pass.
    bool  (*kem_encaps)(void* self, kem_id id, const std::byte* pub, std::size_t publen,
                        std::byte* ct, std::size_t ctcap, std::size_t* ct_len,
                        std::byte* ss, std::size_t sscap, std::size_t* ss_len) noexcept;
};

class provider;

namespace detail {

// Common RAII shell for the opaque context handles below.
template <class Tag>
class handle {
public:
    handle() = default;
    handle(const provider_vtable* vt, void* self, void* ctx) noexcept
        : vt_{vt}, self_{self}, ctx_{ctx} {}

    handle(const handle&) = delete;
    handle& operator=(const handle&) = delete;

    handle(handle&& other) noexcept
        : vt_{other.vt_}, self_{other.self_}, ctx_{std::exchange(other.ctx_, nullptr)} {}

    handle& operator=(handle&& other) noexcept {
        if (this != &other) {
            reset();
            vt_ = other.vt_;
            self_ = other.self_;
            ctx_ = std::exchange(other.ctx_, nullptr);
        }
        return *this;
    }

    ~handle() { reset(); }

    [[nodiscard]] explicit operator bool() const noexcept { return ctx_ != nullptr; }
    [[nodiscard]] void* get() const noexcept { return ctx_; }

    void reset() noexcept {
        if (ctx_ != nullptr) {
            Tag::destroy(vt_, self_, ctx_);
            ctx_ = nullptr;
        }
    }

protected:
    const provider_vtable* vt_ = nullptr;
    void* self_ = nullptr;
    void* ctx_ = nullptr;
};

struct hash_tag {
    static void destroy(const provider_vtable* vt, void* self, void* ctx) noexcept {
        vt->hash_free(self, ctx);
    }
};
struct hmac_tag {
    static void destroy(const provider_vtable* vt, void* self, void* ctx) noexcept {
        vt->hmac_free(self, ctx);
    }
};
struct cipher_tag {
    static void destroy(const provider_vtable* vt, void* self, void* ctx) noexcept {
        vt->cipher_free(self, ctx);
    }
};
struct aead_tag {
    static void destroy(const provider_vtable* vt, void* self, void* ctx) noexcept {
        vt->aead_free(self, ctx);
    }
};
struct kex_tag {
    static void destroy(const provider_vtable* vt, void* self, void* ctx) noexcept {
        vt->kex_free(self, ctx);
    }
};
struct kem_tag {
    static void destroy(const provider_vtable* vt, void* self, void* ctx) noexcept {
        vt->kem_free(self, ctx);
    }
};
struct signing_key_tag {
    static void destroy(const provider_vtable* vt, void* self, void* ctx) noexcept {
        vt->signing_key_free(self, ctx);
    }
};

}  // namespace detail

class hash_ctx : public detail::handle<detail::hash_tag> {
public:
    using handle::handle;

    void update(std::span<const std::byte> in) noexcept {
        vt_->hash_update(self_, ctx_, in.data(), in.size());
    }
    // Writes exactly hash_output_size(id) bytes and resets for reuse.
    [[nodiscard]] bool final_into(std::span<std::byte> out) noexcept {
        return vt_->hash_final(self_, ctx_, out.data());
    }
};

class hmac_ctx : public detail::handle<detail::hmac_tag> {
public:
    using handle::handle;

    void update(std::span<const std::byte> in) noexcept {
        vt_->hmac_update(self_, ctx_, in.data(), in.size());
    }
    [[nodiscard]] bool final_into(std::span<std::byte> out) noexcept {
        return vt_->hmac_final(self_, ctx_, out.data());
    }
};

class cipher : public detail::handle<detail::cipher_tag> {
public:
    using handle::handle;

    [[nodiscard]] bool set_iv(std::span<const std::byte> iv) noexcept {
        return vt_->cipher_set_iv(self_, ctx_, iv.data(), iv.size());
    }
    [[nodiscard]] bool update(std::span<const std::byte> in, std::span<std::byte> out) noexcept {
        if (out.size() < in.size()) return false;
        return vt_->cipher_update(self_, ctx_, in.data(), out.data(), in.size());
    }
};

class aead_cipher : public detail::handle<detail::aead_tag> {
public:
    using handle::handle;

    [[nodiscard]] bool begin(std::span<const std::byte> iv,
                             std::span<const std::byte> aad) noexcept {
        return vt_->aead_begin(self_, ctx_, iv.data(), iv.size(), aad.data(), aad.size());
    }
    [[nodiscard]] bool update(std::span<const std::byte> in, std::span<std::byte> out) noexcept {
        if (out.size() < in.size()) return false;
        return vt_->aead_update(self_, ctx_, in.data(), out.data(), in.size());
    }
    [[nodiscard]] bool final(std::span<std::byte> tag) noexcept {
        return vt_->aead_final(self_, ctx_, tag.data(), tag.size());
    }
};

class kex_agreement : public detail::handle<detail::kex_tag> {
public:
    using handle::handle;

    [[nodiscard]] bool public_value(std::span<std::byte> out, std::size_t& len) noexcept {
        return vt_->kex_public(self_, ctx_, out.data(), out.size(), &len);
    }
    [[nodiscard]] bool agree(std::span<const std::byte> peer, std::span<std::byte> out,
                             std::size_t& len) noexcept {
        return vt_->kex_agree(self_, ctx_, peer.data(), peer.size(), out.data(), out.size(), &len);
    }
};

class signing_key : public detail::handle<detail::signing_key_tag> {
public:
    using handle::handle;

    [[nodiscard]] bool sign(std::span<const std::byte> msg, std::span<std::byte> out,
                            std::size_t& len) noexcept {
        return vt_->sig_sign(self_, ctx_, msg.data(), msg.size(), out.data(), out.size(), &len);
    }
};

// Decapsulation side of a KEM: owns the private key from provider::new_kem.
class kem_keypair : public detail::handle<detail::kem_tag> {
public:
    using handle::handle;

    [[nodiscard]] bool public_key(std::span<std::byte> out, std::size_t& len) noexcept {
        return vt_->kem_public(self_, ctx_, out.data(), out.size(), &len);
    }
    [[nodiscard]] bool decapsulate(std::span<const std::byte> ct, std::span<std::byte> ss,
                                   std::size_t& len) noexcept {
        return vt_->kem_decaps(self_, ctx_, ct.data(), ct.size(), ss.data(), ss.size(), &len);
    }
};

namespace detail_adapt {
template <class T>
struct decorate_thunks;
}

// Non-owning handle to a crypto backend. Copyable and cheap; the backend's
// lifetime is owned by whoever created it.
class provider {
public:
    provider() = default;
    provider(const provider_vtable* vt, void* self) noexcept : vt_{vt}, self_{self} {}

    template <class T>
    [[nodiscard]] static provider wrap(T& backend) noexcept;
    template <class T>
    [[nodiscard]] static provider decorate(T& overlay) noexcept;

    [[nodiscard]] explicit operator bool() const noexcept { return vt_ != nullptr; }

    [[nodiscard]] bool supports(hash_id id) const noexcept { return sup(primitive_kind::hash, id); }
    [[nodiscard]] bool supports(cipher_id id) const noexcept { return sup(primitive_kind::cipher, id); }
    [[nodiscard]] bool supports(mac_id id) const noexcept { return sup(primitive_kind::mac, id); }
    [[nodiscard]] bool supports(kex_id id) const noexcept {
        if (id == kex_id::mlkem768x25519) {
            return supports(kem_id::mlkem768) && supports(kex_id::curve25519);
        }
        return sup(primitive_kind::kex, id);
    }
    [[nodiscard]] bool supports(sig_id id) const noexcept { return sup(primitive_kind::signature, id); }
    // True only when the backend fills the whole kem group and reports the id.
    [[nodiscard]] bool supports(kem_id id) const noexcept {
        return has_kem() && sup(primitive_kind::kem, id);
    }

    [[nodiscard]] std::error_code random_bytes(std::span<std::byte> out) const noexcept {
        if (!vt_ || vt_->random_bytes == nullptr) {
            return code::crypto_backend_failure;
        }
        return vt_->random_bytes(self_, out.data(), out.size())
                   ? std::error_code{}
                   : code::random_failure;
    }

    [[nodiscard]] bool constant_time_eq(std::span<const std::byte> a,
                                        std::span<const std::byte> b) const noexcept {
        if (a.size() != b.size()) return false;
        return vt_->constant_time_eq(self_, a.data(), b.data(), a.size());
    }

    [[nodiscard]] hash_ctx new_hash(hash_id id) const noexcept {
        if (!vt_ || vt_->hash_new == nullptr) return {};
        return {vt_, self_, vt_->hash_new(self_, id)};
    }
    [[nodiscard]] hmac_ctx new_hmac(hash_id id, std::span<const std::byte> key) const noexcept {
        if (!vt_ || vt_->hmac_new == nullptr) return {};
        return {vt_, self_, vt_->hmac_new(self_, id, key.data(), key.size())};
    }
    [[nodiscard]] cipher new_cipher(cipher_id id, std::span<const std::byte> key,
                                    bool encrypt) const noexcept {
        if (!vt_ || vt_->cipher_new == nullptr) return {};
        return {vt_, self_, vt_->cipher_new(self_, id, key.data(), key.size(), encrypt)};
    }
    [[nodiscard]] aead_cipher new_aead(cipher_id id, std::span<const std::byte> key,
                                       bool encrypt) const noexcept {
        if (!vt_ || vt_->aead_new == nullptr) return {};
        return {vt_, self_, vt_->aead_new(self_, id, key.data(), key.size(), encrypt)};
    }
    [[nodiscard]] kex_agreement new_kex(kex_id id) const noexcept {
        if (!vt_ || vt_->kex_new == nullptr) return {};
        return {vt_, self_, vt_->kex_new(self_, id)};
    }
    [[nodiscard]] kem_keypair new_kem(kem_id id) const noexcept {
        if (!has_kem()) return {};
        return {vt_, self_, vt_->kem_new(self_, id)};
    }
    [[nodiscard]] bool encapsulate(kem_id id, std::span<const std::byte> pub,
                                   std::span<std::byte> ct, std::size_t& ct_len,
                                   std::span<std::byte> ss, std::size_t& ss_len) const noexcept {
        if (!has_kem()) return false;
        return vt_->kem_encaps(self_, id, pub.data(), pub.size(), ct.data(), ct.size(), &ct_len,
                               ss.data(), ss.size(), &ss_len);
    }
    [[nodiscard]] signing_key new_signing_key(const private_key_material& key) const noexcept {
        if (!vt_ || vt_->signing_key_new == nullptr) return {};
        return {vt_, self_, vt_->signing_key_new(self_, &key)};
    }

    [[nodiscard]] bool poly1305(std::span<const std::byte> key32, std::span<const std::byte> in,
                                std::span<std::byte> out16) const noexcept {
        if (key32.size() != 32 || out16.size() < 16) return false;
        if (!vt_ || vt_->poly1305 == nullptr) return false;
        return vt_->poly1305(self_, key32.data(), in.data(), in.size(), out16.data());
    }

    [[nodiscard]] bool verify(const public_key_material& key, std::span<const std::byte> msg,
                              const signature_material& sig) const noexcept {
        if (!vt_ || vt_->sig_verify == nullptr) return false;
        return vt_->sig_verify(self_, &key, msg.data(), msg.size(), &sig);
    }

    [[nodiscard]] bool cbc_crypt(cipher_id id, bool encrypt,
                                 std::span<const std::byte> key,
                                 std::span<const std::byte> iv,
                                 std::span<const std::byte> in,
                                 std::span<std::byte> out) const noexcept {
        if (out.size() < in.size()) return false;
        cipher c = new_cipher(id, key, encrypt);
        if (!c || !c.set_iv(iv)) return false;
        return c.update(in, out);
    }

    [[nodiscard]] bool generate_keypair(sig_id id, std::uint32_t bits,
                                        private_key_material& out,
                                        std::span<std::byte> storage) const noexcept {
        if (!vt_ || vt_->generate_keypair == nullptr) return false;
        std::size_t used = 0;
        if (!vt_->generate_keypair(self_, id, bits, &out, storage.data(),
                                   storage.size(), &used)) {
            return false;
        }
        return used <= storage.size();
    }

    // One-shot hash into `out`, which must be at least hash_output_size(id) bytes.
    [[nodiscard]] bool hash(hash_id id, std::span<const std::byte> in,
                            std::span<std::byte> out) const noexcept {
        hash_ctx h = new_hash(id);
        if (!h) return false;
        h.update(in);
        return h.final_into(out);
    }

private:
    template <class T>
    friend struct detail_adapt::decorate_thunks;

    // Type-erased backend; decorate() forwards unoverridden slots through these.
    [[nodiscard]] const provider_vtable* vtable() const noexcept { return vt_; }
    [[nodiscard]] void* self_ptr() const noexcept { return self_; }

    [[nodiscard]] bool has_kem() const noexcept {
        return vt_ != nullptr && vt_->kem_new != nullptr && vt_->kem_free != nullptr
               && vt_->kem_public != nullptr && vt_->kem_decaps != nullptr
               && vt_->kem_encaps != nullptr;
    }

    template <class Id>
    [[nodiscard]] bool sup(primitive_kind kind, Id id) const noexcept {
        return vt_ != nullptr && vt_->supports(self_, kind, static_cast<std::uint8_t>(id));
    }

    const provider_vtable* vt_ = nullptr;
    void* self_ = nullptr;
};

}  // namespace yanterm::ssh::crypto

#include <yanterm-ssh/crypto/detail/provider_adapt.hpp>
