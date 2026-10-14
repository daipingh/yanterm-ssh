#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/crypto/provider.hpp>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <type_traits>
#include <utility>

namespace yanterm::ssh::crypto {
namespace detail_adapt {

template <class T>
constexpr bool has_supports = requires(T& t, primitive_kind k, std::uint8_t id) {
    { t.supports(k, id) } noexcept -> std::same_as<bool>;
};
template <class T>
constexpr bool has_random_bytes = requires(T& t, std::byte* p, std::size_t n) {
    { t.random_bytes(p, n) } noexcept -> std::same_as<bool>;
};
template <class T>
constexpr bool has_constant_time_eq =
    requires(T& t, const std::byte* a, const std::byte* b, std::size_t n) {
        { t.constant_time_eq(a, b, n) } noexcept -> std::same_as<bool>;
    };

template <class T>
constexpr bool has_hash_new = requires(T& t, hash_id id) {
    { t.hash_new(id) } noexcept -> std::same_as<void*>;
};
template <class T>
constexpr bool has_hash_free = requires(T& t, void* ctx) {
    { t.hash_free(ctx) } noexcept;
};
template <class T>
constexpr bool has_hash_update = requires(T& t, void* ctx, const std::byte* in, std::size_t n) {
    { t.hash_update(ctx, in, n) } noexcept;
};
template <class T>
constexpr bool has_hash_final = requires(T& t, void* ctx, std::byte* out) {
    { t.hash_final(ctx, out) } noexcept -> std::same_as<bool>;
};

template <class T>
constexpr bool has_hmac_new =
    requires(T& t, hash_id id, const std::byte* key, std::size_t keylen) {
        { t.hmac_new(id, key, keylen) } noexcept -> std::same_as<void*>;
    };
template <class T>
constexpr bool has_hmac_free = requires(T& t, void* ctx) {
    { t.hmac_free(ctx) } noexcept;
};
template <class T>
constexpr bool has_hmac_update = requires(T& t, void* ctx, const std::byte* in, std::size_t n) {
    { t.hmac_update(ctx, in, n) } noexcept;
};
template <class T>
constexpr bool has_hmac_final = requires(T& t, void* ctx, std::byte* out) {
    { t.hmac_final(ctx, out) } noexcept -> std::same_as<bool>;
};

template <class T>
constexpr bool has_cipher_new =
    requires(T& t, cipher_id id, const std::byte* key, std::size_t keylen, bool enc) {
        { t.cipher_new(id, key, keylen, enc) } noexcept -> std::same_as<void*>;
    };
template <class T>
constexpr bool has_cipher_free = requires(T& t, void* ctx) {
    { t.cipher_free(ctx) } noexcept;
};
template <class T>
constexpr bool has_cipher_set_iv =
    requires(T& t, void* ctx, const std::byte* iv, std::size_t ivlen) {
        { t.cipher_set_iv(ctx, iv, ivlen) } noexcept -> std::same_as<bool>;
    };
template <class T>
constexpr bool has_cipher_update =
    requires(T& t, void* ctx, const std::byte* in, std::byte* out, std::size_t n) {
        { t.cipher_update(ctx, in, out, n) } noexcept -> std::same_as<bool>;
    };

template <class T>
constexpr bool has_aead_new =
    requires(T& t, cipher_id id, const std::byte* key, std::size_t keylen, bool enc) {
        { t.aead_new(id, key, keylen, enc) } noexcept -> std::same_as<void*>;
    };
template <class T>
constexpr bool has_aead_free = requires(T& t, void* ctx) {
    { t.aead_free(ctx) } noexcept;
};
template <class T>
constexpr bool has_aead_begin = requires(T& t, void* ctx, const std::byte* iv, std::size_t ivlen,
                                         const std::byte* aad, std::size_t aadlen) {
    { t.aead_begin(ctx, iv, ivlen, aad, aadlen) } noexcept -> std::same_as<bool>;
};
template <class T>
constexpr bool has_aead_update =
    requires(T& t, void* ctx, const std::byte* in, std::byte* out, std::size_t n) {
        { t.aead_update(ctx, in, out, n) } noexcept -> std::same_as<bool>;
    };
template <class T>
constexpr bool has_aead_final = requires(T& t, void* ctx, std::byte* tag, std::size_t n) {
    { t.aead_final(ctx, tag, n) } noexcept -> std::same_as<bool>;
};

template <class T>
constexpr bool has_poly1305 =
    requires(T& t, const std::byte* key32, const std::byte* in, std::size_t n, std::byte* out16) {
        { t.poly1305(key32, in, n, out16) } noexcept -> std::same_as<bool>;
    };

template <class T>
constexpr bool has_kex_new = requires(T& t, kex_id id) {
    { t.kex_new(id) } noexcept -> std::same_as<void*>;
};
template <class T>
constexpr bool has_kex_free = requires(T& t, void* ctx) {
    { t.kex_free(ctx) } noexcept;
};
template <class T>
constexpr bool has_kex_public =
    requires(T& t, void* ctx, std::byte* out, std::size_t cap, std::size_t* out_len) {
        { t.kex_public(ctx, out, cap, out_len) } noexcept -> std::same_as<bool>;
    };
template <class T>
constexpr bool has_kex_agree = requires(T& t, void* ctx, const std::byte* peer, std::size_t peerlen,
                                        std::byte* out, std::size_t cap, std::size_t* out_len) {
    { t.kex_agree(ctx, peer, peerlen, out, cap, out_len) } noexcept -> std::same_as<bool>;
};

template <class T>
constexpr bool has_sig_verify = requires(T& t, const public_key_material* key, const std::byte* msg,
                                         std::size_t msglen, const signature_material* sig) {
    { t.sig_verify(key, msg, msglen, sig) } noexcept -> std::same_as<bool>;
};
template <class T>
constexpr bool has_signing_key_new = requires(T& t, const private_key_material* key) {
    { t.signing_key_new(key) } noexcept -> std::same_as<void*>;
};
template <class T>
constexpr bool has_signing_key_free = requires(T& t, void* handle) {
    { t.signing_key_free(handle) } noexcept;
};
template <class T>
constexpr bool has_sig_sign = requires(T& t, void* handle, const std::byte* msg, std::size_t msglen,
                                       std::byte* out, std::size_t cap, std::size_t* out_len) {
    { t.sig_sign(handle, msg, msglen, out, cap, out_len) } noexcept -> std::same_as<bool>;
};

template <class T>
constexpr bool has_generate_keypair =
    requires(T& t, sig_id id, std::uint32_t bits, private_key_material* out, std::byte* storage,
             std::size_t storage_cap, std::size_t* storage_used) {
        { t.generate_keypair(id, bits, out, storage, storage_cap, storage_used) } noexcept
            -> std::same_as<bool>;
    };

template <class T>
constexpr bool has_inner = requires(const T& t) {
    { t.inner() } noexcept -> std::same_as<provider>;
};

template <class T>
constexpr bool all_hash =
    has_hash_new<T> && has_hash_free<T> && has_hash_update<T> && has_hash_final<T>;
template <class T>
constexpr bool any_hash =
    has_hash_new<T> || has_hash_free<T> || has_hash_update<T> || has_hash_final<T>;

template <class T>
constexpr bool all_hmac =
    has_hmac_new<T> && has_hmac_free<T> && has_hmac_update<T> && has_hmac_final<T>;
template <class T>
constexpr bool any_hmac =
    has_hmac_new<T> || has_hmac_free<T> || has_hmac_update<T> || has_hmac_final<T>;

template <class T>
constexpr bool all_cipher =
    has_cipher_new<T> && has_cipher_free<T> && has_cipher_set_iv<T> && has_cipher_update<T>;
template <class T>
constexpr bool any_cipher =
    has_cipher_new<T> || has_cipher_free<T> || has_cipher_set_iv<T> || has_cipher_update<T>;

template <class T>
constexpr bool all_aead = has_aead_new<T> && has_aead_free<T> && has_aead_begin<T> &&
                          has_aead_update<T> && has_aead_final<T>;
template <class T>
constexpr bool any_aead = has_aead_new<T> || has_aead_free<T> || has_aead_begin<T> ||
                          has_aead_update<T> || has_aead_final<T>;

template <class T>
constexpr bool all_poly1305 = has_poly1305<T>;
template <class T>
constexpr bool any_poly1305 = has_poly1305<T>;

template <class T>
constexpr bool all_kex = has_kex_new<T> && has_kex_free<T> && has_kex_public<T> && has_kex_agree<T>;
template <class T>
constexpr bool any_kex = has_kex_new<T> || has_kex_free<T> || has_kex_public<T> || has_kex_agree<T>;

template <class T>
constexpr bool all_sig =
    has_sig_verify<T> && has_signing_key_new<T> && has_signing_key_free<T> && has_sig_sign<T>;
template <class T>
constexpr bool any_sig =
    has_sig_verify<T> || has_signing_key_new<T> || has_signing_key_free<T> || has_sig_sign<T>;

template <class T>
constexpr bool all_generate_keypair = has_generate_keypair<T>;
template <class T>
constexpr bool any_generate_keypair = has_generate_keypair<T>;

template <class T>
constexpr void assert_groups() {
    static_assert(has_supports<T> && has_random_bytes<T>,
                  "wrap requires supports and random_bytes");
    static_assert(!any_hash<T> || all_hash<T>, "hash group must be complete");
    static_assert(!any_hmac<T> || all_hmac<T>, "hmac group must be complete");
    static_assert(!any_cipher<T> || all_cipher<T>, "cipher group must be complete");
    static_assert(!any_aead<T> || all_aead<T>, "aead group must be complete");
    static_assert(!any_poly1305<T> || all_poly1305<T>, "poly1305 group must be complete");
    static_assert(!any_kex<T> || all_kex<T>, "kex group must be complete");
    static_assert(!any_sig<T> || all_sig<T>, "signature group must be complete");
    static_assert(!any_generate_keypair<T> || all_generate_keypair<T>,
                  "generate_keypair group must be complete");
}

template <class T>
constexpr void assert_decorate_groups() {
    static_assert(has_inner<T>, "decorate requires inner() const noexcept -> provider");
    static_assert(!any_hash<T> || all_hash<T>, "hash group must be complete");
    static_assert(!any_hmac<T> || all_hmac<T>, "hmac group must be complete");
    static_assert(!any_cipher<T> || all_cipher<T>, "cipher group must be complete");
    static_assert(!any_aead<T> || all_aead<T>, "aead group must be complete");
    static_assert(!any_poly1305<T> || all_poly1305<T>, "poly1305 group must be complete");
    static_assert(!any_kex<T> || all_kex<T>, "kex group must be complete");
    static_assert(!any_sig<T> || all_sig<T>, "signature group must be complete");
    static_assert(!any_generate_keypair<T> || all_generate_keypair<T>,
                  "generate_keypair group must be complete");
}

inline bool default_constant_time_eq(void*, const std::byte* a, const std::byte* b,
                                     std::size_t len) noexcept {
    unsigned diff = 0;
    for (std::size_t i = 0; i < len; ++i) {
        diff |= static_cast<unsigned>(std::to_integer<unsigned char>(a[i] ^ b[i]));
    }
    return diff == 0;
}

template <class T>
struct wrap_thunks {
    static bool supports(void* self, primitive_kind k, std::uint8_t id) noexcept {
        return static_cast<T*>(self)->supports(k, id);
    }
    static bool random_bytes(void* self, std::byte* out, std::size_t len) noexcept {
        return static_cast<T*>(self)->random_bytes(out, len);
    }
    static bool constant_time_eq(void* self, const std::byte* a, const std::byte* b,
                                 std::size_t len) noexcept {
        if constexpr (has_constant_time_eq<T>) {
            return static_cast<T*>(self)->constant_time_eq(a, b, len);
        }
        return default_constant_time_eq(self, a, b, len);
    }

    static void* hash_new(void* self, hash_id id) noexcept {
        if constexpr (has_hash_new<T>) {
            return static_cast<T*>(self)->hash_new(id);
        }
        return nullptr;
    }
    static void hash_free(void* self, void* ctx) noexcept {
        if constexpr (has_hash_free<T>) {
            static_cast<T*>(self)->hash_free(ctx);
        }
    }
    static void hash_update(void* self, void* ctx, const std::byte* in, std::size_t n) noexcept {
        if constexpr (has_hash_update<T>) {
            static_cast<T*>(self)->hash_update(ctx, in, n);
        }
    }
    static bool hash_final(void* self, void* ctx, std::byte* out) noexcept {
        if constexpr (has_hash_final<T>) {
            return static_cast<T*>(self)->hash_final(ctx, out);
        }
        return false;
    }

    static void* hmac_new(void* self, hash_id id, const std::byte* key, std::size_t keylen) noexcept {
        if constexpr (has_hmac_new<T>) {
            return static_cast<T*>(self)->hmac_new(id, key, keylen);
        }
        return nullptr;
    }
    static void hmac_free(void* self, void* ctx) noexcept {
        if constexpr (has_hmac_free<T>) {
            static_cast<T*>(self)->hmac_free(ctx);
        }
    }
    static void hmac_update(void* self, void* ctx, const std::byte* in, std::size_t n) noexcept {
        if constexpr (has_hmac_update<T>) {
            static_cast<T*>(self)->hmac_update(ctx, in, n);
        }
    }
    static bool hmac_final(void* self, void* ctx, std::byte* out) noexcept {
        if constexpr (has_hmac_final<T>) {
            return static_cast<T*>(self)->hmac_final(ctx, out);
        }
        return false;
    }

    static void* cipher_new(void* self, cipher_id id, const std::byte* key, std::size_t keylen,
                            bool enc) noexcept {
        if constexpr (has_cipher_new<T>) {
            return static_cast<T*>(self)->cipher_new(id, key, keylen, enc);
        }
        return nullptr;
    }
    static void cipher_free(void* self, void* ctx) noexcept {
        if constexpr (has_cipher_free<T>) {
            static_cast<T*>(self)->cipher_free(ctx);
        }
    }
    static bool cipher_set_iv(void* self, void* ctx, const std::byte* iv,
                              std::size_t ivlen) noexcept {
        if constexpr (has_cipher_set_iv<T>) {
            return static_cast<T*>(self)->cipher_set_iv(ctx, iv, ivlen);
        }
        return false;
    }
    static bool cipher_update(void* self, void* ctx, const std::byte* in, std::byte* out,
                              std::size_t n) noexcept {
        if constexpr (has_cipher_update<T>) {
            return static_cast<T*>(self)->cipher_update(ctx, in, out, n);
        }
        return false;
    }

    static void* aead_new(void* self, cipher_id id, const std::byte* key, std::size_t keylen,
                          bool enc) noexcept {
        if constexpr (has_aead_new<T>) {
            return static_cast<T*>(self)->aead_new(id, key, keylen, enc);
        }
        return nullptr;
    }
    static void aead_free(void* self, void* ctx) noexcept {
        if constexpr (has_aead_free<T>) {
            static_cast<T*>(self)->aead_free(ctx);
        }
    }
    static bool aead_begin(void* self, void* ctx, const std::byte* iv, std::size_t ivlen,
                           const std::byte* aad, std::size_t aadlen) noexcept {
        if constexpr (has_aead_begin<T>) {
            return static_cast<T*>(self)->aead_begin(ctx, iv, ivlen, aad, aadlen);
        }
        return false;
    }
    static bool aead_update(void* self, void* ctx, const std::byte* in, std::byte* out,
                            std::size_t n) noexcept {
        if constexpr (has_aead_update<T>) {
            return static_cast<T*>(self)->aead_update(ctx, in, out, n);
        }
        return false;
    }
    static bool aead_final(void* self, void* ctx, std::byte* tag, std::size_t n) noexcept {
        if constexpr (has_aead_final<T>) {
            return static_cast<T*>(self)->aead_final(ctx, tag, n);
        }
        return false;
    }

    static bool poly1305(void* self, const std::byte* key32, const std::byte* in, std::size_t n,
                         std::byte* out16) noexcept {
        if constexpr (has_poly1305<T>) {
            return static_cast<T*>(self)->poly1305(key32, in, n, out16);
        }
        return false;
    }

    static void* kex_new(void* self, kex_id id) noexcept {
        if constexpr (has_kex_new<T>) {
            return static_cast<T*>(self)->kex_new(id);
        }
        return nullptr;
    }
    static void kex_free(void* self, void* ctx) noexcept {
        if constexpr (has_kex_free<T>) {
            static_cast<T*>(self)->kex_free(ctx);
        }
    }
    static bool kex_public(void* self, void* ctx, std::byte* out, std::size_t cap,
                           std::size_t* out_len) noexcept {
        if constexpr (has_kex_public<T>) {
            return static_cast<T*>(self)->kex_public(ctx, out, cap, out_len);
        }
        return false;
    }
    static bool kex_agree(void* self, void* ctx, const std::byte* peer, std::size_t peerlen,
                          std::byte* out, std::size_t cap, std::size_t* out_len) noexcept {
        if constexpr (has_kex_agree<T>) {
            return static_cast<T*>(self)->kex_agree(ctx, peer, peerlen, out, cap, out_len);
        }
        return false;
    }

    static bool sig_verify(void* self, const public_key_material* key, const std::byte* msg,
                           std::size_t msglen, const signature_material* sig) noexcept {
        if constexpr (has_sig_verify<T>) {
            return static_cast<T*>(self)->sig_verify(key, msg, msglen, sig);
        }
        return false;
    }
    static void* signing_key_new(void* self, const private_key_material* key) noexcept {
        if constexpr (has_signing_key_new<T>) {
            return static_cast<T*>(self)->signing_key_new(key);
        }
        return nullptr;
    }
    static void signing_key_free(void* self, void* handle) noexcept {
        if constexpr (has_signing_key_free<T>) {
            static_cast<T*>(self)->signing_key_free(handle);
        }
    }
    static bool sig_sign(void* self, void* handle, const std::byte* msg, std::size_t msglen,
                         std::byte* out, std::size_t cap, std::size_t* out_len) noexcept {
        if constexpr (has_sig_sign<T>) {
            return static_cast<T*>(self)->sig_sign(handle, msg, msglen, out, cap, out_len);
        }
        return false;
    }

    static bool generate_keypair(void* self, sig_id id, std::uint32_t bits,
                                 private_key_material* out, std::byte* storage,
                                 std::size_t storage_cap, std::size_t* storage_used) noexcept {
        if constexpr (has_generate_keypair<T>) {
            return static_cast<T*>(self)->generate_keypair(id, bits, out, storage, storage_cap,
                                                           storage_used);
        }
        return false;
    }
};

template <class T>
const provider_vtable* wrap_vtable() {
    assert_groups<T>();
    static const provider_vtable vt{
        .supports = &wrap_thunks<T>::supports,
        .random_bytes = &wrap_thunks<T>::random_bytes,
        .constant_time_eq = has_constant_time_eq<T> ? &wrap_thunks<T>::constant_time_eq
                                                    : &default_constant_time_eq,
        .hash_new = all_hash<T> ? &wrap_thunks<T>::hash_new : nullptr,
        .hash_free = all_hash<T> ? &wrap_thunks<T>::hash_free : nullptr,
        .hash_update = all_hash<T> ? &wrap_thunks<T>::hash_update : nullptr,
        .hash_final = all_hash<T> ? &wrap_thunks<T>::hash_final : nullptr,
        .hmac_new = all_hmac<T> ? &wrap_thunks<T>::hmac_new : nullptr,
        .hmac_free = all_hmac<T> ? &wrap_thunks<T>::hmac_free : nullptr,
        .hmac_update = all_hmac<T> ? &wrap_thunks<T>::hmac_update : nullptr,
        .hmac_final = all_hmac<T> ? &wrap_thunks<T>::hmac_final : nullptr,
        .cipher_new = all_cipher<T> ? &wrap_thunks<T>::cipher_new : nullptr,
        .cipher_free = all_cipher<T> ? &wrap_thunks<T>::cipher_free : nullptr,
        .cipher_set_iv = all_cipher<T> ? &wrap_thunks<T>::cipher_set_iv : nullptr,
        .cipher_update = all_cipher<T> ? &wrap_thunks<T>::cipher_update : nullptr,
        .aead_new = all_aead<T> ? &wrap_thunks<T>::aead_new : nullptr,
        .aead_free = all_aead<T> ? &wrap_thunks<T>::aead_free : nullptr,
        .aead_begin = all_aead<T> ? &wrap_thunks<T>::aead_begin : nullptr,
        .aead_update = all_aead<T> ? &wrap_thunks<T>::aead_update : nullptr,
        .aead_final = all_aead<T> ? &wrap_thunks<T>::aead_final : nullptr,
        .poly1305 = all_poly1305<T> ? &wrap_thunks<T>::poly1305 : nullptr,
        .kex_new = all_kex<T> ? &wrap_thunks<T>::kex_new : nullptr,
        .kex_free = all_kex<T> ? &wrap_thunks<T>::kex_free : nullptr,
        .kex_public = all_kex<T> ? &wrap_thunks<T>::kex_public : nullptr,
        .kex_agree = all_kex<T> ? &wrap_thunks<T>::kex_agree : nullptr,
        .sig_verify = all_sig<T> ? &wrap_thunks<T>::sig_verify : nullptr,
        .signing_key_new = all_sig<T> ? &wrap_thunks<T>::signing_key_new : nullptr,
        .signing_key_free = all_sig<T> ? &wrap_thunks<T>::signing_key_free : nullptr,
        .sig_sign = all_sig<T> ? &wrap_thunks<T>::sig_sign : nullptr,
        .generate_keypair = all_generate_keypair<T> ? &wrap_thunks<T>::generate_keypair : nullptr,
    };
    return &vt;
}

template <class T>
struct decorate_thunks {
    static bool supports(void* self, primitive_kind k, std::uint8_t id) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_supports<T>) {
            return t->supports(k, id);
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->supports == nullptr) return false;
        return vt->supports(inner.self_ptr(), k, id);
    }
    static bool random_bytes(void* self, std::byte* out, std::size_t len) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_random_bytes<T>) {
            return t->random_bytes(out, len);
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->random_bytes == nullptr) return false;
        return vt->random_bytes(inner.self_ptr(), out, len);
    }
    static bool constant_time_eq(void* self, const std::byte* a, const std::byte* b,
                                 std::size_t len) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_constant_time_eq<T>) {
            return t->constant_time_eq(a, b, len);
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->constant_time_eq == nullptr) return false;
        return vt->constant_time_eq(inner.self_ptr(), a, b, len);
    }

    static void* hash_new(void* self, hash_id id) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_hash_new<T>) {
            return t->hash_new(id);
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->hash_new == nullptr) return nullptr;
        return vt->hash_new(inner.self_ptr(), id);
    }
    static void hash_free(void* self, void* ctx) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_hash_free<T>) {
            t->hash_free(ctx);
            return;
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->hash_free == nullptr) return;
        vt->hash_free(inner.self_ptr(), ctx);
    }
    static void hash_update(void* self, void* ctx, const std::byte* in, std::size_t n) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_hash_update<T>) {
            t->hash_update(ctx, in, n);
            return;
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->hash_update == nullptr) return;
        vt->hash_update(inner.self_ptr(), ctx, in, n);
    }
    static bool hash_final(void* self, void* ctx, std::byte* out) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_hash_final<T>) {
            return t->hash_final(ctx, out);
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->hash_final == nullptr) return false;
        return vt->hash_final(inner.self_ptr(), ctx, out);
    }

    static void* hmac_new(void* self, hash_id id, const std::byte* key, std::size_t keylen) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_hmac_new<T>) {
            return t->hmac_new(id, key, keylen);
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->hmac_new == nullptr) return nullptr;
        return vt->hmac_new(inner.self_ptr(), id, key, keylen);
    }
    static void hmac_free(void* self, void* ctx) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_hmac_free<T>) {
            t->hmac_free(ctx);
            return;
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->hmac_free == nullptr) return;
        vt->hmac_free(inner.self_ptr(), ctx);
    }
    static void hmac_update(void* self, void* ctx, const std::byte* in, std::size_t n) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_hmac_update<T>) {
            t->hmac_update(ctx, in, n);
            return;
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->hmac_update == nullptr) return;
        vt->hmac_update(inner.self_ptr(), ctx, in, n);
    }
    static bool hmac_final(void* self, void* ctx, std::byte* out) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_hmac_final<T>) {
            return t->hmac_final(ctx, out);
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->hmac_final == nullptr) return false;
        return vt->hmac_final(inner.self_ptr(), ctx, out);
    }

    static void* cipher_new(void* self, cipher_id id, const std::byte* key, std::size_t keylen,
                            bool enc) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_cipher_new<T>) {
            return t->cipher_new(id, key, keylen, enc);
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->cipher_new == nullptr) return nullptr;
        return vt->cipher_new(inner.self_ptr(), id, key, keylen, enc);
    }
    static void cipher_free(void* self, void* ctx) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_cipher_free<T>) {
            t->cipher_free(ctx);
            return;
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->cipher_free == nullptr) return;
        vt->cipher_free(inner.self_ptr(), ctx);
    }
    static bool cipher_set_iv(void* self, void* ctx, const std::byte* iv,
                              std::size_t ivlen) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_cipher_set_iv<T>) {
            return t->cipher_set_iv(ctx, iv, ivlen);
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->cipher_set_iv == nullptr) return false;
        return vt->cipher_set_iv(inner.self_ptr(), ctx, iv, ivlen);
    }
    static bool cipher_update(void* self, void* ctx, const std::byte* in, std::byte* out,
                              std::size_t n) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_cipher_update<T>) {
            return t->cipher_update(ctx, in, out, n);
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->cipher_update == nullptr) return false;
        return vt->cipher_update(inner.self_ptr(), ctx, in, out, n);
    }

    static void* aead_new(void* self, cipher_id id, const std::byte* key, std::size_t keylen,
                          bool enc) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_aead_new<T>) {
            return t->aead_new(id, key, keylen, enc);
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->aead_new == nullptr) return nullptr;
        return vt->aead_new(inner.self_ptr(), id, key, keylen, enc);
    }
    static void aead_free(void* self, void* ctx) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_aead_free<T>) {
            t->aead_free(ctx);
            return;
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->aead_free == nullptr) return;
        vt->aead_free(inner.self_ptr(), ctx);
    }
    static bool aead_begin(void* self, void* ctx, const std::byte* iv, std::size_t ivlen,
                           const std::byte* aad, std::size_t aadlen) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_aead_begin<T>) {
            return t->aead_begin(ctx, iv, ivlen, aad, aadlen);
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->aead_begin == nullptr) return false;
        return vt->aead_begin(inner.self_ptr(), ctx, iv, ivlen, aad, aadlen);
    }
    static bool aead_update(void* self, void* ctx, const std::byte* in, std::byte* out,
                            std::size_t n) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_aead_update<T>) {
            return t->aead_update(ctx, in, out, n);
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->aead_update == nullptr) return false;
        return vt->aead_update(inner.self_ptr(), ctx, in, out, n);
    }
    static bool aead_final(void* self, void* ctx, std::byte* tag, std::size_t n) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_aead_final<T>) {
            return t->aead_final(ctx, tag, n);
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->aead_final == nullptr) return false;
        return vt->aead_final(inner.self_ptr(), ctx, tag, n);
    }

    static bool poly1305(void* self, const std::byte* key32, const std::byte* in, std::size_t n,
                         std::byte* out16) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_poly1305<T>) {
            return t->poly1305(key32, in, n, out16);
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->poly1305 == nullptr) return false;
        return vt->poly1305(inner.self_ptr(), key32, in, n, out16);
    }

    static void* kex_new(void* self, kex_id id) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_kex_new<T>) {
            return t->kex_new(id);
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->kex_new == nullptr) return nullptr;
        return vt->kex_new(inner.self_ptr(), id);
    }
    static void kex_free(void* self, void* ctx) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_kex_free<T>) {
            t->kex_free(ctx);
            return;
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->kex_free == nullptr) return;
        vt->kex_free(inner.self_ptr(), ctx);
    }
    static bool kex_public(void* self, void* ctx, std::byte* out, std::size_t cap,
                           std::size_t* out_len) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_kex_public<T>) {
            return t->kex_public(ctx, out, cap, out_len);
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->kex_public == nullptr) return false;
        return vt->kex_public(inner.self_ptr(), ctx, out, cap, out_len);
    }
    static bool kex_agree(void* self, void* ctx, const std::byte* peer, std::size_t peerlen,
                          std::byte* out, std::size_t cap, std::size_t* out_len) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_kex_agree<T>) {
            return t->kex_agree(ctx, peer, peerlen, out, cap, out_len);
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->kex_agree == nullptr) return false;
        return vt->kex_agree(inner.self_ptr(), ctx, peer, peerlen, out, cap, out_len);
    }

    static bool sig_verify(void* self, const public_key_material* key, const std::byte* msg,
                           std::size_t msglen, const signature_material* sig) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_sig_verify<T>) {
            return t->sig_verify(key, msg, msglen, sig);
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->sig_verify == nullptr) return false;
        return vt->sig_verify(inner.self_ptr(), key, msg, msglen, sig);
    }
    static void* signing_key_new(void* self, const private_key_material* key) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_signing_key_new<T>) {
            return t->signing_key_new(key);
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->signing_key_new == nullptr) return nullptr;
        return vt->signing_key_new(inner.self_ptr(), key);
    }
    static void signing_key_free(void* self, void* handle) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_signing_key_free<T>) {
            t->signing_key_free(handle);
            return;
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->signing_key_free == nullptr) return;
        vt->signing_key_free(inner.self_ptr(), handle);
    }
    static bool sig_sign(void* self, void* handle, const std::byte* msg, std::size_t msglen,
                         std::byte* out, std::size_t cap, std::size_t* out_len) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_sig_sign<T>) {
            return t->sig_sign(handle, msg, msglen, out, cap, out_len);
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->sig_sign == nullptr) return false;
        return vt->sig_sign(inner.self_ptr(), handle, msg, msglen, out, cap, out_len);
    }

    static bool generate_keypair(void* self, sig_id id, std::uint32_t bits,
                                 private_key_material* out, std::byte* storage,
                                 std::size_t storage_cap, std::size_t* storage_used) noexcept {
        auto* t = static_cast<T*>(self);
        if constexpr (has_generate_keypair<T>) {
            return t->generate_keypair(id, bits, out, storage, storage_cap, storage_used);
        }
        provider inner = t->inner();
        const provider_vtable* vt = inner.vtable();
        if (vt == nullptr || vt->generate_keypair == nullptr) return false;
        return vt->generate_keypair(inner.self_ptr(), id, bits, out, storage, storage_cap,
                                    storage_used);
    }
};

template <class T>
const provider_vtable* decorate_vtable() {
    assert_decorate_groups<T>();
    static const provider_vtable vt{
        .supports = &decorate_thunks<T>::supports,
        .random_bytes = &decorate_thunks<T>::random_bytes,
        .constant_time_eq = &decorate_thunks<T>::constant_time_eq,
        .hash_new = &decorate_thunks<T>::hash_new,
        .hash_free = &decorate_thunks<T>::hash_free,
        .hash_update = &decorate_thunks<T>::hash_update,
        .hash_final = &decorate_thunks<T>::hash_final,
        .hmac_new = &decorate_thunks<T>::hmac_new,
        .hmac_free = &decorate_thunks<T>::hmac_free,
        .hmac_update = &decorate_thunks<T>::hmac_update,
        .hmac_final = &decorate_thunks<T>::hmac_final,
        .cipher_new = &decorate_thunks<T>::cipher_new,
        .cipher_free = &decorate_thunks<T>::cipher_free,
        .cipher_set_iv = &decorate_thunks<T>::cipher_set_iv,
        .cipher_update = &decorate_thunks<T>::cipher_update,
        .aead_new = &decorate_thunks<T>::aead_new,
        .aead_free = &decorate_thunks<T>::aead_free,
        .aead_begin = &decorate_thunks<T>::aead_begin,
        .aead_update = &decorate_thunks<T>::aead_update,
        .aead_final = &decorate_thunks<T>::aead_final,
        .poly1305 = &decorate_thunks<T>::poly1305,
        .kex_new = &decorate_thunks<T>::kex_new,
        .kex_free = &decorate_thunks<T>::kex_free,
        .kex_public = &decorate_thunks<T>::kex_public,
        .kex_agree = &decorate_thunks<T>::kex_agree,
        .sig_verify = &decorate_thunks<T>::sig_verify,
        .signing_key_new = &decorate_thunks<T>::signing_key_new,
        .signing_key_free = &decorate_thunks<T>::signing_key_free,
        .sig_sign = &decorate_thunks<T>::sig_sign,
        .generate_keypair = &decorate_thunks<T>::generate_keypair,
    };
    return &vt;
}

}  // namespace detail_adapt

template <class T>
provider provider::wrap(T& backend) noexcept {
    return {detail_adapt::wrap_vtable<T>(), std::addressof(backend)};
}

template <class T>
provider provider::decorate(T& overlay) noexcept {
    static_assert(detail_adapt::has_inner<T>,
                  "decorate requires inner() const noexcept -> provider");
    return {detail_adapt::decorate_vtable<T>(), std::addressof(overlay)};
}

}  // namespace yanterm::ssh::crypto
