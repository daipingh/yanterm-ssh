#pragma once

#include <yanterm-ssh/crypto/provider.hpp>

#include <cstddef>

namespace yanterm::ssh::testing {

// A backend that supports nothing. Used to prove that the protocol core degrades
// cleanly when a primitive is unavailable, and that RAII handles pair every
// successful *_new with exactly one *_free.
struct stub_backend {
    int live_handles = 0;
    int total_created = 0;
    int total_freed = 0;
    // When set, *_new succeeds and returns a pointer to this backend, so the
    // handle lifetime can be observed.
    bool allow_handles = false;

    void* make() noexcept {
        if (!allow_handles) return nullptr;
        ++live_handles;
        ++total_created;
        return this;
    }
    void drop() noexcept {
        --live_handles;
        ++total_freed;
    }

    bool supports(crypto::primitive_kind, std::uint8_t) noexcept { return false; }

    bool random_bytes(std::byte* out, std::size_t len) noexcept {
        for (std::size_t i = 0; i < len; ++i) out[i] = std::byte{0xAB};
        return true;
    }

    bool constant_time_eq(const std::byte* a, const std::byte* b, std::size_t len) noexcept {
        unsigned diff = 0;
        for (std::size_t i = 0; i < len; ++i) {
            diff |= std::to_integer<unsigned>(a[i] ^ b[i]);
        }
        return diff == 0;
    }

    void* hash_new(crypto::hash_id) noexcept { return make(); }
    void hash_free(void*) noexcept { drop(); }
    void hash_update(void*, const std::byte*, std::size_t) noexcept {}
    bool hash_final(void*, std::byte*) noexcept { return false; }

    void* hmac_new(crypto::hash_id, const std::byte*, std::size_t) noexcept { return make(); }
    void hmac_free(void*) noexcept { drop(); }
    void hmac_update(void*, const std::byte*, std::size_t) noexcept {}
    bool hmac_final(void*, std::byte*) noexcept { return false; }

    void* cipher_new(crypto::cipher_id, const std::byte*, std::size_t, bool) noexcept {
        return make();
    }
    void cipher_free(void*) noexcept { drop(); }
    bool cipher_set_iv(void*, const std::byte*, std::size_t) noexcept { return false; }
    bool cipher_update(void*, const std::byte*, std::byte*, std::size_t) noexcept { return false; }

    void* aead_new(crypto::cipher_id, const std::byte*, std::size_t, bool) noexcept {
        return make();
    }
    void aead_free(void*) noexcept { drop(); }
    bool aead_begin(void*, const std::byte*, std::size_t, const std::byte*,
                    std::size_t) noexcept {
        return false;
    }
    bool aead_update(void*, const std::byte*, std::byte*, std::size_t) noexcept { return false; }
    bool aead_final(void*, std::byte*, std::size_t) noexcept { return false; }

    bool poly1305(const std::byte*, const std::byte*, std::size_t, std::byte*) noexcept {
        return false;
    }

    void* kex_new(crypto::kex_id) noexcept { return make(); }
    void kex_free(void*) noexcept { drop(); }
    bool kex_public(void*, std::byte*, std::size_t, std::size_t*) noexcept { return false; }
    bool kex_agree(void*, const std::byte*, std::size_t, std::byte*, std::size_t,
                   std::size_t*) noexcept {
        return false;
    }

    bool sig_verify(const crypto::public_key_material*, const std::byte*, std::size_t,
                    const crypto::signature_material*) noexcept {
        return false;
    }
    void* signing_key_new(const crypto::private_key_material*) noexcept { return make(); }
    void signing_key_free(void*) noexcept { drop(); }
    bool sig_sign(void*, const std::byte*, std::size_t, std::byte*, std::size_t,
                  std::size_t*) noexcept {
        return false;
    }

    bool generate_keypair(crypto::sig_id, std::uint32_t, crypto::private_key_material*, std::byte*,
                          std::size_t, std::size_t*) noexcept {
        return false;
    }
};

}  // namespace yanterm::ssh::testing
