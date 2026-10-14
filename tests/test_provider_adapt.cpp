#include <catch2/catch_test_macros.hpp>
#include <yanterm-ssh/crypto/provider.hpp>
#include <array>
#include <cstddef>

using namespace yanterm::ssh;

namespace {

struct hash_only_backend {
    bool supports(crypto::primitive_kind kind, std::uint8_t) noexcept {
        return kind == crypto::primitive_kind::hash;
    }
    bool random_bytes(std::byte* out, std::size_t len) noexcept {
        for (std::size_t i = 0; i < len; ++i) out[i] = std::byte{0x11};
        return true;
    }
    void* hash_new(crypto::hash_id) noexcept { return this; }
    void hash_free(void*) noexcept {}
    void hash_update(void*, const std::byte*, std::size_t) noexcept {}
    bool hash_final(void* ctx, std::byte* out) noexcept {
        (void)ctx;
        out[0] = std::byte{0x22};
        return true;
    }
};

struct cipher_stub {
    bool supports(crypto::primitive_kind kind, std::uint8_t) noexcept {
        return kind == crypto::primitive_kind::cipher;
    }
    bool random_bytes(std::byte*, std::size_t) noexcept { return true; }
    void* cipher_new(crypto::cipher_id, const std::byte*, std::size_t, bool) noexcept {
        return this;
    }
    void cipher_free(void*) noexcept {}
    bool cipher_set_iv(void*, const std::byte*, std::size_t) noexcept { return true; }
    bool cipher_update(void*, const std::byte*, std::byte*, std::size_t) noexcept { return true; }
};

struct random_overlay {
    crypto::provider inner_;
    std::byte fill{0x5A};
    crypto::provider inner() const noexcept { return inner_; }
    bool random_bytes(std::byte* out, std::size_t len) noexcept {
        for (std::size_t i = 0; i < len; ++i) out[i] = fill;
        return true;
    }
};

}  // namespace

TEST_CASE("wrap compiles a hash-only backend and leaves aead empty", "[crypto][provider][wrap]") {
    hash_only_backend b;
    crypto::provider p = crypto::provider::wrap(b);
    REQUIRE(static_cast<bool>(p));
    REQUIRE(p.supports(crypto::hash_id::sha256));
    REQUIRE_FALSE(p.supports(crypto::cipher_id::aes256_gcm));
    crypto::hash_ctx h = p.new_hash(crypto::hash_id::sha256);
    REQUIRE(static_cast<bool>(h));
    std::array<std::byte, 32> out{};
    REQUIRE(h.final_into(out));
    REQUIRE(out[0] == std::byte{0x22});
    crypto::aead_cipher a = p.new_aead(crypto::cipher_id::aes256_gcm, {}, true);
    REQUIRE_FALSE(static_cast<bool>(a));
    crypto::cipher c = p.new_cipher(crypto::cipher_id::aes128_ctr, {}, true);
    REQUIRE_FALSE(static_cast<bool>(c));
}

TEST_CASE("decorate overrides random_bytes and forwards cipher", "[crypto][provider][decorate]") {
    cipher_stub inner_b;
    random_overlay ov{crypto::provider::wrap(inner_b)};
    crypto::provider p = crypto::provider::decorate(ov);
    std::array<std::byte, 4> buf{};
    REQUIRE_FALSE(static_cast<bool>(p.random_bytes(buf)));
    REQUIRE(buf[0] == std::byte{0x5A});
    crypto::cipher c = p.new_cipher(crypto::cipher_id::aes128_ctr, {}, true);
    REQUIRE(static_cast<bool>(c));
    REQUIRE(c.set_iv({}));
    std::array<std::byte, 16> in{};
    std::array<std::byte, 16> out{};
    REQUIRE(c.update(in, out));
}
