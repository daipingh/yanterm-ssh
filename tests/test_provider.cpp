#include <catch2/catch_test_macros.hpp>

#include "stub_provider.hpp"

#include <array>
#include <cstddef>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

TEST_CASE("algorithm size tables are self-consistent", "[crypto]") {
    REQUIRE(crypto::hash_output_size(crypto::hash_id::sha1) == 20);
    REQUIRE(crypto::hash_output_size(crypto::hash_id::sha256) == 32);
    REQUIRE(crypto::hash_output_size(crypto::hash_id::sha384) == 48);
    REQUIRE(crypto::hash_output_size(crypto::hash_id::sha512) == 64);
    REQUIRE(crypto::hash_output_size(crypto::hash_id::sm3) == 32);
    REQUIRE(crypto::cipher_key_size(crypto::cipher_id::sm4_ctr) == 16);
    REQUIRE(crypto::cipher_key_size(crypto::cipher_id::sm4_cbc) == 16);
    REQUIRE(crypto::is_rsa_sig(crypto::sig_id::rsa_pkcs1_sha256));
    REQUIRE_FALSE(crypto::is_rsa_sig(crypto::sig_id::ed25519));
    REQUIRE(crypto::is_ecdsa_sig(crypto::sig_id::ecdsa_nistp256));
    REQUIRE_FALSE(crypto::is_ecdsa_sig(crypto::sig_id::sm2_za));
    REQUIRE(crypto::is_sm2_sig(crypto::sig_id::sm2_za));
    REQUIRE(crypto::is_sm2_sig(crypto::sig_id::sm2_ecdsa));
    REQUIRE_FALSE(crypto::is_sm2_sig(crypto::sig_id::ecdsa_nistp256));
    REQUIRE(crypto::kex_public_size(crypto::kex_id::ecdh_sm2) == 65);
    REQUIRE(crypto::kex_secret_size(crypto::kex_id::sm2_kap) == 32);

    REQUIRE(crypto::cipher_key_size(crypto::cipher_id::aes128_ctr) == 16);
    REQUIRE(crypto::cipher_key_size(crypto::cipher_id::aes256_gcm) == 32);
    REQUIRE(crypto::cipher_key_size(crypto::cipher_id::chacha20) == 32);

    REQUIRE(crypto::cipher_block_size(crypto::cipher_id::aes256_ctr) == 16);
    REQUIRE(crypto::cipher_block_size(crypto::cipher_id::chacha20) == 8);

    REQUIRE(crypto::kex_public_size(crypto::kex_id::curve25519) == 32);
    REQUIRE(crypto::kex_public_size(crypto::kex_id::ecdh_nistp256) == 65);
    REQUIRE(crypto::kex_secret_size(crypto::kex_id::ecdh_nistp521) == 66);

    REQUIRE(crypto::cipher_key_size(crypto::cipher_id::aes128_cbc) == 16);
    REQUIRE(crypto::cipher_key_size(crypto::cipher_id::aes192_cbc) == 24);
    REQUIRE(crypto::cipher_key_size(crypto::cipher_id::aes256_cbc) == 32);
    REQUIRE(crypto::cipher_block_size(crypto::cipher_id::aes256_cbc) == 16);
    REQUIRE(crypto::cipher_iv_size(crypto::cipher_id::aes256_cbc) == 16);
    REQUIRE(crypto::cipher_iv_size(crypto::cipher_id::aes256_ctr) == 16);
    REQUIRE(crypto::cipher_iv_size(crypto::cipher_id::aes256_gcm) == 12);
    REQUIRE(crypto::cipher_iv_size(crypto::cipher_id::chacha20) == 16);
}

TEST_CASE("a backend that supports nothing reports so", "[crypto][provider]") {
    stub_backend backend;
    crypto::provider p = crypto::provider::wrap(backend);

    REQUIRE(static_cast<bool>(p));
    REQUIRE_FALSE(p.supports(crypto::hash_id::sha256));
    REQUIRE_FALSE(p.supports(crypto::cipher_id::aes256_gcm));
    REQUIRE_FALSE(p.supports(crypto::mac_id::hmac_sha256));
    REQUIRE_FALSE(p.supports(crypto::kex_id::curve25519));
    REQUIRE_FALSE(p.supports(crypto::sig_id::ed25519));
}

TEST_CASE("a default-constructed provider is falsy and supports nothing", "[crypto][provider]") {
    crypto::provider p;
    REQUIRE_FALSE(static_cast<bool>(p));
    REQUIRE_FALSE(p.supports(crypto::hash_id::sha256));
}

TEST_CASE("failed context creation yields a falsy handle", "[crypto][provider]") {
    stub_backend backend;  // allow_handles stays false
    crypto::provider p = crypto::provider::wrap(backend);

    crypto::hash_ctx h = p.new_hash(crypto::hash_id::sha256);
    REQUIRE_FALSE(static_cast<bool>(h));
    REQUIRE(backend.total_created == 0);
    REQUIRE(backend.total_freed == 0);
}

TEST_CASE("handles free exactly once", "[crypto][provider]") {
    stub_backend backend;
    backend.allow_handles = true;
    crypto::provider p = crypto::provider::wrap(backend);

    {
        crypto::hash_ctx h = p.new_hash(crypto::hash_id::sha256);
        REQUIRE(static_cast<bool>(h));
        REQUIRE(backend.live_handles == 1);
    }
    REQUIRE(backend.live_handles == 0);
    REQUIRE(backend.total_created == 1);
    REQUIRE(backend.total_freed == 1);
}

TEST_CASE("moving a handle does not double free", "[crypto][provider]") {
    stub_backend backend;
    backend.allow_handles = true;
    crypto::provider p = crypto::provider::wrap(backend);

    {
        crypto::hmac_ctx a = p.new_hmac(crypto::hash_id::sha256, std::span<const std::byte>{});
        REQUIRE(backend.live_handles == 1);
        crypto::hmac_ctx b = std::move(a);
        REQUIRE(static_cast<bool>(b));
        REQUIRE_FALSE(static_cast<bool>(a));
        REQUIRE(backend.live_handles == 1);
    }
    REQUIRE(backend.live_handles == 0);
    REQUIRE(backend.total_freed == 1);
}

TEST_CASE("move assignment frees the previous context", "[crypto][provider]") {
    stub_backend backend;
    backend.allow_handles = true;
    crypto::provider p = crypto::provider::wrap(backend);

    crypto::kex_agreement a = p.new_kex(crypto::kex_id::curve25519);
    crypto::kex_agreement b = p.new_kex(crypto::kex_id::curve25519);
    REQUIRE(backend.live_handles == 2);
    a = std::move(b);
    REQUIRE(backend.live_handles == 1);
    REQUIRE(backend.total_freed == 1);
}

TEST_CASE("random_bytes returns a falsy error_code on success", "[crypto][provider]") {
    stub_backend backend;
    crypto::provider p = crypto::provider::wrap(backend);
    std::array<std::byte, 4> buf{};
    const std::error_code ec = p.random_bytes(buf);
    REQUIRE_FALSE(static_cast<bool>(ec));
    REQUIRE(buf[0] == std::byte{0xAB});
}

TEST_CASE("constant_time_eq compares by content and rejects size mismatch", "[crypto][provider]") {
    stub_backend backend;
    crypto::provider p = crypto::provider::wrap(backend);

    const std::array<std::byte, 3> a{std::byte{1}, std::byte{2}, std::byte{3}};
    const std::array<std::byte, 3> b{std::byte{1}, std::byte{2}, std::byte{3}};
    const std::array<std::byte, 3> c{std::byte{1}, std::byte{2}, std::byte{4}};
    const std::array<std::byte, 2> d{std::byte{1}, std::byte{2}};

    REQUIRE(p.constant_time_eq(a, b));
    REQUIRE_FALSE(p.constant_time_eq(a, c));
    REQUIRE_FALSE(p.constant_time_eq(a, d));
}

TEST_CASE("secure_zero clears a buffer", "[crypto]") {
    std::array<std::byte, 4> buf{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    crypto::secure_zero(buf);
    for (std::byte b : buf) REQUIRE(b == std::byte{0});
}
