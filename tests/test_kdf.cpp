#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/kex/algorithms.hpp>
#include <yanterm-ssh/core/types.hpp>
#include <yanterm-ssh/memory/detail/pages.hpp>
#include <yanterm-ssh/core/detail/kdf.hpp>
#include <yanterm-ssh/core/detail/packet.hpp>
#include <yanterm-ssh/wire/types.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>

#include "hex_util.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>
#include <vector>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

namespace {

crypto::provider prov() {
    static crypto::openssl_backend backend;
    return crypto::provider::wrap(backend);
}

// Fixed KDF inputs (magnitude of K; tests mpint-encode before derive_key).
constexpr std::string_view k_secret_mag = "shared-secret-magnitude!!";  // 24 bytes, MSB < 0x80
constexpr std::string_view k_exchange_hash =
    "0123456789abcdef0123456789abcdef";  // 32 bytes
constexpr std::string_view k_session_id =
    "session-id-bytes-for-kdf-tests!!";  // 32 bytes

std::vector<std::byte> mpint_encode(std::span<const std::byte> magnitude) {
    wire::writer w;
    w.write_mpint(magnitude);
    return {w.data().begin(), w.data().end()};
}

std::vector<std::byte> manual_derive(crypto::provider p, crypto::hash_id h,
                                     std::span<const std::byte> K_mpint,
                                     std::span<const std::byte> H, char letter,
                                     std::span<const std::byte> session_id, std::size_t n) {
    const std::size_t digest = crypto::hash_output_size(h);
    std::vector<std::byte> out;
    out.reserve(n);
    std::vector<std::byte> block(digest);
    std::vector<std::byte> so_far;

    auto hash_concat = [&](std::span<const std::byte> suffix, std::span<std::byte> dest) {
        crypto::hash_ctx ctx = p.new_hash(h);
        REQUIRE(static_cast<bool>(ctx));
        ctx.update(K_mpint);
        ctx.update(H);
        ctx.update(suffix);
        REQUIRE(ctx.final_into(dest));
    };

    // K1 = HASH(K || H || letter || session_id)
    {
        std::vector<std::byte> suffix;
        suffix.push_back(static_cast<std::byte>(letter));
        suffix.insert(suffix.end(), session_id.begin(), session_id.end());
        hash_concat(suffix, block);
    }
    so_far = block;
    out.insert(out.end(), block.begin(), block.end());

    while (out.size() < n) {
        // Ki = HASH(K || H || K1 || ... || K{i-1})
        hash_concat(so_far, block);
        so_far.insert(so_far.end(), block.begin(), block.end());
        out.insert(out.end(), block.begin(), block.end());
    }
    out.resize(n);
    return out;
}

kex::negotiated make_nego(core::detail::packet_mode mode_c2s, core::detail::packet_mode mode_s2c,
                          crypto::cipher_id cipher_c2s, crypto::cipher_id cipher_s2c,
                          crypto::hash_id mac_c2s = crypto::hash_id::sha256,
                          crypto::hash_id mac_s2c = crypto::hash_id::sha256) {
    kex::negotiated n;
    n.kex = crypto::kex_id::curve25519;
    n.kex_name = "curve25519-sha256";
    n.host_key = crypto::sig_id::ed25519;
    n.host_key_name = "ssh-ed25519";
    n.exchange_hash = crypto::hash_id::sha256;
    n.mode_c2s = mode_c2s;
    n.mode_s2c = mode_s2c;
    n.cipher_c2s = cipher_c2s;
    n.cipher_s2c = cipher_s2c;
    n.mac_c2s = mac_c2s;
    n.mac_s2c = mac_s2c;
    return n;
}

std::error_code write_packet(crypto::provider p, core::detail::direction_state st,
                             std::span<const std::byte> payload, std::vector<std::byte>& wire_out) {
    core::detail::packet_writer w(p);
    w.install(std::move(st));
    memory::detail::page_pool pool;
    memory::detail::page_slice slice;
    auto ec = w.write(payload, pool, slice);
    if (ec) return ec;
    wire_out.assign(slice.bytes().begin(), slice.bytes().end());
    return {};
}

std::error_code read_packet(crypto::provider p, core::detail::direction_state st,
                            std::span<const std::byte> wire_in, std::vector<std::byte>& payload_out) {
    core::detail::packet_reader r(p);
    r.install(std::move(st));
    memory::detail::page_pool pool;
    std::size_t consumed = 0;
    memory::detail::page_slice got;
    auto ec = r.read(wire_in, consumed, pool, got);
    if (ec) return ec;
    REQUIRE(consumed == wire_in.size());
    payload_out.assign(got.bytes().begin(), got.bytes().end());
    return {};
}

}  // namespace

TEST_CASE("derive_key matches manual HASH(K||H||letter||session_id) for A-F", "[kdf]") {
    crypto::provider p = prov();
    const auto K = mpint_encode(bytes_of(k_secret_mag));
    const auto H = bytes_of(k_exchange_hash);
    const auto sid = bytes_of(k_session_id);
    const auto h = crypto::hash_id::sha256;
    const std::size_t n = crypto::hash_output_size(h);

    for (char letter = 'A'; letter <= 'F'; ++letter) {
        INFO("letter " << letter);
        std::vector<std::byte> out(n);
        REQUIRE_FALSE(core::detail::derive_key(p, h, K, H, letter, sid, out));
        const auto expected = manual_derive(p, h, K, H, letter, sid, n);
        REQUIRE(hex(out) == hex(expected));
    }
}

TEST_CASE("derive_key extends past one digest as K1||K2", "[kdf]") {
    crypto::provider p = prov();
    const auto K = mpint_encode(bytes_of(k_secret_mag));
    const auto H = bytes_of(k_exchange_hash);
    const auto sid = bytes_of(k_session_id);
    const auto h = crypto::hash_id::sha256;

    std::vector<std::byte> out(64);
    REQUIRE_FALSE(core::detail::derive_key(p, h, K, H, 'C', sid, out));
    const auto expected = manual_derive(p, h, K, H, 'C', sid, 64);
    REQUIRE(out.size() == 64);
    REQUIRE(hex(out) == hex(expected));
    // Explicitly: first 32 is K1, second 32 is K2 = HASH(K||H||K1).
    REQUIRE(hex(std::span{out}.first(32)) == hex(std::span{expected}.first(32)));
    REQUIRE(hex(std::span{out}.subspan(32)) == hex(std::span{expected}.subspan(32)));
}

TEST_CASE("derive_key of exactly one digest does not extend", "[kdf]") {
    crypto::provider p = prov();
    const auto K = mpint_encode(bytes_of(k_secret_mag));
    const auto H = bytes_of(k_exchange_hash);
    const auto sid = bytes_of(k_session_id);
    const auto h = crypto::hash_id::sha256;

    std::array<std::byte, 32> out{};
    REQUIRE_FALSE(core::detail::derive_key(p, h, K, H, 'A', sid, out));

    // Manual single-block only (no extension).
    std::array<std::byte, 32> k1{};
    crypto::hash_ctx ctx = p.new_hash(h);
    REQUIRE(static_cast<bool>(ctx));
    ctx.update(K);
    ctx.update(H);
    const std::byte letter{static_cast<std::byte>('A')};
    ctx.update(std::span{&letter, 1});
    ctx.update(sid);
    REQUIRE(ctx.final_into(k1));
    REQUIRE(hex(out) == hex(k1));
}

TEST_CASE("client outbound keys match server inbound and vice versa", "[kdf][direction]") {
    crypto::provider p = prov();
    const auto K = mpint_encode(bytes_of(k_secret_mag));
    const auto H = bytes_of(k_exchange_hash);
    const auto sid = bytes_of(k_session_id);
    const auto n = make_nego(core::detail::packet_mode::ctr_encrypt_and_mac,
                             core::detail::packet_mode::ctr_encrypt_and_mac,
                             crypto::cipher_id::aes256_ctr, crypto::cipher_id::aes256_ctr);

    core::detail::direction_state c_out, c_in, s_out, s_in;
    REQUIRE_FALSE(core::detail::make_direction_states(p, n, K, H, sid, core::role::client, c_out, c_in));
    REQUIRE_FALSE(core::detail::make_direction_states(p, n, K, H, sid, core::role::server, s_out, s_in));

    // Random padding prevents byte-identical wire compare; complementary
    // directions must decrypt each other's packets instead.
    const auto payload = bytes_of("hello-kdf-direction");
    std::vector<std::byte> wire;
    std::vector<std::byte> got;

    REQUIRE_FALSE(write_packet(p, std::move(c_out), payload, wire));
    REQUIRE_FALSE(read_packet(p, std::move(s_in), wire, got));
    REQUIRE(hex(got) == hex(payload));

    wire.clear();
    got.clear();
    REQUIRE_FALSE(write_packet(p, std::move(s_out), payload, wire));
    REQUIRE_FALSE(read_packet(p, std::move(c_in), wire, got));
    REQUIRE(hex(got) == hex(payload));

    // Crossed directions must fail MAC / decrypt (proves mapping is not swapped).
    core::detail::direction_state c_out2, c_in2, s_out2, s_in2;
    REQUIRE_FALSE(
        core::detail::make_direction_states(p, n, K, H, sid, core::role::client, c_out2, c_in2));
    REQUIRE_FALSE(
        core::detail::make_direction_states(p, n, K, H, sid, core::role::server, s_out2, s_in2));
    wire.clear();
    REQUIRE_FALSE(write_packet(p, std::move(c_out2), payload, wire));
    got.clear();
    REQUIRE(read_packet(p, std::move(s_out2), wire, got));  // server outbound ≠ client outbound
}

TEST_CASE("make_direction_states sizes match mode table", "[kdf][direction]") {
    crypto::provider p = prov();
    const auto K = mpint_encode(bytes_of(k_secret_mag));
    const auto H = bytes_of(k_exchange_hash);
    const auto sid = bytes_of(k_session_id);
    const auto h = crypto::hash_id::sha256;

    SECTION("ctr: key=cipher_key_size, iv=16, mac=hash_output_size") {
        const auto n = make_nego(core::detail::packet_mode::ctr_encrypt_then_mac,
                                 core::detail::packet_mode::ctr_encrypt_then_mac,
                                 crypto::cipher_id::aes128_ctr, crypto::cipher_id::aes192_ctr,
                                 crypto::hash_id::sha256, crypto::hash_id::sha512);
        // Prove derive sizes used by the table.
        std::vector<std::byte> key(crypto::cipher_key_size(crypto::cipher_id::aes128_ctr));
        std::vector<std::byte> iv(16);
        std::vector<std::byte> mac(crypto::hash_output_size(crypto::hash_id::sha256));
        REQUIRE_FALSE(core::detail::derive_key(p, h, K, H, 'C', sid, key));
        REQUIRE_FALSE(core::detail::derive_key(p, h, K, H, 'A', sid, iv));
        REQUIRE_FALSE(core::detail::derive_key(p, h, K, H, 'E', sid, mac));
        REQUIRE(key.size() == 16);
        REQUIRE(iv.size() == 16);
        REQUIRE(mac.size() == 32);

        core::detail::direction_state out, in;
        REQUIRE_FALSE(core::detail::make_direction_states(p, n, K, H, sid, core::role::client, out, in));
        REQUIRE(out.mode == core::detail::packet_mode::ctr_encrypt_then_mac);
        REQUIRE(out.block_size == 16);
        REQUIRE(out.mac_length == 32);
        REQUIRE(static_cast<bool>(out.cipher));
        REQUIRE(static_cast<bool>(out.mac));
        REQUIRE(in.mode == core::detail::packet_mode::ctr_encrypt_then_mac);
        REQUIRE(in.block_size == 16);
        REQUIRE(in.mac_length == 64);  // sha512 MAC on s2c
        REQUIRE(static_cast<bool>(in.cipher));
        REQUIRE(static_cast<bool>(in.mac));
    }

    SECTION("gcm: key=cipher_key_size, iv=12, mac=0") {
        const auto n = make_nego(core::detail::packet_mode::gcm, core::detail::packet_mode::gcm,
                                 crypto::cipher_id::aes256_gcm, crypto::cipher_id::aes128_gcm);
        std::vector<std::byte> key(32);
        std::vector<std::byte> iv(12);
        REQUIRE_FALSE(core::detail::derive_key(p, h, K, H, 'C', sid, key));
        REQUIRE_FALSE(core::detail::derive_key(p, h, K, H, 'A', sid, iv));

        core::detail::direction_state out, in;
        REQUIRE_FALSE(core::detail::make_direction_states(p, n, K, H, sid, core::role::client, out, in));
        REQUIRE(out.mode == core::detail::packet_mode::gcm);
        REQUIRE(out.block_size == 16);
        REQUIRE(out.mac_length == 16);
        REQUIRE(static_cast<bool>(out.aead));
        REQUIRE_FALSE(static_cast<bool>(out.mac));
        REQUIRE(in.mode == core::detail::packet_mode::gcm);
        REQUIRE(static_cast<bool>(in.aead));
    }

    SECTION("chacha20_poly1305: key=64, iv=0, mac=0") {
        const auto n =
            make_nego(core::detail::packet_mode::chacha20_poly1305,
                      core::detail::packet_mode::chacha20_poly1305, crypto::cipher_id::chacha20,
                      crypto::cipher_id::chacha20);
        std::vector<std::byte> key(64);
        REQUIRE_FALSE(core::detail::derive_key(p, h, K, H, 'C', sid, key));
        REQUIRE(key.size() == 64);

        core::detail::direction_state out, in;
        REQUIRE_FALSE(core::detail::make_direction_states(p, n, K, H, sid, core::role::client, out, in));
        REQUIRE(out.mode == core::detail::packet_mode::chacha20_poly1305);
        REQUIRE(out.block_size == 8);
        REQUIRE(out.mac_length == 16);
        REQUIRE(static_cast<bool>(out.cipher));
        REQUIRE(static_cast<bool>(out.length_cipher));
        REQUIRE_FALSE(static_cast<bool>(out.mac));
    }
}

TEST_CASE("chacha20-poly1305 loads distinct payload and length keys", "[kdf][chacha]") {
    crypto::provider p = prov();
    const auto K = mpint_encode(bytes_of(k_secret_mag));
    const auto H = bytes_of(k_exchange_hash);
    const auto sid = bytes_of(k_session_id);
    const auto n =
        make_nego(core::detail::packet_mode::chacha20_poly1305,
                  core::detail::packet_mode::chacha20_poly1305, crypto::cipher_id::chacha20,
                  crypto::cipher_id::chacha20);

    std::vector<std::byte> key64(64);
    REQUIRE_FALSE(core::detail::derive_key(p, crypto::hash_id::sha256, K, H, 'C', sid, key64));
    REQUIRE(hex(std::span{key64}.first(32)) != hex(std::span{key64}.subspan(32)));

    core::detail::direction_state out, in;
    REQUIRE_FALSE(core::detail::make_direction_states(p, n, K, H, sid, core::role::client, out, in));
    REQUIRE(static_cast<bool>(out.cipher));
    REQUIRE(static_cast<bool>(out.length_cipher));
    REQUIRE(static_cast<bool>(in.cipher));
    REQUIRE(static_cast<bool>(in.length_cipher));
}

TEST_CASE("derived direction_states round-trip a packet client to server", "[kdf][e2e]") {
    crypto::provider p = prov();
    const auto K = mpint_encode(bytes_of(k_secret_mag));
    const auto H = bytes_of(k_exchange_hash);
    const auto sid = bytes_of(k_session_id);
    const auto n = make_nego(core::detail::packet_mode::ctr_encrypt_and_mac,
                             core::detail::packet_mode::ctr_encrypt_and_mac,
                             crypto::cipher_id::aes256_ctr, crypto::cipher_id::aes256_ctr);

    core::detail::direction_state c_out, c_in, s_out, s_in;
    REQUIRE_FALSE(core::detail::make_direction_states(p, n, K, H, sid, core::role::client, c_out, c_in));
    REQUIRE_FALSE(core::detail::make_direction_states(p, n, K, H, sid, core::role::server, s_out, s_in));

    const auto payload = bytes_of("e2e-packet-payload");
    std::vector<std::byte> wire;
    REQUIRE_FALSE(write_packet(p, std::move(c_out), payload, wire));

    std::vector<std::byte> got;
    REQUIRE_FALSE(read_packet(p, std::move(s_in), wire, got));
    REQUIRE(hex(got) == hex(payload));

    // Opposite direction.
    wire.clear();
    got.clear();
    REQUIRE_FALSE(write_packet(p, std::move(s_out), payload, wire));
    REQUIRE_FALSE(read_packet(p, std::move(c_in), wire, got));
    REQUIRE(hex(got) == hex(payload));
}

TEST_CASE("derived CBC direction_states round-trip a packet", "[kdf][e2e][gm]") {
    crypto::provider p = prov();
    const auto K = mpint_encode(bytes_of(k_secret_mag));
    const auto H = bytes_of(k_exchange_hash);
    const auto sid = bytes_of(k_session_id);
    const core::detail::packet_mode modes[] = {
        core::detail::packet_mode::cbc_encrypt_and_mac,
        core::detail::packet_mode::cbc_encrypt_then_mac,
    };
    for (auto mode : modes) {
        INFO("mode=" << static_cast<int>(mode));
        const auto n = make_nego(mode, mode, crypto::cipher_id::sm4_cbc, crypto::cipher_id::sm4_cbc,
                                 crypto::hash_id::sm3, crypto::hash_id::sm3);

        core::detail::direction_state c_out, c_in, s_out, s_in;
        REQUIRE_FALSE(core::detail::make_direction_states(p, n, K, H, sid, core::role::client, c_out, c_in));
        REQUIRE_FALSE(core::detail::make_direction_states(p, n, K, H, sid, core::role::server, s_out, s_in));
        REQUIRE(c_out.mode == mode);
        REQUIRE(s_in.mode == mode);

        const auto payload = bytes_of("e2e-cbc-packet");
        std::vector<std::byte> wire;
        REQUIRE_FALSE(write_packet(p, std::move(c_out), payload, wire));

        std::vector<std::byte> got;
        REQUIRE_FALSE(read_packet(p, std::move(s_in), wire, got));
        REQUIRE(hex(got) == hex(payload));

        wire.clear();
        got.clear();
        REQUIRE_FALSE(write_packet(p, std::move(s_out), payload, wire));
        REQUIRE_FALSE(read_packet(p, std::move(c_in), wire, got));
        REQUIRE(hex(got) == hex(payload));
    }
}
