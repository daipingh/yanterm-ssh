#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/core/detail/host_key.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/detail/error.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#ifndef YANTERM_SSH_FIXTURE_DIR
#error "YANTERM_SSH_FIXTURE_DIR must be defined"
#endif

using namespace yanterm::ssh;

namespace {

crypto::provider prov() {
    static crypto::openssl_backend backend;
    return crypto::provider::wrap(backend);
}

std::vector<std::byte> load_fixture(std::string_view name) {
    const std::string path = std::string{YANTERM_SSH_FIXTURE_DIR} + "/" + std::string{name};
    std::ifstream in{path, std::ios::binary};
    REQUIRE(in);
    in.seekg(0, std::ios::end);
    const auto n = static_cast<std::size_t>(in.tellg());
    in.seekg(0, std::ios::beg);
    std::vector<std::byte> out(n);
    if (n > 0) {
        in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(n));
        REQUIRE(in);
    }
    return out;
}

void write_ssh_string(wire::writer& w, std::string_view s) { w.write_string(s); }

void write_ssh_string_bytes(wire::writer& w, std::span<const std::byte> s) { w.write_string(s); }

}  // namespace

TEST_CASE("parse ed25519 host key blob from OpenSSH", "[kex][host_key]") {
    const auto blob = load_fixture("ed25519.blob");
    core::detail::host_key_view key;
    REQUIRE_FALSE(core::detail::parse_host_key(blob, key));
    REQUIRE(key.algorithm_name == "ssh-ed25519");
    REQUIRE(key.algorithm == crypto::sig_id::ed25519);
    REQUIRE(key.material.a.size() == 32);
    REQUIRE(key.blob.size() == blob.size());
    REQUIRE(key.blob.data() == blob.data());
}

TEST_CASE("parse ecdsa-nistp256 host key blob from OpenSSH", "[kex][host_key]") {
    const auto blob = load_fixture("ecdsa.blob");
    core::detail::host_key_view key;
    REQUIRE_FALSE(core::detail::parse_host_key(blob, key));
    REQUIRE(key.algorithm_name == "ecdsa-sha2-nistp256");
    REQUIRE(key.algorithm == crypto::sig_id::ecdsa_nistp256);
    REQUIRE(key.material.a.size() == 65);
    REQUIRE(std::to_integer<std::uint8_t>(key.material.a[0]) == 0x04);
}

TEST_CASE("parse rsa host key blob from OpenSSH", "[kex][host_key]") {
    const auto blob = load_fixture("rsa.blob");
    core::detail::host_key_view key;
    REQUIRE_FALSE(core::detail::parse_host_key(blob, key));
    REQUIRE(key.algorithm_name == "ssh-rsa");
    REQUIRE_FALSE(key.material.a.empty());  // n
    REQUIRE_FALSE(key.material.b.empty());  // e
    // Typical public exponent 65537 = 01 00 01.
    REQUIRE(key.material.b.size() == 3);
    REQUIRE(std::to_integer<std::uint8_t>(key.material.b[0]) == 0x01);
    REQUIRE(std::to_integer<std::uint8_t>(key.material.b[1]) == 0x00);
    REQUIRE(std::to_integer<std::uint8_t>(key.material.b[2]) == 0x01);
}

TEST_CASE("truncated host key blob yields invalid_host_key", "[kex][host_key]") {
    const auto blob = load_fixture("ed25519.blob");
    const auto half = std::span{blob}.first(blob.size() / 2);
    core::detail::host_key_view key;
    const auto ec = core::detail::parse_host_key(half, key);
    REQUIRE(ec == code::invalid_host_key);
}

TEST_CASE("ecdsa curve name mismatch yields invalid_host_key", "[kex][host_key]") {
    // Hand-build: ecdsa-sha2-nistp256 + "nistp384" + a 65-byte Q.
    wire::writer w;
    write_ssh_string(w, "ecdsa-sha2-nistp256");
    write_ssh_string(w, "nistp384");
    std::array<std::byte, 65> q{};
    q[0] = std::byte{0x04};
    write_ssh_string_bytes(w, q);

    core::detail::host_key_view key;
    const auto ec = core::detail::parse_host_key(w.data(), key);
    REQUIRE(ec == code::invalid_host_key);
}

TEST_CASE("unknown host key algorithm yields unsupported_algorithm", "[kex][host_key]") {
    wire::writer w;
    write_ssh_string(w, "ssh-dss");
    write_ssh_string_bytes(w, std::span<const std::byte>{});

    core::detail::host_key_view key;
    const auto ec = core::detail::parse_host_key(w.data(), key);
    REQUIRE(ec == code::unsupported_algorithm);
}

TEST_CASE("ed25519 sign/encode/verify round-trip over message.bin", "[kex][host_key]") {
    crypto::provider p = prov();
    const auto message = load_fixture("message.bin");
    const auto blob = load_fixture("ed25519.blob");
    const auto seed = load_fixture("ed25519.seed");

    core::detail::host_key_view key;
    REQUIRE_FALSE(core::detail::parse_host_key(blob, key));

    crypto::private_key_material sk_mat{crypto::sig_id::ed25519, seed, key.material.a};
    crypto::signing_key sk = p.new_signing_key(sk_mat);
    REQUIRE(static_cast<bool>(sk));

    std::array<std::byte, 64> raw_sig{};
    std::size_t sig_len = 0;
    REQUIRE(sk.sign(message, raw_sig, sig_len));
    REQUIRE(sig_len == 64);

    wire::writer sig_w;
    REQUIRE_FALSE(core::detail::encode_signature("ssh-ed25519", std::span{raw_sig}.first(sig_len), sig_w));

    REQUIRE_FALSE(core::detail::verify_signature(p, key, "ssh-ed25519", sig_w.data(), message));

    // Tamper one byte of the signature payload → fail.
    auto tampered = std::vector<std::byte>(sig_w.data().begin(), sig_w.data().end());
    tampered.back() ^= std::byte{0x01};
    REQUIRE(core::detail::verify_signature(p, key, "ssh-ed25519", tampered, message)
            == code::signature_verification_failed);
}

TEST_CASE("fixture verify vectors for ed25519, ecdsa-nistp256, rsa-sha2-256",
          "[kex][host_key]") {
    crypto::provider p = prov();
    const auto message = load_fixture("message.bin");

    SECTION("ssh-ed25519") {
        const auto blob = load_fixture("ed25519.blob");
        const auto sig = load_fixture("ed25519.sig");
        core::detail::host_key_view key;
        REQUIRE_FALSE(core::detail::parse_host_key(blob, key));
        REQUIRE_FALSE(core::detail::verify_signature(p, key, "ssh-ed25519", sig, message));
    }
    SECTION("ecdsa-sha2-nistp256") {
        const auto blob = load_fixture("ecdsa.blob");
        const auto sig = load_fixture("ecdsa.sig");
        core::detail::host_key_view key;
        REQUIRE_FALSE(core::detail::parse_host_key(blob, key));
        REQUIRE_FALSE(core::detail::verify_signature(p, key, "ecdsa-sha2-nistp256", sig, message));
    }
    SECTION("rsa-sha2-256") {
        const auto blob = load_fixture("rsa.blob");
        const auto sig = load_fixture("rsa.sig");
        core::detail::host_key_view key;
        REQUIRE_FALSE(core::detail::parse_host_key(blob, key));
        // Pubkey blob name is ssh-rsa; signature / negotiated name is rsa-sha2-256.
        REQUIRE(key.algorithm_name == "ssh-rsa");
        REQUIRE_FALSE(core::detail::verify_signature(p, key, "rsa-sha2-256", sig, message));
    }
}

TEST_CASE("rsa signature algorithm follows signature blob not pubkey name", "[kex][host_key]") {
    crypto::provider p = prov();
    const auto message = load_fixture("message.bin");
    const auto blob = load_fixture("rsa.blob");
    const auto sig = load_fixture("rsa.sig");  // name inside: rsa-sha2-256

    core::detail::host_key_view key;
    REQUIRE_FALSE(core::detail::parse_host_key(blob, key));
    REQUIRE(key.algorithm_name == "ssh-rsa");

    SECTION("expected rsa-sha2-256 matches signature blob → SHA-256 path succeeds") {
        REQUIRE_FALSE(core::detail::verify_signature(p, key, "rsa-sha2-256", sig, message));
    }
    SECTION("expected rsa-sha2-512 mismatches signature blob name → fail") {
        REQUIRE(core::detail::verify_signature(p, key, "rsa-sha2-512", sig, message)
                == code::signature_verification_failed);
    }
}

TEST_CASE("encode_host_key ed25519 matches OpenSSH blob byte-for-byte", "[kex][host_key]") {
    const auto blob = load_fixture("ed25519.blob");
    core::detail::host_key_view key;
    REQUIRE_FALSE(core::detail::parse_host_key(blob, key));

    wire::writer w;
    REQUIRE_FALSE(core::detail::encode_host_key(key.material, w));
    REQUIRE(w.size() == blob.size());
    REQUIRE(std::equal(w.data().begin(), w.data().end(), blob.begin()));
}
