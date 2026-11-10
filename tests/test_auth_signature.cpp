#include <catch2/catch_test_macros.hpp>
#include "handshake_fixture.hpp"

#include <yanterm-ssh/core/detail/auth_signature.hpp>
#include <yanterm-ssh/detail/error.hpp>
#include <yanterm-ssh/wire/types.hpp>
#include <yanterm-ssh/core/detail/host_key.hpp>
#include <yanterm-ssh/wire/types.hpp>
#include <yanterm-ssh/crypto/algorithms.hpp>
#include <yanterm-ssh/keys/public_key.hpp>

#include <array>
#include <cstddef>
#include <span>
#include <vector>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

using core::detail::write_publickey_signed_data;

TEST_CASE("publickey signed data verifies with provider", "[auth][signature]") {
    auto p = prov();
    std::array<std::byte, crypto::max_generated_key_storage> storage{};
    crypto::private_key_material priv{};
    REQUIRE(p.generate_keypair(crypto::sig_id::ed25519, 0, priv, storage));

    crypto::public_key_material pub{crypto::sig_id::ed25519, priv.public_key, {}};
    keys::public_key pk;
    REQUIRE_FALSE(keys::public_key::from_material(pub, pk));

    const std::byte session_id[] = {std::byte{0x11}, std::byte{0x22}, std::byte{0x33}};
    wire::writer data_w;
    write_publickey_signed_data(data_w, session_id, "alice", "ssh-connection", "ssh-ed25519",
                                pk.blob());

    crypto::signing_key sk = p.new_signing_key(priv);
    REQUIRE(static_cast<bool>(sk));
    std::array<std::byte, crypto::max_signature_size> raw{};
    std::size_t len = 0;
    REQUIRE(sk.sign(data_w.data(), raw, len));
    REQUIRE(len == 64);

    wire::writer sig_w;
    REQUIRE_FALSE(core::detail::encode_signature("ssh-ed25519", std::span{raw}.first(len), sig_w));

    core::detail::host_key_view key;
    REQUIRE_FALSE(core::detail::parse_host_key(pk.blob(), key));
    REQUIRE_FALSE(core::detail::verify_signature(p, key, "ssh-ed25519", sig_w.data(), data_w.data()));
}

TEST_CASE("host-bound signed data places the server host key after the user key", "[auth][signature]") {
    auto p = prov();
    std::array<std::byte, crypto::max_generated_key_storage> storage{};
    crypto::private_key_material priv{};
    REQUIRE(p.generate_keypair(crypto::sig_id::ed25519, 0, priv, storage));
    crypto::public_key_material pub{crypto::sig_id::ed25519, priv.public_key, {}};
    keys::public_key pk;
    REQUIRE_FALSE(keys::public_key::from_material(pub, pk));

    const std::byte session_id[] = {std::byte{1}, std::byte{2}};
    const std::byte host_key[] = {std::byte{9}, std::byte{8}, std::byte{7}};
    wire::writer plain;
    write_publickey_signed_data(plain, session_id, "alice", "ssh-connection", "ssh-ed25519", pk.blob(),
                                "publickey", host_key);
    wire::writer bound;
    write_publickey_signed_data(bound, session_id, "alice", "ssh-connection", "ssh-ed25519", pk.blob(),
                                auth::method_hostbound_publickey, host_key);

    auto fields = [&](std::span<const std::byte> raw) {
        wire::reader r{raw};
        struct out {
            std::string_view method;
            bool has_signature = false;
            std::span<const std::byte> host;
            bool has_host = false;
            bool empty = false;
        } got;
        std::span<const std::byte> sid;
        std::uint8_t id = 0;
        std::string_view user;
        std::string_view service;
        std::string_view alg;
        std::span<const std::byte> blob;
        REQUIRE(r.read_string(sid));
        REQUIRE(sid.size() == 2);
        REQUIRE(r.read_byte(id));
        REQUIRE(id == static_cast<std::uint8_t>(wire::msg::userauth_request));
        REQUIRE(r.read_string(user));
        REQUIRE(user == "alice");
        REQUIRE(r.read_string(service));
        REQUIRE(service == "ssh-connection");
        REQUIRE(r.read_string(got.method));
        REQUIRE(r.read_bool(got.has_signature));
        REQUIRE(got.has_signature);
        REQUIRE(r.read_string(alg));
        REQUIRE(alg == "ssh-ed25519");
        REQUIRE(r.read_string(blob));
        REQUIRE(blob.size() == pk.blob().size());
        if (!r.empty()) {
            REQUIRE(r.read_string(got.host));
            got.has_host = true;
        }
        got.empty = r.empty();
        return got;
    };

    const auto plain_fields = fields(plain.data());
    REQUIRE(plain_fields.method == "publickey");
    REQUIRE_FALSE(plain_fields.has_host);
    REQUIRE(plain_fields.empty);

    const auto bound_fields = fields(bound.data());
    REQUIRE(bound_fields.method == auth::method_hostbound_publickey);
    REQUIRE(bound_fields.has_host);
    REQUIRE(bound_fields.host.size() == 3);
    REQUIRE(bound_fields.host[0] == std::byte{9});
    REQUIRE(bound_fields.empty);

    crypto::signing_key sk = p.new_signing_key(priv);
    REQUIRE(static_cast<bool>(sk));
    std::array<std::byte, crypto::max_signature_size> raw{};
    std::size_t len = 0;
    REQUIRE(sk.sign(bound.data(), raw, len));
    wire::writer sig_w;
    REQUIRE_FALSE(core::detail::encode_signature("ssh-ed25519", std::span{raw}.first(len), sig_w));
    core::detail::host_key_view key;
    REQUIRE_FALSE(core::detail::parse_host_key(pk.blob(), key));
    REQUIRE_FALSE(core::detail::verify_userauth_publickey(
        p, session_id, "alice", "ssh-connection", "ssh-ed25519", pk.blob(), sig_w.data(),
        auth::method_hostbound_publickey, host_key));
    REQUIRE(core::detail::verify_userauth_publickey(
                p, session_id, "alice", "ssh-connection", "ssh-ed25519", pk.blob(), sig_w.data(),
                "publickey", {}) == code::signature_verification_failed);
}
