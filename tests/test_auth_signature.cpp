#include <catch2/catch_test_macros.hpp>
#include "handshake_fixture.hpp"

#include <yanterm-ssh/core/detail/auth_signature.hpp>
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

using core::detail::pick_userauth_sig_alg;
using core::detail::write_publickey_signed_data;

TEST_CASE("pick rsa-sha2-256 from server-sig-algs", "[auth][signature]") {
    REQUIRE(pick_userauth_sig_alg("ssh-rsa", "rsa-sha2-512,rsa-sha2-256", false)
            == "rsa-sha2-256");
    REQUIRE(pick_userauth_sig_alg("ssh-rsa", "", false) == "rsa-sha2-256");
    REQUIRE(pick_userauth_sig_alg("ssh-rsa", "ssh-rsa", false).empty());
    REQUIRE(pick_userauth_sig_alg("ssh-rsa", "ssh-rsa", true) == "ssh-rsa");
    REQUIRE(pick_userauth_sig_alg("ssh-ed25519", "", false) == "ssh-ed25519");
}

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
