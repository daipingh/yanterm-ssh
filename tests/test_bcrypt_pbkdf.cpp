#include <catch2/catch_test_macros.hpp>
#include <yanterm-ssh/crypto/detail/bcrypt_pbkdf.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>
#include "hex_util.hpp"

#include <array>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

namespace {

crypto::provider prov() {
    static crypto::openssl_backend backend;
    return crypto::provider::wrap(backend);
}

}  // namespace

TEST_CASE("bcrypt_pbkdf matches OpenBSD golden password/salt/12", "[crypto][bcrypt]") {
    crypto::provider p = prov();
    auto pass = bytes_of("password");
    auto salt = bytes_of("salt");
    std::array<std::byte, 32> out{};
    REQUIRE(crypto::detail::bcrypt_pbkdf(p, pass, salt, 12, out));
    REQUIRE(hex(out) == "1ae42c05d487bc02f64921a4ebe4ea93"
                        "bcacfe135fda99974c06b7b01fae149a");
}

TEST_CASE("bcrypt_pbkdf rejects empty password or zero rounds", "[crypto][bcrypt]") {
    crypto::provider p = prov();
    auto salt = bytes_of("salt");
    std::array<std::byte, 32> out{};
    REQUIRE_FALSE(crypto::detail::bcrypt_pbkdf(p, {}, salt, 12, out));
    REQUIRE_FALSE(crypto::detail::bcrypt_pbkdf(
        p, bytes_of("password"), salt, 0, out));
}
