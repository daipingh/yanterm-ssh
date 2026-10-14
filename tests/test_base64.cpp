#include <catch2/catch_test_macros.hpp>
#include <yanterm-ssh/keys/detail/base64.hpp>

#include "hex_util.hpp"

#include <vector>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

TEST_CASE("base64 encode with and without padding", "[keys][base64]") {
    auto in = bytes_of("hello");
    REQUIRE(keys::detail::base64_encode(in, true) == "aGVsbG8=");
    REQUIRE(keys::detail::base64_encode(in, false) == "aGVsbG8");
}

TEST_CASE("base64 decode accepts missing padding", "[keys][base64]") {
    std::vector<std::byte> out;
    REQUIRE(keys::detail::base64_decode("aGVsbG8", out));
    REQUIRE(hex(out) == "68656c6c6f");
}
