#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/crypto/openssl.hpp>

#include <array>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

using namespace yanterm::ssh;

namespace {

crypto::provider prov() {
    static crypto::openssl_backend backend;
    return crypto::provider::wrap(backend);
}


std::span<const std::byte> bytes_of(std::string_view s) {
    return {reinterpret_cast<const std::byte*>(s.data()), s.size()};
}

std::string hex(std::span<const std::byte> in) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    for (std::byte b : in) {
        out.push_back(kDigits[std::to_integer<unsigned>(b) >> 4]);
        out.push_back(kDigits[std::to_integer<unsigned>(b) & 0x0Fu]);
    }
    return out;
}

std::vector<std::byte> unhex(std::string_view s) {
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return c - 'A' + 10;
    };
    std::vector<std::byte> out;
    for (std::size_t i = 0; i + 1 < s.size(); i += 2) {
        out.push_back(static_cast<std::byte>(nibble(s[i]) * 16 + nibble(s[i + 1])));
    }
    return out;
}

}  // namespace

TEST_CASE("openssl backend advertises the M1 algorithm set", "[crypto][openssl]") {
    crypto::provider p = prov();

    REQUIRE(p.supports(crypto::hash_id::sha1));
    REQUIRE(p.supports(crypto::hash_id::sha256));
    REQUIRE(p.supports(crypto::hash_id::sha384));
    REQUIRE(p.supports(crypto::hash_id::sha512));

    REQUIRE(p.supports(crypto::mac_id::hmac_sha1));
    REQUIRE(p.supports(crypto::mac_id::hmac_sha256));
    REQUIRE(p.supports(crypto::mac_id::hmac_sha512));
    REQUIRE(p.supports(crypto::hash_id::sm3));
    REQUIRE(p.supports(crypto::mac_id::hmac_sm3));
}

// FIPS 180-2 / RFC 6234 well-known "abc" digests.
TEST_CASE("hashes match published test vectors", "[crypto][openssl]") {
    crypto::provider p = prov();

    struct vec { crypto::hash_id id; std::string_view expected; };
    const vec vs[] = {
        {crypto::hash_id::sha1,   "a9993e364706816aba3e25717850c26c9cd0d89d"},
        {crypto::hash_id::sha256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {crypto::hash_id::sha384, "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                                  "8086072ba1e7cc2358baeca134c825a7"},
        {crypto::hash_id::sha512, "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                                  "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
    };

    for (const vec& v : vs) {
        std::array<std::byte, 64> out{};
        const std::size_t n = crypto::hash_output_size(v.id);
        INFO("hash_id " << static_cast<int>(v.id));
        REQUIRE(p.hash(v.id, bytes_of("abc"), std::span{out}.first(n)));
        REQUIRE(hex(std::span{out}.first(n)) == v.expected);
    }
}

TEST_CASE("hash context supports incremental update", "[crypto][openssl]") {
    crypto::provider p = prov();

    crypto::hash_ctx h = p.new_hash(crypto::hash_id::sha256);
    REQUIRE(static_cast<bool>(h));
    h.update(bytes_of("a"));
    h.update(bytes_of("b"));
    h.update(bytes_of("c"));
    std::array<std::byte, 32> out{};
    REQUIRE(h.final_into(out));
    REQUIRE(hex(out) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_CASE("hash context resets after final and can be reused", "[crypto][openssl]") {
    crypto::provider p = prov();

    crypto::hash_ctx h = p.new_hash(crypto::hash_id::sha256);
    std::array<std::byte, 32> first{};
    std::array<std::byte, 32> second{};
    h.update(bytes_of("abc"));
    REQUIRE(h.final_into(first));
    h.update(bytes_of("abc"));
    REQUIRE(h.final_into(second));
    REQUIRE(hex(first) == hex(second));
}

// RFC 4231 section 4.2: key = 20 bytes of 0x0b, data = "Hi There".
TEST_CASE("hmac matches RFC 4231 test case 1", "[crypto][openssl]") {
    crypto::provider p = prov();

    const std::vector<std::byte> key(20, std::byte{0x0b});

    SECTION("hmac-sha256") {
        crypto::hmac_ctx m = p.new_hmac(crypto::hash_id::sha256, key);
        REQUIRE(static_cast<bool>(m));
        m.update(bytes_of("Hi There"));
        std::array<std::byte, 32> out{};
        REQUIRE(m.final_into(out));
        REQUIRE(hex(out) == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }
    SECTION("hmac-sha512") {
        crypto::hmac_ctx m = p.new_hmac(crypto::hash_id::sha512, key);
        m.update(bytes_of("Hi There"));
        std::array<std::byte, 64> out{};
        REQUIRE(m.final_into(out));
        REQUIRE(hex(out) == "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
                            "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
    }
}

// RFC 2202 section 3, test case 1, for the legacy hmac-sha1 tail.
TEST_CASE("hmac-sha1 matches RFC 2202 test case 1", "[crypto][openssl]") {
    crypto::provider p = prov();

    const std::vector<std::byte> key(20, std::byte{0x0b});
    crypto::hmac_ctx m = p.new_hmac(crypto::hash_id::sha1, key);
    m.update(bytes_of("Hi There"));
    std::array<std::byte, 20> out{};
    REQUIRE(m.final_into(out));
    REQUIRE(hex(out) == "b617318655057264e28bc0b6fb378c8ef146be00");
}

TEST_CASE("hmac context resets after final", "[crypto][openssl]") {
    crypto::provider p = prov();

    const std::vector<std::byte> key(20, std::byte{0x0b});
    crypto::hmac_ctx m = p.new_hmac(crypto::hash_id::sha256, key);
    std::array<std::byte, 32> a{};
    std::array<std::byte, 32> b{};
    m.update(bytes_of("Hi There"));
    REQUIRE(m.final_into(a));
    m.update(bytes_of("Hi There"));
    REQUIRE(m.final_into(b));
    REQUIRE(hex(a) == hex(b));
}

TEST_CASE("random_bytes fills the buffer and varies", "[crypto][openssl]") {
    crypto::provider p = prov();

    std::array<std::byte, 32> a{};
    std::array<std::byte, 32> b{};
    REQUIRE_FALSE(static_cast<bool>(p.random_bytes(a)));
    REQUIRE_FALSE(static_cast<bool>(p.random_bytes(b)));
    REQUIRE(hex(a) != hex(b));
}

TEST_CASE("constant_time_eq agrees with a plain comparison", "[crypto][openssl]") {
    crypto::provider p = prov();

    const auto a = unhex("00112233445566778899aabbccddeeff");
    const auto b = unhex("00112233445566778899aabbccddeeff");
    const auto c = unhex("00112233445566778899aabbccddee00");
    REQUIRE(p.constant_time_eq(a, b));
    REQUIRE_FALSE(p.constant_time_eq(a, c));
}
