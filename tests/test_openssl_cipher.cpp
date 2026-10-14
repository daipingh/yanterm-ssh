#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/crypto/openssl.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

using namespace yanterm::ssh;

namespace {

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

std::string hex(std::span<const std::byte> in) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    for (std::byte b : in) {
        out.push_back(kDigits[std::to_integer<unsigned>(b) >> 4]);
        out.push_back(kDigits[std::to_integer<unsigned>(b) & 0x0Fu]);
    }
    return out;
}

crypto::provider prov() {
    static crypto::openssl_backend backend;
    return crypto::provider::wrap(backend);
}

[[nodiscard]] bool aead_feed(auto&& update, std::span<const std::byte> in, std::span<std::byte> out,
                             std::size_t chunk) {
    if (out.size() < in.size()) return false;
    if (!update(std::span<const std::byte>{}, std::span<std::byte>{})) return false;
    std::size_t off = 0;
    while (off < in.size()) {
        const std::size_t n = std::min(chunk, in.size() - off);
        if (!update(in.subspan(off, n), out.subspan(off, n))) return false;
        off += n;
    }
    return true;
}

}  // namespace

// NIST SP 800-38A section F.5.1, AES-128-CTR.
TEST_CASE("aes-128-ctr matches NIST SP 800-38A F.5.1", "[crypto][openssl][cipher]") {
    const auto key = unhex("2b7e151628aed2a6abf7158809cf4f3c");
    const auto iv  = unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    const auto plain = unhex(
        "6bc1bee22e409f96e93d7e117393172a"
        "ae2d8a571e03ac9c9eb76fac45af8e51");
    const std::string expected =
        "874d6191b620e3261bef6864990db6ce"
        "9806f66b7970fdff8617187bb9fffdff";

    crypto::provider p = prov();
    crypto::cipher c = p.new_cipher(crypto::cipher_id::aes128_ctr, key, true);
    REQUIRE(static_cast<bool>(c));
    REQUIRE(c.set_iv(iv));

    std::vector<std::byte> out(plain.size());
    REQUIRE(c.update(plain, out));
    REQUIRE(hex(out) == expected);
}

TEST_CASE("aes-ctr keeps its counter across calls", "[crypto][openssl][cipher]") {
    const auto key = unhex("2b7e151628aed2a6abf7158809cf4f3c");
    const auto iv  = unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    const auto block1 = unhex("6bc1bee22e409f96e93d7e117393172a");
    const auto block2 = unhex("ae2d8a571e03ac9c9eb76fac45af8e51");

    crypto::provider p = prov();
    crypto::cipher c = p.new_cipher(crypto::cipher_id::aes128_ctr, key, true);
    REQUIRE(c.set_iv(iv));

    std::vector<std::byte> o1(16);
    std::vector<std::byte> o2(16);
    REQUIRE(c.update(block1, o1));
    REQUIRE(c.update(block2, o2));
    // Splitting the input must give the same keystream as one call.
    REQUIRE(hex(o1) == "874d6191b620e3261bef6864990db6ce");
    REQUIRE(hex(o2) == "9806f66b7970fdff8617187bb9fffdff");
}

TEST_CASE("aes-ctr round-trips in place", "[crypto][openssl][cipher]") {
    const auto key = unhex("2b7e151628aed2a6abf7158809cf4f3c");
    const auto iv  = unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    std::vector<std::byte> data = unhex("00112233445566778899aabbccddeeff");
    const std::string original = hex(data);

    crypto::provider p = prov();
    {
        crypto::cipher c = p.new_cipher(crypto::cipher_id::aes128_ctr, key, true);
        REQUIRE(c.set_iv(iv));
        REQUIRE(c.update(data, data));   // in place
    }
    REQUIRE(hex(data) != original);
    {
        crypto::cipher c = p.new_cipher(crypto::cipher_id::aes128_ctr, key, true);
        REQUIRE(c.set_iv(iv));
        REQUIRE(c.update(data, data));
    }
    REQUIRE(hex(data) == original);
}

// NIST GCM test vectors, "Test Case 16" from the GCM specification.
TEST_CASE("aes-256-gcm seals and opens with aad", "[crypto][openssl][aead]") {
    const auto key = unhex("feffe9928665731c6d6a8f9467308308"
                           "feffe9928665731c6d6a8f9467308308");
    const auto iv  = unhex("cafebabefacedbaddecaf888");
    const auto aad = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    const auto plain = unhex(
        "d9313225f88406e5a55909c5aff5269a"
        "86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b39");
    const std::string expected_cipher =
        "522dc1f099567d07f47f37a32a84427d"
        "643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838"
        "c5f61e6393ba7a0abcc9f662";
    const std::string expected_tag = "76fc6ece0f4e1768cddf8853bb2d551b";

    const std::size_t chunks[] = {1, 15, 16, 17, plain.size()};
    for (std::size_t chunk : chunks) {
        SECTION("chunk " + std::to_string(chunk)) {
            crypto::provider p = prov();
            crypto::aead_cipher sealer = p.new_aead(crypto::cipher_id::aes256_gcm, key, true);
            crypto::aead_cipher opener = p.new_aead(crypto::cipher_id::aes256_gcm, key, false);
            REQUIRE(static_cast<bool>(sealer));
            REQUIRE(static_cast<bool>(opener));

            std::vector<std::byte> ct(plain.size());
            std::array<std::byte, 16> tag{};
            REQUIRE(sealer.begin(iv, aad));
            REQUIRE(aead_feed([&](std::span<const std::byte> in, std::span<std::byte> out) {
                return sealer.update(in, out);
            }, plain, ct, chunk));
            REQUIRE(sealer.final(tag));
            REQUIRE(hex(ct) == expected_cipher);
            REQUIRE(hex(tag) == expected_tag);

            std::vector<std::byte> back(ct.size());
            REQUIRE(opener.begin(iv, aad));
            REQUIRE(aead_feed([&](std::span<const std::byte> in, std::span<std::byte> out) {
                return opener.update(in, out);
            }, ct, back, chunk));
            REQUIRE(opener.final(tag));
            REQUIRE(hex(back) == hex(plain));
        }
    }
}

TEST_CASE("aes-gcm round-trips in place", "[crypto][openssl][aead]") {
    const auto key = unhex("feffe9928665731c6d6a8f9467308308"
                           "feffe9928665731c6d6a8f9467308308");
    const auto iv  = unhex("cafebabefacedbaddecaf888");
    const auto aad = unhex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
    const auto plain = unhex(
        "d9313225f88406e5a55909c5aff5269a"
        "86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b39");
    const std::string expected_cipher =
        "522dc1f099567d07f47f37a32a84427d"
        "643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838"
        "c5f61e6393ba7a0abcc9f662";
    const std::string expected_tag = "76fc6ece0f4e1768cddf8853bb2d551b";

    crypto::provider p = prov();
    crypto::aead_cipher sealer = p.new_aead(crypto::cipher_id::aes256_gcm, key, true);
    crypto::aead_cipher opener = p.new_aead(crypto::cipher_id::aes256_gcm, key, false);
    REQUIRE(static_cast<bool>(sealer));
    REQUIRE(static_cast<bool>(opener));

    std::vector<std::byte> buf = plain;
    std::array<std::byte, 16> tag{};
    REQUIRE(sealer.begin(iv, aad));
    REQUIRE(sealer.update(buf, buf));
    REQUIRE(sealer.final(tag));
    REQUIRE(hex(buf) == expected_cipher);
    REQUIRE(hex(tag) == expected_tag);

    REQUIRE(opener.begin(iv, aad));
    REQUIRE(opener.update(buf, buf));
    REQUIRE(opener.final(tag));
    REQUIRE(hex(buf) == hex(plain));
}

TEST_CASE("aes-gcm rejects a corrupted tag and a corrupted aad", "[crypto][openssl][aead]") {
    const auto key = unhex("feffe9928665731c6d6a8f9467308308"
                           "feffe9928665731c6d6a8f9467308308");
    const auto iv  = unhex("cafebabefacedbaddecaf888");
    const auto aad = unhex("feedfacedeadbeef");
    const auto plain = unhex("00112233445566778899aabbccddeeff");

    crypto::provider p = prov();
    crypto::aead_cipher sealer = p.new_aead(crypto::cipher_id::aes256_gcm, key, true);
    crypto::aead_cipher opener = p.new_aead(crypto::cipher_id::aes256_gcm, key, false);

    std::vector<std::byte> ct(plain.size());
    std::array<std::byte, 16> tag{};
    REQUIRE(sealer.begin(iv, aad));
    REQUIRE(sealer.update(plain, ct));
    REQUIRE(sealer.final(tag));

    std::vector<std::byte> back(ct.size());

    SECTION("corrupted tag") {
        std::array<std::byte, 16> bad = tag;
        bad[0] ^= std::byte{0x01};
        REQUIRE(opener.begin(iv, aad));
        REQUIRE(opener.update(ct, back));
        REQUIRE_FALSE(opener.final(bad));

        std::fill(back.begin(), back.end(), std::byte{0});
        REQUIRE(opener.begin(iv, aad));
        REQUIRE(opener.update(ct, back));
        REQUIRE(opener.final(tag));
        REQUIRE(hex(back) == hex(plain));
    }
    SECTION("corrupted aad") {
        auto bad_aad = aad;
        bad_aad[0] ^= std::byte{0x01};
        REQUIRE(opener.begin(iv, bad_aad));
        REQUIRE(opener.update(ct, back));
        REQUIRE_FALSE(opener.final(tag));
        REQUIRE(opener.begin(iv, aad));
        REQUIRE(opener.update(ct, back));
        REQUIRE(opener.final(tag));
        REQUIRE(hex(back) == hex(plain));
    }
    SECTION("corrupted ciphertext") {
        auto bad_ct = ct;
        bad_ct[0] ^= std::byte{0x01};
        REQUIRE(opener.begin(iv, aad));
        REQUIRE(opener.update(bad_ct, back));
        REQUIRE_FALSE(opener.final(tag));
    }
}

TEST_CASE("aes-gcm sealer can begin twice on one handle", "[crypto][openssl][aead]") {
    const auto key = unhex("feffe9928665731c6d6a8f9467308308"
                           "feffe9928665731c6d6a8f9467308308");
    const auto iv1 = unhex("cafebabefacedbaddecaf888");
    const auto iv2 = unhex("cafebabefacedbaddecaf889");
    const auto plain = unhex("00112233445566778899aabbccddeeff");
    crypto::provider p = prov();
    crypto::aead_cipher sealer = p.new_aead(crypto::cipher_id::aes256_gcm, key, true);
    std::vector<std::byte> ct(plain.size());
    std::array<std::byte, 16> tag{};
    REQUIRE(sealer.begin(iv1, {}));
    REQUIRE(sealer.update(plain, ct));
    REQUIRE(sealer.final(tag));
    REQUIRE(sealer.begin(iv2, {}));
    REQUIRE(sealer.update(plain, ct));
    REQUIRE(sealer.final(tag));
}

TEST_CASE("aes-gcm opener can begin twice on one handle", "[crypto][openssl][aead]") {
    const auto key = unhex("feffe9928665731c6d6a8f9467308308"
                           "feffe9928665731c6d6a8f9467308308");
    const auto iv1 = unhex("cafebabefacedbaddecaf888");
    const auto iv2 = unhex("cafebabefacedbaddecaf889");
    const auto plain = unhex("00112233445566778899aabbccddeeff");
    crypto::provider p = prov();
    crypto::aead_cipher sealer = p.new_aead(crypto::cipher_id::aes256_gcm, key, true);
    crypto::aead_cipher opener = p.new_aead(crypto::cipher_id::aes256_gcm, key, false);
    std::vector<std::byte> ct1(plain.size());
    std::vector<std::byte> ct2(plain.size());
    std::array<std::byte, 16> tag1{};
    std::array<std::byte, 16> tag2{};
    REQUIRE(sealer.begin(iv1, {}));
    REQUIRE(sealer.update(plain, ct1));
    REQUIRE(sealer.final(tag1));
    REQUIRE(sealer.begin(iv2, {}));
    REQUIRE(sealer.update(plain, ct2));
    REQUIRE(sealer.final(tag2));
    std::vector<std::byte> back(plain.size());
    REQUIRE(opener.begin(iv1, {}));
    REQUIRE(opener.update(ct1, back));
    REQUIRE(opener.final(tag1));
    REQUIRE(opener.begin(iv2, {}));
    REQUIRE(opener.update(ct2, back));
    REQUIRE(opener.final(tag2));
}

// RFC 8439 section 2.4.2: the ChaCha20 encryption test vector, expressed with
// the IV layout EVP_chacha20 uses (4-byte LE counter, then the 12-byte nonce).
TEST_CASE("chacha20 matches RFC 8439 section 2.4.2", "[crypto][openssl][cipher]") {
    const auto key = unhex("000102030405060708090a0b0c0d0e0f"
                           "101112131415161718191a1b1c1d1e1f");
    // counter = 1 (little endian), nonce = 000000000000004a00000000
    const auto iv = unhex("01000000" "000000000000004a00000000");
    const std::string_view text =
        "Ladies and Gentlemen of the class of '99: If I could offer you only one "
        "tip for the future, sunscreen would be it.";
    const std::span<const std::byte> plain{
        reinterpret_cast<const std::byte*>(text.data()), text.size()};

    crypto::provider p = prov();
    crypto::cipher c = p.new_cipher(crypto::cipher_id::chacha20, key, true);
    REQUIRE(static_cast<bool>(c));
    REQUIRE(c.set_iv(iv));

    std::vector<std::byte> out(plain.size());
    REQUIRE(c.update(plain, out));
    REQUIRE(hex(out).substr(0, 64) ==
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b");
}

// RFC 8439 section 2.5.2.
TEST_CASE("poly1305 matches RFC 8439 section 2.5.2", "[crypto][openssl][mac]") {
    const auto key = unhex("85d6be7857556d337f4452fe42d506a8"
                           "0103808afb0db2fd4abff6af4149f51b");
    const std::string_view text = "Cryptographic Forum Research Group";
    const std::span<const std::byte> msg{
        reinterpret_cast<const std::byte*>(text.data()), text.size()};

    crypto::provider p = prov();
    std::array<std::byte, 16> tag{};
    REQUIRE(p.poly1305(key, msg, tag));
    REQUIRE(hex(tag) == "a8061dc1305136c6c22b8baf0c0127a9");
}

TEST_CASE("poly1305 rejects a wrong key size", "[crypto][openssl][mac]") {
    const auto key = unhex("85d6be7857556d337f4452fe42d506a8");   // 16 bytes
    crypto::provider p = prov();
    std::array<std::byte, 16> tag{};
    REQUIRE_FALSE(p.poly1305(key, std::span<const std::byte>{}, tag));
}

TEST_CASE("cipher capability reflects the implemented set", "[crypto][openssl]") {
    crypto::provider p = prov();
    REQUIRE(p.supports(crypto::cipher_id::aes128_ctr));
    REQUIRE(p.supports(crypto::cipher_id::aes192_ctr));
    REQUIRE(p.supports(crypto::cipher_id::aes256_ctr));
    REQUIRE(p.supports(crypto::cipher_id::aes128_gcm));
    REQUIRE(p.supports(crypto::cipher_id::aes256_gcm));
    REQUIRE(p.supports(crypto::cipher_id::chacha20));
    REQUIRE(p.supports(crypto::mac_id::poly1305));
    REQUIRE(p.supports(crypto::cipher_id::sm4_ctr));
    REQUIRE(p.supports(crypto::cipher_id::sm4_cbc));
}

TEST_CASE("aes-256-cbc matches NIST SP 800-38A F.2.5", "[crypto][openssl][cbc]") {
    const auto key = unhex("603deb1015ca71be2b73aef0857d7781"
                           "1f352c073b6108d72d9810a30914dff4");
    const auto iv  = unhex("000102030405060708090a0b0c0d0e0f");
    const auto plain = unhex("6bc1bee22e409f96e93d7e117393172a");
    const std::string expected = "f58c4c04d6e5f1ba779eabfb5f7bfbd6";

    crypto::provider p = prov();
    REQUIRE(p.supports(crypto::cipher_id::aes256_cbc));
    std::vector<std::byte> out(plain.size());
    REQUIRE(p.cbc_crypt(crypto::cipher_id::aes256_cbc, true, key, iv, plain, out));
    REQUIRE(hex(out) == expected);

    std::vector<std::byte> back(plain.size());
    REQUIRE(p.cbc_crypt(crypto::cipher_id::aes256_cbc, false, key, iv, out, back));
    REQUIRE(hex(back) == hex(plain));
}

TEST_CASE("aes-cbc rejects non-block-sized input", "[crypto][openssl][cbc]") {
    crypto::provider p = prov();
    const auto key = unhex("603deb1015ca71be2b73aef0857d7781"
                           "1f352c073b6108d72d9810a30914dff4");
    const auto iv  = unhex("000102030405060708090a0b0c0d0e0f");
    const auto odd = unhex("001122334455667788");
    std::vector<std::byte> out(odd.size());
    REQUIRE_FALSE(p.cbc_crypt(crypto::cipher_id::aes256_cbc, true, key, iv, odd, out));
}
