#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/wire/types.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>

#include <array>
#include <cstddef>
#include <span>
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

}  // namespace

// Two independently generated contexts must agree. This is the property the
// protocol depends on; the private half is never injectable because all
// randomness comes from the provider by design.
TEST_CASE("key agreement is symmetric for every supported group", "[crypto][openssl][kex]") {
    crypto::provider p = prov();

    const crypto::kex_id groups[] = {
        crypto::kex_id::curve25519,
        crypto::kex_id::ecdh_nistp256,
        crypto::kex_id::ecdh_nistp384,
        crypto::kex_id::ecdh_nistp521,
        crypto::kex_id::dh_group14,
        crypto::kex_id::dh_group16,
        crypto::kex_id::ecdh_sm2,
    };

    for (crypto::kex_id id : groups) {
        INFO("kex_id " << static_cast<int>(id));
        REQUIRE(p.supports(id));

        crypto::kex_agreement a = p.new_kex(id);
        crypto::kex_agreement b = p.new_kex(id);
        REQUIRE(static_cast<bool>(a));
        REQUIRE(static_cast<bool>(b));

        std::vector<std::byte> pa(crypto::kex_public_size(id));
        std::vector<std::byte> pb(crypto::kex_public_size(id));
        std::size_t la = 0;
        std::size_t lb = 0;
        REQUIRE(a.public_value(pa, la));
        REQUIRE(b.public_value(pb, lb));
        REQUIRE(la == crypto::kex_public_size(id));
        REQUIRE(lb == crypto::kex_public_size(id));

        std::vector<std::byte> sa(crypto::kex_secret_size(id));
        std::vector<std::byte> sb(crypto::kex_secret_size(id));
        std::size_t ka = 0;
        std::size_t kb = 0;
        REQUIRE(a.agree(std::span{pb}.first(lb), sa, ka));
        REQUIRE(b.agree(std::span{pa}.first(la), sb, kb));
        REQUIRE(ka == kb);
        REQUIRE(hex(std::span{sa}.first(ka)) == hex(std::span{sb}.first(kb)));
    }
}

TEST_CASE("sm2-sm3 KAP agrees only across initiator and responder roles", "[crypto][openssl][kex][gm]") {
    crypto::provider p = prov();
    REQUIRE(p.supports(crypto::kex_id::sm2_kap));
    REQUIRE(p.supports(crypto::kex_id::sm2_kap_server));

    crypto::kex_agreement client = p.new_kex(crypto::kex_id::sm2_kap);
    crypto::kex_agreement server = p.new_kex(crypto::kex_id::sm2_kap_server);
    std::vector<std::byte> qc(65);
    std::vector<std::byte> qs(65);
    std::size_t lc = 0;
    std::size_t ls = 0;
    REQUIRE(client.public_value(qc, lc));
    REQUIRE(server.public_value(qs, ls));

    std::vector<std::byte> kc(32);
    std::vector<std::byte> ks(32);
    std::size_t nkc = 0;
    std::size_t nks = 0;
    REQUIRE(client.agree(std::span{qs}.first(ls), kc, nkc));
    REQUIRE(server.agree(std::span{qc}.first(lc), ks, nks));
    REQUIRE(nkc == 32);
    REQUIRE(nks == 32);
    REQUIRE(hex(kc) == hex(ks));

    crypto::kex_agreement both_init = p.new_kex(crypto::kex_id::sm2_kap);
    std::vector<std::byte> qi(65);
    std::size_t li = 0;
    REQUIRE(both_init.public_value(qi, li));
    std::vector<std::byte> k_wrong(32);
    std::size_t nw = 0;
    REQUIRE(client.agree(std::span{qi}.first(li), k_wrong, nw));
    REQUIRE(hex(k_wrong) != hex(kc));
}

TEST_CASE("x25519 rejects an all-zero shared secret", "[crypto][openssl][kex]") {
    crypto::provider p = prov();
    crypto::kex_agreement a = p.new_kex(crypto::kex_id::curve25519);
    // A low-order point drives the X25519 output to all zeros (RFC 8731 sec 3).
    const auto low_order = unhex("0000000000000000000000000000000000000000000000000000000000000000");
    std::array<std::byte, 32> secret{};
    std::size_t len = 0;
    REQUIRE_FALSE(a.agree(low_order, secret, len));
}

TEST_CASE("finite field dh rejects out-of-range peer values", "[crypto][openssl][kex]") {
    crypto::provider p = prov();
    crypto::kex_agreement a = p.new_kex(crypto::kex_id::dh_group14);
    std::vector<std::byte> secret(256);
    std::size_t len = 0;

    SECTION("f = 0") {
        const std::vector<std::byte> zero(256, std::byte{0});
        REQUIRE_FALSE(a.agree(zero, secret, len));
    }
    SECTION("f = 1") {
        std::vector<std::byte> one(256, std::byte{0});
        one.back() = std::byte{1};
        REQUIRE_FALSE(a.agree(one, secret, len));
    }
}

TEST_CASE("kex public value rejects an undersized destination", "[crypto][openssl][kex]") {
    crypto::provider p = prov();
    crypto::kex_agreement a = p.new_kex(crypto::kex_id::curve25519);
    std::array<std::byte, 16> too_small{};
    std::size_t len = 0;
    REQUIRE_FALSE(a.public_value(too_small, len));
}

// RFC 8032 section 7.1, TEST 1 and TEST 2.
TEST_CASE("ed25519 verify matches RFC 8032 vectors", "[crypto][openssl][sig]") {
    crypto::provider p = prov();

    SECTION("TEST 1: empty message") {
        const auto pub = unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        const auto sig = unhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e0652249015"
                               "55fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        crypto::public_key_material key{crypto::sig_id::ed25519, pub, {}};
        crypto::signature_material s{sig, {}};
        REQUIRE(p.verify(key, std::span<const std::byte>{}, s));
    }
    SECTION("TEST 2: one-byte message 0x72") {
        const auto pub = unhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        const auto msg = unhex("72");
        const auto sig = unhex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                               "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
        crypto::public_key_material key{crypto::sig_id::ed25519, pub, {}};
        crypto::signature_material s{sig, {}};
        REQUIRE(p.verify(key, msg, s));
    }
}

TEST_CASE("ed25519 verify rejects a tampered signature and message", "[crypto][openssl][sig]") {
    crypto::provider p = prov();
    const auto pub = unhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    const auto msg = unhex("72");
    auto sig = unhex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                     "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
    crypto::public_key_material key{crypto::sig_id::ed25519, pub, {}};

    SECTION("tampered signature") {
        sig[0] ^= std::byte{0x01};
        crypto::signature_material s{sig, {}};
        REQUIRE_FALSE(p.verify(key, msg, s));
    }
    SECTION("tampered message") {
        const auto other = unhex("73");
        crypto::signature_material s{sig, {}};
        REQUIRE_FALSE(p.verify(key, other, s));
    }
}

// Ed25519 is deterministic, so signing an RFC 8032 vector must reproduce it byte
// for byte.
TEST_CASE("ed25519 sign matches RFC 8032 TEST 2", "[crypto][openssl][sig]") {
    crypto::provider p = prov();
    const auto seed = unhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    const auto pub  = unhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    const auto msg  = unhex("72");

    crypto::private_key_material key{crypto::sig_id::ed25519, seed, pub};
    crypto::signing_key sk = p.new_signing_key(key);
    REQUIRE(static_cast<bool>(sk));

    std::array<std::byte, 64> sig{};
    std::size_t len = 0;
    REQUIRE(sk.sign(msg, sig, len));
    REQUIRE(len == 64);
    REQUIRE(hex(sig) == "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                        "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
}

TEST_CASE("generate ed25519 keypair and sign round-trips", "[crypto][openssl][keygen]") {
    crypto::provider p = prov();
    std::array<std::byte, crypto::max_generated_key_storage> storage{};
    crypto::private_key_material priv{};
    REQUIRE(p.generate_keypair(crypto::sig_id::ed25519, 0, priv, storage));
    REQUIRE(priv.seed.size() == 32);
    REQUIRE(priv.public_key.size() == 32);

    crypto::signing_key sk = p.new_signing_key(priv);
    REQUIRE(static_cast<bool>(sk));
    const auto msg = unhex("72");
    std::array<std::byte, 64> sig{};
    std::size_t len = 0;
    REQUIRE(sk.sign(msg, sig, len));
    REQUIRE(len == 64);

    crypto::public_key_material pub{crypto::sig_id::ed25519, priv.public_key, {}};
    crypto::signature_material sm{std::span{sig}.first(len), {}};
    REQUIRE(p.verify(pub, msg, sm));
}

TEST_CASE("generate ecdsa p256 keypair and sign round-trips", "[crypto][openssl][keygen]") {
    crypto::provider p = prov();
    std::array<std::byte, crypto::max_generated_key_storage> storage{};
    crypto::private_key_material priv{};
    REQUIRE(p.generate_keypair(crypto::sig_id::ecdsa_nistp256, 0, priv, storage));
    REQUIRE_FALSE(priv.seed.empty());
    REQUIRE(priv.public_key.size() == 65);
    REQUIRE(std::to_integer<std::uint8_t>(priv.public_key[0]) == 0x04);

    crypto::signing_key sk = p.new_signing_key(priv);
    REQUIRE(static_cast<bool>(sk));
    const auto msg = unhex("01020304");
    std::array<std::byte, 256> raw{};
    std::size_t len = 0;
    REQUIRE(sk.sign(msg, raw, len));
    REQUIRE(len > 0);

    // Inner blob is mpint r || mpint s — reuse wire::reader in the test file.
    wire::reader r{std::span{raw}.first(len)};
    std::span<const std::byte> rr, ss;
    REQUIRE(r.read_mpint(rr));
    REQUIRE(r.read_mpint(ss));
    REQUIRE(r.empty());

    crypto::public_key_material pub{crypto::sig_id::ecdsa_nistp256, priv.public_key, {}};
    crypto::signature_material sm{rr, ss};
    REQUIRE(p.verify(pub, msg, sm));
}

TEST_CASE("generate rsa 2048 keypair and sha256-sign round-trips", "[crypto][openssl][keygen]") {
    crypto::provider p = prov();
    std::array<std::byte, crypto::max_generated_key_storage> storage{};
    crypto::private_key_material priv{};
    REQUIRE(p.generate_keypair(crypto::sig_id::rsa_pkcs1_sha256, 2048, priv, storage));
    REQUIRE_FALSE(priv.n.empty());
    REQUIRE_FALSE(priv.e.empty());
    REQUIRE_FALSE(priv.d.empty());
    REQUIRE_FALSE(priv.p.empty());
    REQUIRE_FALSE(priv.q.empty());
    REQUIRE_FALSE(priv.iqmp.empty());

    crypto::signing_key sk = p.new_signing_key(priv);
    REQUIRE(static_cast<bool>(sk));
    const auto msg = unhex("01020304");
    std::vector<std::byte> sig(512);
    std::size_t len = 0;
    REQUIRE(sk.sign(msg, sig, len));
    sig.resize(len);

    crypto::public_key_material pub{crypto::sig_id::rsa_pkcs1_sha256, priv.n, priv.e};
    crypto::signature_material sm{sig, {}};
    REQUIRE(p.verify(pub, msg, sm));
}

TEST_CASE("default rsa signature exceeds 256 bytes and fits the 1024-byte cap",
          "[crypto][openssl][keygen]") {
    crypto::provider p = prov();
    std::array<std::byte, crypto::max_generated_key_storage> storage{};
    crypto::private_key_material priv{};
    REQUIRE(p.generate_keypair(crypto::sig_id::rsa_pkcs1_sha256, 0, priv, storage));

    crypto::signing_key sk = p.new_signing_key(priv);
    REQUIRE(static_cast<bool>(sk));
    const auto msg = unhex("01020304");
    std::array<std::byte, crypto::max_signature_size> sig{};
    std::size_t len = 0;
    REQUIRE(sk.sign(msg, sig, len));
    REQUIRE(len > 256);
    REQUIRE(len <= crypto::max_signature_size);
}

TEST_CASE("rsa generate rejects bits below 2048", "[crypto][openssl][keygen]") {
    crypto::provider p = prov();
    std::array<std::byte, crypto::max_generated_key_storage> storage{};
    crypto::private_key_material priv{};
    REQUIRE_FALSE(p.generate_keypair(crypto::sig_id::rsa_pkcs1_sha256, 1024, priv, storage));
}

TEST_CASE("verification is available for every host key type M1 must accept",
          "[crypto][openssl][sig]") {
    crypto::provider p = prov();
    REQUIRE(p.supports(crypto::sig_id::ed25519));
    REQUIRE(p.supports(crypto::sig_id::ecdsa_nistp256));
    REQUIRE(p.supports(crypto::sig_id::ecdsa_nistp384));
    REQUIRE(p.supports(crypto::sig_id::ecdsa_nistp521));
    REQUIRE(p.supports(crypto::sig_id::rsa_pkcs1_sha1));
    REQUIRE(p.supports(crypto::sig_id::rsa_pkcs1_sha256));
    REQUIRE(p.supports(crypto::sig_id::rsa_pkcs1_sha512));
}
