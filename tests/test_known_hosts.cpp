#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/keys/detail/base64.hpp>
#include <yanterm-ssh/keys/known_hosts.hpp>
#include <yanterm-ssh/keys/public_key.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
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


std::string load_text(std::string_view name) {
    const std::string path = std::string{YANTERM_SSH_FIXTURE_DIR} + "/" + std::string{name};
    std::ifstream in{path, std::ios::binary};
    REQUIRE(in);
    in.seekg(0, std::ios::end);
    const auto n = static_cast<std::size_t>(in.tellg());
    in.seekg(0, std::ios::beg);
    std::string out(n, '\0');
    if (n > 0) {
        in.read(out.data(), static_cast<std::streamsize>(n));
        REQUIRE(in);
    }
    return out;
}

keys::public_key load_ed25519_pub() {
    keys::public_key key;
    std::string comment;
    REQUIRE_FALSE(keys::public_key::parse_line(load_text("id_ed25519.pub"), key, &comment));
    return key;
}

bool blobs_equal(const keys::public_key& a, const keys::public_key& b) {
    const auto xa = a.blob();
    const auto xb = b.blob();
    return xa.size() == xb.size() && std::equal(xa.begin(), xa.end(), xb.begin());
}

std::string hashed_host_token(crypto::provider p, std::string_view host_form,
                              std::span<const std::byte> salt) {
    auto hmac = p.new_hmac(crypto::hash_id::sha1, salt);
    REQUIRE(hmac);
    hmac.update({reinterpret_cast<const std::byte*>(host_form.data()), host_form.size()});
    std::array<std::byte, 20> mac{};
    REQUIRE(hmac.final_into(mac));
    return "|1|" + keys::detail::base64_encode(salt, true) + "|" +
           keys::detail::base64_encode(mac, true);
}

std::string key_b64(const keys::public_key& key) {
    return keys::detail::base64_encode(key.blob(), true);
}

}  // namespace

TEST_CASE("known_hosts matches plaintext host and port form", "[keys][known_hosts]") {
    crypto::provider p = prov();
    const auto key = load_ed25519_pub();
    const std::string b64 = key_b64(key);

    keys::known_hosts kh;
    REQUIRE_FALSE(keys::known_hosts::parse(
        "example.com ssh-ed25519 " + b64 + "\n"
        "[example.com]:2222 ssh-ed25519 " + b64 + "\n",
        kh));
    REQUIRE(kh.lines().size() == 2);
    REQUIRE(kh.lines()[0].key.has_value());
    REQUIRE(blobs_equal(*kh.lines()[0].key, key));

    REQUIRE(kh.match(p, "example.com", 22, key) == keys::host_key_match::found);
    REQUIRE(kh.match(p, "example.com", 2222, key) == keys::host_key_match::found);
    REQUIRE(kh.match(p, "example.com", 2223, key) == keys::host_key_match::none);
    REQUIRE(kh.match(p, "other.com", 22, key) == keys::host_key_match::none);

    keys::public_key other;
    REQUIRE_FALSE(keys::public_key::parse_line(load_text("id_ecdsa.pub"), other));
    REQUIRE(kh.match(p, "example.com", 22, other) == keys::host_key_match::none);
}

TEST_CASE("hashed |1| host matches via HMAC-SHA1", "[keys][known_hosts]") {
    crypto::provider p = prov();
    const auto key = load_ed25519_pub();
    const std::string b64 = key_b64(key);

    std::array<std::byte, 20> salt{};
    for (std::size_t i = 0; i < salt.size(); ++i) {
        salt[i] = std::byte{static_cast<unsigned char>(i + 1)};
    }

    const std::string tok22 = hashed_host_token(p, "example.com", salt);
    const std::string tok2222 = hashed_host_token(p, "[example.com]:2222", salt);

    keys::known_hosts kh;
    REQUIRE_FALSE(keys::known_hosts::parse(
        tok22 + " ssh-ed25519 " + b64 + "\n" + tok2222 + " ssh-ed25519 " + b64 + "\n", kh));

    REQUIRE(kh.match(p, "example.com", 22, key) == keys::host_key_match::found);
    REQUIRE(kh.match(p, "example.com", 2222, key) == keys::host_key_match::found);
    REQUIRE(kh.match(p, "other.com", 22, key) == keys::host_key_match::none);
    REQUIRE(kh.match(p, "example.com", 2223, key) == keys::host_key_match::none);
}

TEST_CASE("@revoked wins over a later accept", "[keys][known_hosts]") {
    crypto::provider p = prov();
    const auto key = load_ed25519_pub();
    const std::string b64 = key_b64(key);

    keys::known_hosts kh;
    REQUIRE_FALSE(keys::known_hosts::parse(
        "@revoked example.com ssh-ed25519 " + b64 + "\n"
        "example.com ssh-ed25519 " + b64 + " comment\n",
        kh));

    REQUIRE(kh.match(p, "example.com", 22, key) == keys::host_key_match::revoked);

    keys::known_hosts later_first;
    REQUIRE_FALSE(keys::known_hosts::parse(
        "example.com ssh-ed25519 " + b64 + "\n"
        "@revoked example.com ssh-ed25519 " + b64 + "\n",
        later_first));
    REQUIRE(later_first.match(p, "example.com", 22, key) == keys::host_key_match::revoked);
}

TEST_CASE("@cert-authority is not a host key hit", "[keys][known_hosts]") {
    crypto::provider p = prov();
    const auto key = load_ed25519_pub();
    const std::string b64 = key_b64(key);

    keys::known_hosts kh;
    REQUIRE_FALSE(keys::known_hosts::parse(
        "@cert-authority example.com ssh-ed25519 " + b64 + "\n", kh));
    REQUIRE(kh.lines().size() == 1);
    REQUIRE(kh.lines()[0].marker == keys::host_marker::cert_authority);
    REQUIRE(kh.lines()[0].key.has_value());
    REQUIRE(kh.match(p, "example.com", 22, key) == keys::host_key_match::none);
}

TEST_CASE("wildcard * and negation !", "[keys][known_hosts]") {
    crypto::provider p = prov();
    const auto key = load_ed25519_pub();
    const std::string b64 = key_b64(key);

    keys::known_hosts kh;
    REQUIRE_FALSE(keys::known_hosts::parse(
        "*.example.com,!foo.example.com ssh-ed25519 " + b64 + "\n"
        "exampl?.com ssh-ed25519 " + b64 + "\n",
        kh));

    REQUIRE(kh.match(p, "bar.example.com", 22, key) == keys::host_key_match::found);
    REQUIRE(kh.match(p, "foo.example.com", 22, key) == keys::host_key_match::none);
    REQUIRE(kh.match(p, "example.com", 22, key) == keys::host_key_match::found);
}

TEST_CASE("comments and unknown lines survive serialize after append", "[keys][known_hosts]") {
    crypto::provider p = prov();
    const auto key = load_ed25519_pub();
    const std::string b64 = key_b64(key);

    const std::string text =
        "# keep this comment\n"
        "\n"
        "sk.example.com sk-ssh-ed25519@openssh.com " + b64 + "\n"
        "example.com ssh-ed25519 " + b64 + " orig\n";

    keys::known_hosts kh;
    REQUIRE_FALSE(keys::known_hosts::parse(text, kh));
    REQUIRE(kh.lines().size() == 4);
    REQUIRE_FALSE(kh.lines()[0].key.has_value());
    REQUIRE(kh.lines()[0].raw == "# keep this comment");
    REQUIRE_FALSE(kh.lines()[1].key.has_value());
    REQUIRE(kh.lines()[1].raw.empty());
    REQUIRE_FALSE(kh.lines()[2].key.has_value());
    REQUIRE(kh.lines()[2].raw.find("sk-ssh-ed25519@openssh.com") != std::string::npos);
    REQUIRE(kh.lines()[3].key.has_value());

    keys::known_host_line added;
    added.pattern = "new.example.com";
    added.key = key;
    added.comment = "appended";
    kh.append(std::move(added));

    const std::string dumped = kh.serialize();
    REQUIRE(dumped.find("# keep this comment\n") != std::string::npos);
    REQUIRE(dumped.find("\n\n") != std::string::npos);
    REQUIRE(dumped.find("sk-ssh-ed25519@openssh.com") != std::string::npos);
    REQUIRE(dumped.find("new.example.com ssh-ed25519 ") != std::string::npos);

    keys::known_hosts again;
    REQUIRE_FALSE(keys::known_hosts::parse(dumped, again));
    REQUIRE(again.lines().size() == 5);
    REQUIRE(again.lines()[0].raw == "# keep this comment");
    REQUIRE_FALSE(again.lines()[0].key.has_value());
    REQUIRE(again.lines()[1].raw.empty());
    REQUIRE_FALSE(again.lines()[1].key.has_value());
    REQUIRE_FALSE(again.lines()[2].key.has_value());
    REQUIRE(again.lines()[4].pattern == "new.example.com");
    REQUIRE(again.lines()[4].comment == "appended");

    REQUIRE(again.erase_matching(p, "example.com", 22, key) == 1);
    REQUIRE(again.lines().size() == 4);
    REQUIRE(again.lines()[0].raw == "# keep this comment");
    REQUIRE_FALSE(again.lines()[0].key.has_value());
    REQUIRE_FALSE(again.lines()[1].key.has_value());
    REQUIRE_FALSE(again.lines()[2].key.has_value());
    REQUIRE(again.lines()[3].pattern == "new.example.com");
    REQUIRE(again.match(p, "example.com", 22, key) == keys::host_key_match::none);
    REQUIRE(again.match(p, "new.example.com", 22, key) == keys::host_key_match::found);
}
