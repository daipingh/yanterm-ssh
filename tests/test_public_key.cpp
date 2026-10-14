#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/wire/types.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/keys/fingerprint.hpp>
#include <yanterm-ssh/keys/public_key.hpp>

#include <algorithm>
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

std::string load_text(std::string_view name) {
    const auto bytes = load_fixture(name);
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

}  // namespace

TEST_CASE("public_key parses OpenSSH blob fixture", "[keys][public]") {
    const auto blob = load_fixture("ed25519.blob");
    keys::public_key key;
    REQUIRE_FALSE(keys::public_key::parse_blob(blob, key));
    REQUIRE(key.algorithm_name() == "ssh-ed25519");
    REQUIRE(key.material().a.size() == 32);
}

TEST_CASE("public_key round-trips OpenSSH .pub line", "[keys][public]") {
    const auto text = load_text("id_ed25519.pub");
    keys::public_key key;
    std::string comment;
    REQUIRE_FALSE(keys::public_key::parse_line(text, key, &comment));
    REQUIRE(comment.find("yanterm-ssh test") != std::string::npos);
    const std::string line = key.to_line(comment);
    keys::public_key again;
    REQUIRE_FALSE(keys::public_key::parse_line(line, again));
    REQUIRE(again.blob().size() == key.blob().size());
    REQUIRE(std::equal(again.blob().begin(), again.blob().end(), key.blob().begin()));
}

TEST_CASE("fingerprint matches ssh-keygen SHA256 format", "[keys][public][fingerprint]") {
    crypto::provider p = prov();
    keys::public_key key;
    REQUIRE_FALSE(keys::public_key::parse_blob(load_fixture("ed25519.blob"), key));
    const std::string fp = keys::fingerprint_sha256(p, key);
    REQUIRE(fp.rfind("SHA256:", 0) == 0);
    REQUIRE(fp.find('=') == std::string::npos);
}

TEST_CASE("public_key rejects OpenSSH certificate blobs", "[keys][public]") {
    wire::writer w;
    w.write_string("ssh-ed25519-cert-v01@openssh.com");
    keys::public_key key;
    REQUIRE(keys::public_key::parse_blob(w.data(), key)
            == errc::unsupported_key_format);
}

TEST_CASE("public_key rejects sk-ssh-ed25519 blobs", "[keys][public]") {
    wire::writer w;
    w.write_string("sk-ssh-ed25519@openssh.com");
    keys::public_key key;
    REQUIRE(keys::public_key::parse_blob(w.data(), key)
            == errc::unsupported_key_format);
}
