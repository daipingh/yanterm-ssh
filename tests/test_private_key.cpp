#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/wire/types.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/keys/detail/file_cipher.hpp>
#include <yanterm-ssh/keys/private_key.hpp>

#include "hex_util.hpp"

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
using namespace yanterm::ssh::testing;

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

std::vector<std::byte> truncated_encrypted_header() {
    static constexpr char kMagic[] = "openssh-key-v1";
    wire::writer w;
    w.write_bytes({reinterpret_cast<const std::byte*>(kMagic), sizeof(kMagic)});
    w.write_string("aes256-ctr");
    w.write_string("bcrypt");
    w.write_string("");
    w.write_uint32(1);
    return {w.data().begin(), w.data().end()};
}

}  // namespace

TEST_CASE("inspect unencrypted openssh-key-v1", "[keys][private]") {
    const auto bytes = load_fixture("id_ed25519");
    const auto info = keys::private_key::inspect(bytes);
    REQUIRE_FALSE(info.encrypted);
    REQUIRE(info.cipher == "none");
    REQUIRE(info.kdf == "none");
}

TEST_CASE("parse unencrypted ed25519/ecdsa/rsa fixtures", "[keys][private]") {
    crypto::provider p = prov();
    for (const char* name : {"id_ed25519", "id_ecdsa", "id_rsa"}) {
        keys::private_key k;
        REQUIRE_FALSE(keys::private_key::parse(load_fixture(name), p, {}, k));
        REQUIRE_FALSE(k.pub().blob().empty());
    }
}

TEST_CASE("unencrypted serialize round-trips parse", "[keys][private]") {
    crypto::provider p = prov();
    keys::private_key k;
    REQUIRE_FALSE(keys::private_key::parse(load_fixture("id_ed25519"), p, {}, k));
    std::vector<std::byte> out;
    REQUIRE_FALSE(k.serialize(p, {}, "none", out));
    const auto text = std::string_view{reinterpret_cast<const char*>(out.data()), out.size()};
    REQUIRE(text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
    keys::private_key again;
    REQUIRE_FALSE(keys::private_key::parse(out, p, {}, again));
    REQUIRE(std::equal(k.pub().blob().begin(), k.pub().blob().end(),
                       again.pub().blob().begin()));
}

TEST_CASE("OPENSSH PRIVATE KEY armor is openssh-key-v1", "[keys][private]") {
    crypto::provider p = prov();
    keys::private_key k;
    REQUIRE_FALSE(keys::private_key::parse(load_fixture("id_ed25519"), p, {}, k));
    REQUIRE(k.pub().algorithm_name() == "ssh-ed25519");
}

TEST_CASE("traditional PEM / PKCS#8 is unsupported in M2", "[keys][private]") {
    crypto::provider p = prov();
    keys::private_key k;
    const auto rsa_pem = bytes_of(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK8=\n-----END RSA PRIVATE KEY-----\n");
    REQUIRE(keys::private_key::parse(rsa_pem, p, {}, k)
            == errc::unsupported_key_format);
    const auto pkcs8 = bytes_of(
        "-----BEGIN PRIVATE KEY-----\nMII=\n-----END PRIVATE KEY-----\n");
    REQUIRE(keys::private_key::parse(pkcs8, p, {}, k)
            == errc::unsupported_key_format);
}

TEST_CASE("encrypted key without passphrase is passphrase_required", "[keys][private]") {
    const auto fake = truncated_encrypted_header();
    const auto info = keys::private_key::inspect(fake);
    REQUIRE(info.encrypted);
    REQUIRE(info.cipher == "aes256-ctr");
    REQUIRE(info.kdf == "bcrypt");

    crypto::provider p = prov();
    keys::private_key k;
    REQUIRE(keys::private_key::parse(fake, p, {}, k)
            == errc::passphrase_required);
}

TEST_CASE("aes256-ctr bcrypt round-trip", "[keys][private][encrypt]") {
    crypto::provider p = prov();
    keys::private_key k;
    REQUIRE_FALSE(keys::private_key::parse(load_fixture("id_ed25519"), p, {}, k));
    auto pass = bytes_of("correct horse");
    std::vector<std::byte> enc;
    REQUIRE_FALSE(k.serialize(p, pass, "aes256-ctr", enc));
    auto info = keys::private_key::inspect(enc);
    REQUIRE(info.encrypted);
    REQUIRE(info.cipher == "aes256-ctr");
    REQUIRE(info.kdf == "bcrypt");
    REQUIRE(info.bcrypt_rounds == 16);

    keys::private_key k2;
    REQUIRE(keys::private_key::parse(enc, p, {}, k2)
            == errc::passphrase_required);
    REQUIRE(keys::private_key::parse(enc, p, bytes_of("wrong"), k2)
            == errc::incorrect_passphrase);
    REQUIRE_FALSE(keys::private_key::parse(enc, p, pass, k2));
    REQUIRE(std::equal(k.pub().blob().begin(), k.pub().blob().end(),
                       k2.pub().blob().begin()));
}

TEST_CASE("serialize refuses ciphers other than none and aes256-ctr",
          "[keys][private][encrypt]") {
    crypto::provider p = prov();
    keys::private_key k;
    REQUIRE_FALSE(keys::private_key::parse(load_fixture("id_ed25519"), p, {}, k));
    auto pass = bytes_of("correct horse");
    std::vector<std::byte> enc;
    REQUIRE(k.serialize(p, pass, "aes256-cbc", enc)
            == errc::unsupported_algorithm);
    REQUIRE(k.serialize(p, pass, "chacha20-poly1305@openssh.com", enc)
            == errc::unsupported_algorithm);
    REQUIRE(k.serialize(p, pass, "aes256-gcm@openssh.com", enc)
            == errc::unsupported_algorithm);
}

TEST_CASE("file cipher aes256-cbc seal/open round-trip", "[keys][private][encrypt]") {
    crypto::provider p = prov();
    const auto* fc = keys::detail::find_file_cipher("aes256-cbc");
    REQUIRE(fc != nullptr);
    REQUIRE(fc->k == keys::detail::file_cipher::kind::cbc);

    std::array<std::byte, 48> key_iv{};
    REQUIRE_FALSE(p.random_bytes(key_iv));
    const auto plain = unhex(
        "00112233445566778899aabbccddeeff"
        "ffeeddccbbaa99887766554433221100");
    std::vector<std::byte> ct;
    REQUIRE_FALSE(keys::detail::seal(p, *fc, key_iv, plain, ct));
    REQUIRE(ct.size() == plain.size());

    std::vector<std::byte> back;
    REQUIRE_FALSE(keys::detail::open(p, *fc, key_iv, ct, back));
    REQUIRE(std::equal(plain.begin(), plain.end(), back.begin()));
}

TEST_CASE("file cipher aes256-gcm seal/open round-trip", "[keys][private][encrypt]") {
    crypto::provider p = prov();
    const auto* fc = keys::detail::find_file_cipher("aes256-gcm@openssh.com");
    REQUIRE(fc != nullptr);
    REQUIRE(fc->k == keys::detail::file_cipher::kind::gcm);
    REQUIRE(fc->tag_len == 16);
    REQUIRE(fc->iv_len == 12);

    std::array<std::byte, 44> key_iv{};
    REQUIRE_FALSE(p.random_bytes(key_iv));
    const auto plain = unhex(
        "00112233445566778899aabbccddeeff");
    std::vector<std::byte> ct;
    REQUIRE_FALSE(keys::detail::seal(p, *fc, key_iv, plain, ct));
    REQUIRE(ct.size() == plain.size() + 16);

    std::vector<std::byte> back;
    REQUIRE_FALSE(keys::detail::open(p, *fc, key_iv, ct, back));
    REQUIRE(std::equal(plain.begin(), plain.end(), back.begin()));

    auto bad = ct;
    bad.back() ^= std::byte{0x01};
    std::vector<std::byte> junk;
    REQUIRE(keys::detail::open(p, *fc, key_iv, bad, junk));
}

TEST_CASE("file cipher chacha20-poly1305 OpenSSH file construction round-trip",
          "[keys][private][encrypt]") {
    crypto::provider p = prov();
    const auto* fc = keys::detail::find_file_cipher("chacha20-poly1305@openssh.com");
    REQUIRE(fc != nullptr);
    REQUIRE(fc->k == keys::detail::file_cipher::kind::chacha_file);
    REQUIRE(fc->key_len == 64);
    REQUIRE(fc->iv_len == 0);
    REQUIRE(fc->tag_len == 16);
    REQUIRE(fc->block == 8);

    std::array<std::byte, 64> key_iv{};
    REQUIRE_FALSE(p.random_bytes(key_iv));
    const auto plain = unhex(
        "00112233445566778899aabbccddeeff"
        "0102030405060708");
    std::vector<std::byte> ct;
    REQUIRE_FALSE(keys::detail::seal(p, *fc, key_iv, plain, ct));
    REQUIRE(ct.size() == plain.size() + 16);

    std::vector<std::byte> back;
    REQUIRE_FALSE(keys::detail::open(p, *fc, key_iv, ct, back));
    REQUIRE(std::equal(plain.begin(), plain.end(), back.begin()));

    auto bad = ct;
    bad[0] ^= std::byte{0x01};
    std::vector<std::byte> junk;
    REQUIRE(keys::detail::open(p, *fc, key_iv, bad, junk));
}

TEST_CASE("generate ed25519 then serialize none and parse", "[keys][private][generate]") {
    crypto::provider p = prov();
    keys::private_key k;
    REQUIRE_FALSE(keys::private_key::generate(p, crypto::sig_id::ed25519, 0, "t", k));
    REQUIRE(k.pub().algorithm_name() == "ssh-ed25519");
    std::vector<std::byte> blob;
    REQUIRE_FALSE(k.serialize(p, {}, "none", blob));
    keys::private_key k2;
    REQUIRE_FALSE(keys::private_key::parse(blob, p, {}, k2));
    REQUIRE(k2.comment() == "t");
}

TEST_CASE("generate rsa 2048 produces matching public blob", "[keys][private][generate]") {
    crypto::provider p = prov();
    keys::private_key k;
    REQUIRE_FALSE(keys::private_key::generate(p, crypto::sig_id::rsa_pkcs1_sha256, 2048, {}, k));
    REQUIRE(k.pub().algorithm_name() == "ssh-rsa");
    const auto m = k.material();
    crypto::public_key_material pub_m{m.algorithm, m.n, m.e};
    keys::public_key reconstructed;
    REQUIRE_FALSE(keys::public_key::from_material(pub_m, reconstructed));
    REQUIRE(std::equal(k.pub().blob().begin(), k.pub().blob().end(),
                       reconstructed.blob().begin(), reconstructed.blob().end()));
}
