#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/kex/algorithms.hpp>
#include <yanterm-ssh/core/detail/kex_negotiation.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/detail/error.hpp>

#include <list>
#include <string>
#include <string_view>
#include <vector>

using namespace yanterm::ssh;

namespace {

crypto::provider prov() {
    static crypto::openssl_backend backend;
    return crypto::provider::wrap(backend);
}


std::string join_names(std::span<const std::string_view> names) {
    std::string out;
    for (std::size_t i = 0; i < names.size(); ++i) {
        if (i != 0) out.push_back(',');
        out.append(names[i]);
    }
    return out;
}

bool contains_name(std::span<const std::string_view> names, std::string_view needle) {
    for (std::string_view n : names) {
        if (n == needle) return true;
    }
    return false;
}

wire::detail::kexinit make_kexinit(const kex::detail::algorithm_names& n) {
    // name_list borrows joined strings; list nodes stay stable across pushes.
    struct storage {
        std::string kex, host, c2s, s2c, mac_c2s, mac_s2c, comp_c2s, comp_s2c;
    };
    static thread_local std::list<storage> keep;
    keep.push_back({});
    auto& s = keep.back();
    s.kex = join_names(n.kex);
    s.host = join_names(n.host_key);
    s.c2s = join_names(n.cipher);
    s.s2c = join_names(n.cipher);
    s.mac_c2s = join_names(n.mac);
    s.mac_s2c = join_names(n.mac);
    s.comp_c2s = join_names(n.compression);
    s.comp_s2c = join_names(n.compression);

    wire::detail::kexinit m;
    m.kex_algorithms = wire::name_list{s.kex};
    m.server_host_key_algorithms = wire::name_list{s.host};
    m.encryption_c2s = wire::name_list{s.c2s};
    m.encryption_s2c = wire::name_list{s.s2c};
    m.mac_c2s = wire::name_list{s.mac_c2s};
    m.mac_s2c = wire::name_list{s.mac_s2c};
    m.compression_c2s = wire::name_list{s.comp_c2s};
    m.compression_s2c = wire::name_list{s.comp_s2c};
    return m;
}

wire::detail::kexinit make_kexinit_raw(std::string_view kex, std::string_view host,
                               std::string_view enc_c2s, std::string_view enc_s2c,
                               std::string_view mac_c2s, std::string_view mac_s2c,
                               std::string_view comp = "none") {
    struct storage {
        std::string kex, host, c2s, s2c, m_c2s, m_s2c, comp_c2s, comp_s2c;
    };
    static thread_local std::list<storage> keep;
    keep.push_back({std::string{kex}, std::string{host}, std::string{enc_c2s},
                    std::string{enc_s2c}, std::string{mac_c2s}, std::string{mac_s2c},
                    std::string{comp}, std::string{comp}});
    const auto& s = keep.back();
    wire::detail::kexinit m;
    m.kex_algorithms = wire::name_list{s.kex};
    m.server_host_key_algorithms = wire::name_list{s.host};
    m.encryption_c2s = wire::name_list{s.c2s};
    m.encryption_s2c = wire::name_list{s.s2c};
    m.mac_c2s = wire::name_list{s.m_c2s};
    m.mac_s2c = wire::name_list{s.m_s2c};
    m.compression_c2s = wire::name_list{s.comp_c2s};
    m.compression_s2c = wire::name_list{s.comp_s2c};
    return m;
}

}  // namespace

TEST_CASE("KEXINIT cipher list never advertises CBC", "[kex][negotiation]") {
    crypto::provider p = prov();
    core::config cfg{};
    core::detail::local_algorithms algs{p, cfg, core::role::client};
    REQUIRE_FALSE(contains_name(algs.names().cipher, "aes256-cbc"));
    REQUIRE_FALSE(contains_name(algs.names().cipher, "aes128-cbc"));
    REQUIRE(contains_name(algs.names().cipher, "aes256-ctr"));
    REQUIRE(contains_name(algs.names().cipher, "sm4-ctr"));
    REQUIRE_FALSE(contains_name(algs.names().cipher, "sm4-cbc"));
}

TEST_CASE("default name lists omit legacy algorithms", "[kex][nego]") {
    auto p = prov();
    core::config cfg;

    core::detail::local_algorithms client{p, cfg, core::role::client};
    auto n = client.names();
    REQUIRE_FALSE(contains_name(n.kex, "diffie-hellman-group14-sha1"));
    REQUIRE_FALSE(contains_name(n.host_key, "ssh-rsa"));
    REQUIRE_FALSE(contains_name(n.mac, "hmac-sha1"));

    cfg.preferred_kex = "diffie-hellman-group14-sha1,curve25519-sha256";
    cfg.preferred_host_key = "ssh-rsa,ssh-ed25519";
    cfg.preferred_mac = "hmac-sha1,hmac-sha2-256";
    core::detail::local_algorithms legacy{p, cfg, core::role::client};
    auto L = legacy.names();
    REQUIRE(contains_name(L.kex, "diffie-hellman-group14-sha1"));
    REQUIRE(contains_name(L.host_key, "ssh-rsa"));
    REQUIRE(contains_name(L.mac, "hmac-sha1"));
}

TEST_CASE("role-specific ext-info and strict-kex markers trail the kex list", "[kex][nego]") {
    auto p = prov();
    core::config cfg;

    core::detail::local_algorithms client{p, cfg, core::role::client};
    auto c = client.names().kex;
    REQUIRE(c.size() >= 2);
    REQUIRE(c[c.size() - 2] == "ext-info-c");
    REQUIRE(c[c.size() - 1] == "kex-strict-c-v00@openssh.com");

    core::detail::local_algorithms server{p, cfg, core::role::server};
    auto s = server.names().kex;
    REQUIRE(s.size() >= 2);
    REQUIRE(s[s.size() - 2] == "ext-info-s");
    REQUIRE(s[s.size() - 1] == "kex-strict-s-v00@openssh.com");

    core::detail::local_algorithms rekey{p, cfg, core::role::client, /*advertise_ext_info=*/false};
    auto r = rekey.names().kex;
    REQUIRE_FALSE(contains_name(r, "ext-info-c"));
    REQUIRE(r.back() == "kex-strict-c-v00@openssh.com");
}

TEST_CASE("two default local name lists negotiate modern defaults", "[kex][nego]") {
    auto p = prov();
    core::config cfg;

    core::detail::local_algorithms client{p, cfg, core::role::client};
    core::detail::local_algorithms server{p, cfg, core::role::server};
    auto ck = make_kexinit(client.names());
    auto sk = make_kexinit(server.names());

    kex::negotiated out;
    REQUIRE_FALSE(core::detail::negotiate(p, core::role::client, ck, sk, out));
    REQUIRE(out.kex_name == "curve25519-sha256");
    REQUIRE(out.kex == crypto::kex_id::curve25519);
    REQUIRE(out.host_key_name == "ssh-ed25519");
    REQUIRE(out.host_key == crypto::sig_id::ed25519);
    REQUIRE(out.cipher_c2s == crypto::cipher_id::chacha20);
    REQUIRE(out.cipher_s2c == crypto::cipher_id::chacha20);
    REQUIRE(out.mode_c2s == transport::packet_mode::chacha20_poly1305);
    REQUIRE(out.mode_s2c == transport::packet_mode::chacha20_poly1305);
    REQUIRE(out.exchange_hash == crypto::hash_id::sha256);
    REQUIRE(out.strict_kex);
    REQUIRE(out.peer_supports_ext_info);

    REQUIRE_FALSE(core::detail::negotiate(p, core::role::server, ck, sk, out));
    REQUIRE(out.peer_supports_ext_info);
}

TEST_CASE("cipher choice follows client preference constrained by server", "[kex][nego]") {
    auto p = prov();

    auto client = make_kexinit_raw(
        "curve25519-sha256", "ssh-ed25519",
        "aes128-ctr,aes256-ctr", "aes128-ctr,aes256-ctr",
        "hmac-sha2-256", "hmac-sha2-256");
    auto server = make_kexinit_raw(
        "curve25519-sha256", "ssh-ed25519",
        "aes256-ctr", "aes256-ctr",
        "hmac-sha2-256", "hmac-sha2-256");

    kex::negotiated out;
    REQUIRE_FALSE(core::detail::negotiate(p, core::role::client, client, server, out));
    REQUIRE(out.cipher_c2s == crypto::cipher_id::aes256_ctr);
    REQUIRE(out.cipher_s2c == crypto::cipher_id::aes256_ctr);
    REQUIRE(out.mode_c2s == transport::packet_mode::ctr_encrypt_and_mac);
}

TEST_CASE("unsupported client cipher yields no_common_cipher", "[kex][nego]") {
    auto p = prov();

    auto client = make_kexinit_raw(
        "curve25519-sha256", "ssh-ed25519",
        "aes128-cbc", "aes128-cbc",
        "hmac-sha2-256", "hmac-sha2-256");
    auto server = make_kexinit_raw(
        "curve25519-sha256", "ssh-ed25519",
        "aes128-cbc,aes256-ctr", "aes128-cbc,aes256-ctr",
        "hmac-sha2-256", "hmac-sha2-256");

    kex::negotiated out;
    REQUIRE(core::detail::negotiate(p, core::role::client, client, server, out) == code::no_common_cipher);
}

TEST_CASE("no common kex or host key returns dedicated errors", "[kex][nego]") {
    auto p = prov();

    {
        auto client = make_kexinit_raw(
            "diffie-hellman-group1-sha1", "ssh-ed25519",
            "aes256-ctr", "aes256-ctr", "hmac-sha2-256", "hmac-sha2-256");
        auto server = make_kexinit_raw(
            "curve25519-sha256", "ssh-ed25519",
            "aes256-ctr", "aes256-ctr", "hmac-sha2-256", "hmac-sha2-256");
        kex::negotiated out;
        REQUIRE(core::detail::negotiate(p, core::role::client, client, server, out) == code::no_common_kex_algorithm);
    }
    {
        auto client = make_kexinit_raw(
            "curve25519-sha256", "ssh-dss",
            "aes256-ctr", "aes256-ctr", "hmac-sha2-256", "hmac-sha2-256");
        auto server = make_kexinit_raw(
            "curve25519-sha256", "ssh-ed25519",
            "aes256-ctr", "aes256-ctr", "hmac-sha2-256", "hmac-sha2-256");
        kex::negotiated out;
        REQUIRE(core::detail::negotiate(p, core::role::client, client, server, out) == code::no_common_host_key_algorithm);
    }
}

TEST_CASE("strict_kex requires both role markers", "[kex][nego]") {
    auto p = prov();

    auto both = make_kexinit_raw(
        "curve25519-sha256,kex-strict-c-v00@openssh.com", "ssh-ed25519",
        "aes256-ctr", "aes256-ctr", "hmac-sha2-256", "hmac-sha2-256");
    auto server_only = make_kexinit_raw(
        "curve25519-sha256,kex-strict-s-v00@openssh.com", "ssh-ed25519",
        "aes256-ctr", "aes256-ctr", "hmac-sha2-256", "hmac-sha2-256");
    auto client_only = make_kexinit_raw(
        "curve25519-sha256,kex-strict-c-v00@openssh.com", "ssh-ed25519",
        "aes256-ctr", "aes256-ctr", "hmac-sha2-256", "hmac-sha2-256");
    auto plain = make_kexinit_raw(
        "curve25519-sha256", "ssh-ed25519",
        "aes256-ctr", "aes256-ctr", "hmac-sha2-256", "hmac-sha2-256");

    kex::negotiated out;
    REQUIRE_FALSE(core::detail::negotiate(p, core::role::client, both, server_only, out));
    REQUIRE(out.strict_kex);

    REQUIRE_FALSE(core::detail::negotiate(p, core::role::client, client_only, plain, out));
    REQUIRE_FALSE(out.strict_kex);

    REQUIRE_FALSE(core::detail::negotiate(p, core::role::client, plain, server_only, out));
    REQUIRE_FALSE(out.strict_kex);
}

TEST_CASE("peer_supports_ext_info follows peer marker for local role", "[kex][nego]") {
    auto p = prov();

    auto client_with = make_kexinit_raw(
        "curve25519-sha256,ext-info-c", "ssh-ed25519",
        "aes256-ctr", "aes256-ctr", "hmac-sha2-256", "hmac-sha2-256");
    auto server_with = make_kexinit_raw(
        "curve25519-sha256,ext-info-s", "ssh-ed25519",
        "aes256-ctr", "aes256-ctr", "hmac-sha2-256", "hmac-sha2-256");
    auto plain = make_kexinit_raw(
        "curve25519-sha256", "ssh-ed25519",
        "aes256-ctr", "aes256-ctr", "hmac-sha2-256", "hmac-sha2-256");

    kex::negotiated out;

    // Server advertises ext-info-s only: client peer sees support; server does not.
    REQUIRE_FALSE(core::detail::negotiate(p, core::role::client, plain, server_with, out));
    REQUIRE(out.peer_supports_ext_info);
    REQUIRE_FALSE(core::detail::negotiate(p, core::role::server, plain, server_with, out));
    REQUIRE_FALSE(out.peer_supports_ext_info);

    // Client advertises ext-info-c only: server peer sees support; client does not.
    REQUIRE_FALSE(core::detail::negotiate(p, core::role::server, client_with, plain, out));
    REQUIRE(out.peer_supports_ext_info);
    REQUIRE_FALSE(core::detail::negotiate(p, core::role::client, client_with, plain, out));
    REQUIRE_FALSE(out.peer_supports_ext_info);

    // Neither advertises.
    REQUIRE_FALSE(core::detail::negotiate(p, core::role::client, plain, plain, out));
    REQUIRE_FALSE(out.peer_supports_ext_info);
    REQUIRE_FALSE(core::detail::negotiate(p, core::role::server, plain, plain, out));
    REQUIRE_FALSE(out.peer_supports_ext_info);
}

TEST_CASE("AEAD cipher sets AEAD mode and tolerates empty MAC lists", "[kex][nego]") {
    auto p = prov();

    auto client = make_kexinit_raw(
        "curve25519-sha256", "ssh-ed25519",
        "aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com",
        "", "");
    auto server = make_kexinit_raw(
        "curve25519-sha256", "ssh-ed25519",
        "aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com",
        "", "");

    kex::negotiated out;
    REQUIRE_FALSE(core::detail::negotiate(p, core::role::client, client, server, out));
    REQUIRE(out.cipher_c2s == crypto::cipher_id::aes256_gcm);
    REQUIRE(out.cipher_s2c == crypto::cipher_id::chacha20);
    REQUIRE(out.mode_c2s == transport::packet_mode::gcm);
    REQUIRE(out.mode_s2c == transport::packet_mode::chacha20_poly1305);
}

TEST_CASE("CTR MAC selects encrypt-then-mac or encrypt-and-mac", "[kex][nego]") {
    auto p = prov();

    {
        auto client = make_kexinit_raw(
            "curve25519-sha256", "ssh-ed25519",
            "aes256-ctr", "aes256-ctr",
            "hmac-sha2-256-etm@openssh.com", "hmac-sha2-256-etm@openssh.com");
        auto server = client;
        kex::negotiated out;
        REQUIRE_FALSE(core::detail::negotiate(p, core::role::client, client, server, out));
        REQUIRE(out.mode_c2s == transport::packet_mode::ctr_encrypt_then_mac);
        REQUIRE(out.mode_s2c == transport::packet_mode::ctr_encrypt_then_mac);
        REQUIRE(out.mac_c2s == crypto::hash_id::sha256);
        REQUIRE(out.mac_s2c == crypto::hash_id::sha256);
    }
    {
        auto client = make_kexinit_raw(
            "curve25519-sha256", "ssh-ed25519",
            "aes256-ctr", "aes256-ctr",
            "hmac-sha2-256", "hmac-sha2-256");
        auto server = client;
        kex::negotiated out;
        REQUIRE_FALSE(core::detail::negotiate(p, core::role::client, client, server, out));
        REQUIRE(out.mode_c2s == transport::packet_mode::ctr_encrypt_and_mac);
        REQUIRE(out.mode_s2c == transport::packet_mode::ctr_encrypt_and_mac);
    }
}

TEST_CASE("directions may negotiate different ciphers", "[kex][nego]") {
    auto p = prov();

    auto client = make_kexinit_raw(
        "curve25519-sha256", "ssh-ed25519",
        "aes128-ctr,aes256-ctr", "aes256-gcm@openssh.com,aes128-ctr",
        "hmac-sha2-256", "hmac-sha2-256");
    auto server = make_kexinit_raw(
        "curve25519-sha256", "ssh-ed25519",
        "aes256-ctr", "aes256-gcm@openssh.com",
        "hmac-sha2-256", "hmac-sha2-256");

    kex::negotiated out;
    REQUIRE_FALSE(core::detail::negotiate(p, core::role::client, client, server, out));
    REQUIRE(out.cipher_c2s == crypto::cipher_id::aes256_ctr);
    REQUIRE(out.cipher_s2c == crypto::cipher_id::aes256_gcm);
    REQUIRE(out.mode_c2s == transport::packet_mode::ctr_encrypt_and_mac);
    REQUIRE(out.mode_s2c == transport::packet_mode::gcm);
}

TEST_CASE("algorithm query lists", "[core][kex]") {
    auto p = prov();
    using kex::default_cipher_algorithms;
    using kex::default_host_key_algorithms;
    using kex::default_kex_algorithms;
    using kex::default_mac_algorithms;
    using kex::supported_cipher_algorithms;
    using kex::supported_host_key_algorithms;
    using kex::supported_kex_algorithms;
    using kex::supported_mac_algorithms;

    const auto d_kex = default_kex_algorithms(p);
    const auto d_host = default_host_key_algorithms(p);
    const auto d_mac = default_mac_algorithms(p);
    REQUIRE(wire::name_list{d_kex}.contains("curve25519-sha256"));
    REQUIRE_FALSE(wire::name_list{d_kex}.contains("diffie-hellman-group14-sha1"));
    REQUIRE_FALSE(wire::name_list{d_host}.contains("ssh-rsa"));
    REQUIRE_FALSE(wire::name_list{d_mac}.contains("hmac-sha1"));
    REQUIRE_FALSE(wire::name_list{d_kex}.contains("ext-info-c"));
    REQUIRE_FALSE(wire::name_list{d_kex}.contains("kex-strict-c-v00@openssh.com"));

    const auto s_kex = supported_kex_algorithms(p);
    const auto s_host = supported_host_key_algorithms(p);
    const auto s_mac = supported_mac_algorithms(p);
    REQUIRE(wire::name_list{s_kex}.contains("diffie-hellman-group14-sha1"));
    REQUIRE(wire::name_list{s_host}.contains("ssh-rsa"));
    REQUIRE(wire::name_list{s_mac}.contains("hmac-sha1"));
    REQUIRE(wire::name_list{supported_cipher_algorithms(p)}.contains("aes256-ctr"));
    REQUIRE(wire::name_list{default_cipher_algorithms(p)}.contains("aes256-ctr"));
    REQUIRE(wire::name_list{default_cipher_algorithms(p)}.contains("sm4-ctr"));
    REQUIRE_FALSE(wire::name_list{default_cipher_algorithms(p)}.contains("sm4-cbc"));
    REQUIRE(wire::name_list{supported_cipher_algorithms(p)}.contains("sm4-cbc"));
    REQUIRE(wire::name_list{d_kex}.contains("sm2-sm3"));
    REQUIRE(wire::name_list{d_kex}.contains("ecgm-sm2-sm3"));
    REQUIRE(wire::name_list{d_host}.contains("sm2"));
    REQUIRE(wire::name_list{d_mac}.contains("hmac-sm3"));
}

TEST_CASE("preferred_cipher can advertise sm4-cbc", "[kex][negotiation][gm]") {
    crypto::provider p = prov();
    core::config cfg{};
    cfg.preferred_cipher = "sm4-cbc,sm4-ctr";
    core::detail::local_algorithms algs{p, cfg, core::role::client};
    REQUIRE(contains_name(algs.names().cipher, "sm4-cbc"));
    REQUIRE(contains_name(algs.names().cipher, "sm4-ctr"));
}

TEST_CASE("SM4-CBC MAC selects encrypt-then-mac or encrypt-and-mac", "[kex][nego][gm]") {
    auto p = prov();

    {
        auto client = make_kexinit_raw(
            "curve25519-sha256", "ssh-ed25519",
            "sm4-cbc", "sm4-cbc",
            "hmac-sha2-256-etm@openssh.com", "hmac-sha2-256-etm@openssh.com");
        auto server = client;
        kex::negotiated out;
        REQUIRE_FALSE(core::detail::negotiate(p, core::role::client, client, server, out));
        REQUIRE(out.cipher_c2s == crypto::cipher_id::sm4_cbc);
        REQUIRE(out.mode_c2s == transport::packet_mode::cbc_encrypt_then_mac);
        REQUIRE(out.mode_s2c == transport::packet_mode::cbc_encrypt_then_mac);
    }
    {
        auto client = make_kexinit_raw(
            "curve25519-sha256", "ssh-ed25519",
            "sm4-cbc", "sm4-cbc",
            "hmac-sm3", "hmac-sm3");
        auto server = client;
        kex::negotiated out;
        REQUIRE_FALSE(core::detail::negotiate(p, core::role::client, client, server, out));
        REQUIRE(out.mode_c2s == transport::packet_mode::cbc_encrypt_and_mac);
        REQUIRE(out.mode_s2c == transport::packet_mode::cbc_encrypt_and_mac);
    }
}
