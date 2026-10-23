#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/transport/packet_mode.hpp>
#include <yanterm-ssh/wire/types.hpp>
#include <yanterm-ssh/crypto/algorithms.hpp>
#include <yanterm-ssh/crypto/provider.hpp>

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace yanterm::ssh::kex::detail {

// Wire name to internal id, in preference order, filtered by provider capability.
struct algorithm_names {
    std::span<const std::string_view> kex;
    std::span<const std::string_view> host_key;
    std::span<const std::string_view> cipher;
    std::span<const std::string_view> mac;
    std::span<const std::string_view> compression;
};

inline constexpr std::string_view ext_info_c = "ext-info-c";
inline constexpr std::string_view ext_info_s = "ext-info-s";
inline constexpr std::string_view strict_kex_c = "kex-strict-c-v00@openssh.com";
inline constexpr std::string_view strict_kex_s = "kex-strict-s-v00@openssh.com";

struct kex_entry {
    std::string_view name;
    crypto::kex_id id;
    crypto::hash_id hash;
};

struct host_key_entry {
    std::string_view name;
    crypto::sig_id id;
};

enum class cipher_kind : std::uint8_t { ctr, cbc, gcm, chacha };

struct cipher_entry {
    std::string_view name;
    crypto::cipher_id id;
    cipher_kind kind;
};

struct mac_entry {
    std::string_view name;
    crypto::hash_id hash;
    bool etm;
};

inline constexpr kex_entry kex_table[] = {
    {"mlkem768x25519-sha256", crypto::kex_id::mlkem768x25519, crypto::hash_id::sha256},
    {"curve25519-sha256", crypto::kex_id::curve25519, crypto::hash_id::sha256},
    {"curve25519-sha256@libssh.org", crypto::kex_id::curve25519, crypto::hash_id::sha256},
    {"ecdh-sha2-nistp256", crypto::kex_id::ecdh_nistp256, crypto::hash_id::sha256},
    {"ecdh-sha2-nistp384", crypto::kex_id::ecdh_nistp384, crypto::hash_id::sha384},
    {"ecdh-sha2-nistp521", crypto::kex_id::ecdh_nistp521, crypto::hash_id::sha512},
    {"sm2-sm3", crypto::kex_id::sm2_kap, crypto::hash_id::sm3},
    {"ecgm-sm2-sm3", crypto::kex_id::ecdh_sm2, crypto::hash_id::sm3},
    {"diffie-hellman-group16-sha512", crypto::kex_id::dh_group16, crypto::hash_id::sha512},
    {"diffie-hellman-group14-sha256", crypto::kex_id::dh_group14, crypto::hash_id::sha256},
    {"diffie-hellman-group14-sha1", crypto::kex_id::dh_group14, crypto::hash_id::sha1},
};

inline constexpr host_key_entry host_key_table[] = {
    {"ssh-ed25519", crypto::sig_id::ed25519},
    {"ecdsa-sha2-nistp256", crypto::sig_id::ecdsa_nistp256},
    {"ecdsa-sha2-nistp384", crypto::sig_id::ecdsa_nistp384},
    {"ecdsa-sha2-nistp521", crypto::sig_id::ecdsa_nistp521},
    {"sm2", crypto::sig_id::sm2_za},
    {"rsa-sha2-512", crypto::sig_id::rsa_pkcs1_sha512},
    {"rsa-sha2-256", crypto::sig_id::rsa_pkcs1_sha256},
    {"ssh-rsa", crypto::sig_id::rsa_pkcs1_sha1},
};

inline constexpr cipher_entry cipher_table[] = {
    {"chacha20-poly1305@openssh.com", crypto::cipher_id::chacha20, cipher_kind::chacha},
    {"aes256-gcm@openssh.com", crypto::cipher_id::aes256_gcm, cipher_kind::gcm},
    {"aes128-gcm@openssh.com", crypto::cipher_id::aes128_gcm, cipher_kind::gcm},
    {"aes256-ctr", crypto::cipher_id::aes256_ctr, cipher_kind::ctr},
    {"aes192-ctr", crypto::cipher_id::aes192_ctr, cipher_kind::ctr},
    {"aes128-ctr", crypto::cipher_id::aes128_ctr, cipher_kind::ctr},
    {"sm4-ctr", crypto::cipher_id::sm4_ctr, cipher_kind::ctr},
    {"sm4-cbc", crypto::cipher_id::sm4_cbc, cipher_kind::cbc},
};

inline constexpr mac_entry mac_table[] = {
    {"hmac-sha2-256-etm@openssh.com", crypto::hash_id::sha256, true},
    {"hmac-sha2-512-etm@openssh.com", crypto::hash_id::sha512, true},
    {"hmac-sha2-256", crypto::hash_id::sha256, false},
    {"hmac-sha2-512", crypto::hash_id::sha512, false},
    {"hmac-sha1", crypto::hash_id::sha1, false},
    {"hmac-sm3", crypto::hash_id::sm3, false},
};

[[nodiscard]] constexpr bool uses_ecdh_messages(crypto::kex_id id) noexcept {
    switch (id) {
    case crypto::kex_id::curve25519:
    case crypto::kex_id::ecdh_nistp256:
    case crypto::kex_id::ecdh_nistp384:
    case crypto::kex_id::ecdh_nistp521:
    case crypto::kex_id::ecdh_sm2:
    case crypto::kex_id::sm2_kap:
    case crypto::kex_id::sm2_kap_server:
    case crypto::kex_id::mlkem768x25519: return true;
    default: return false;
    }
}

[[nodiscard]] inline bool is_kex_marker(std::string_view name) noexcept {
    return name == ext_info_c || name == ext_info_s || name == strict_kex_c || name == strict_kex_s;
}

[[nodiscard]] inline const kex_entry* find_kex(std::string_view name) noexcept {
    for (const auto& e : kex_table) {
        if (e.name == name) return &e;
    }
    return nullptr;
}

[[nodiscard]] inline const host_key_entry* find_host_key(std::string_view name) noexcept {
    for (const auto& e : host_key_table) {
        if (e.name == name) return &e;
    }
    return nullptr;
}

[[nodiscard]] inline const cipher_entry* find_cipher(std::string_view name) noexcept {
    for (const auto& e : cipher_table) {
        if (e.name == name) return &e;
    }
    return nullptr;
}

[[nodiscard]] inline const mac_entry* find_mac(std::string_view name) noexcept {
    for (const auto& e : mac_table) {
        if (e.name == name) return &e;
    }
    return nullptr;
}

[[nodiscard]] inline bool provider_supports_kex(crypto::provider p, const kex_entry& e) noexcept {
    return p.supports(e.id) && p.supports(e.hash);
}

[[nodiscard]] inline bool provider_supports_host_key(crypto::provider p,
                                                     const host_key_entry& e) noexcept {
    return p.supports(e.id);
}

[[nodiscard]] inline bool provider_supports_cipher(crypto::provider p,
                                                   const cipher_entry& e) noexcept {
    return p.supports(e.id);
}

[[nodiscard]] inline bool provider_supports_mac(crypto::provider p, const mac_entry& e) noexcept {
    return p.supports(e.hash);
}

[[nodiscard]] inline bool is_aead(cipher_kind kind) noexcept {
    return kind == cipher_kind::gcm || kind == cipher_kind::chacha;
}

[[nodiscard]] inline ::yanterm::ssh::transport::packet_mode mode_for(cipher_kind kind, bool etm) noexcept {
    switch (kind) {
    case cipher_kind::gcm: return ::yanterm::ssh::transport::packet_mode::gcm;
    case cipher_kind::chacha: return ::yanterm::ssh::transport::packet_mode::chacha20_poly1305;
    case cipher_kind::ctr:
        return etm ? ::yanterm::ssh::transport::packet_mode::ctr_encrypt_then_mac
                   : ::yanterm::ssh::transport::packet_mode::ctr_encrypt_and_mac;
    case cipher_kind::cbc:
        return etm ? ::yanterm::ssh::transport::packet_mode::cbc_encrypt_then_mac
                   : ::yanterm::ssh::transport::packet_mode::cbc_encrypt_and_mac;
    }
    return ::yanterm::ssh::transport::packet_mode::plaintext;
}

// First name in `client` that also appears in `server` and for which `accept`
// returns true. Skips names that fail `accept` (unknown / unsupported).
template <class Accept>
[[nodiscard]] std::optional<std::string_view> first_common(const wire::name_list& client,
                                                           const wire::name_list& server,
                                                           Accept accept) {
    for (std::string_view name : client) {
        if (!server.contains(name)) continue;
        if (!accept(name)) continue;
        return name;
    }
    return std::nullopt;
}

}  // namespace yanterm::ssh::kex::detail
