#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/wire/types.hpp>
#include <yanterm-ssh/crypto/algorithms.hpp>

#include <cstdint>
#include <span>
#include <string_view>
#include <system_error>

namespace yanterm::ssh::keys::detail {

enum class pubkey_kind : std::uint8_t { ed25519, ecdsa, rsa };

struct pubkey_type {
    std::string_view name;
    crypto::sig_id id;
    pubkey_kind kind;
    std::string_view curve;  // ecdsa only
};

inline constexpr pubkey_type pubkey_types[] = {
    {"ssh-ed25519", crypto::sig_id::ed25519, pubkey_kind::ed25519, {}},
    {"ecdsa-sha2-nistp256", crypto::sig_id::ecdsa_nistp256, pubkey_kind::ecdsa, "nistp256"},
    {"ecdsa-sha2-nistp384", crypto::sig_id::ecdsa_nistp384, pubkey_kind::ecdsa, "nistp384"},
    {"ecdsa-sha2-nistp521", crypto::sig_id::ecdsa_nistp521, pubkey_kind::ecdsa, "nistp521"},
    {"sm2", crypto::sig_id::sm2_za, pubkey_kind::ecdsa, "sm2"},
    {"ssh-rsa", crypto::sig_id::rsa_pkcs1_sha1, pubkey_kind::rsa, {}},
};

[[nodiscard]] inline bool is_cert_or_sk(std::string_view name) noexcept {
    if (name.starts_with("sk-")) return true;
    return name.find("-cert-") != std::string_view::npos;
}

[[nodiscard]] inline const pubkey_type* find_pubkey_type(std::string_view name) noexcept {
    for (const auto& e : pubkey_types) {
        if (e.name == name) return &e;
    }
    return nullptr;
}

[[nodiscard]] const pubkey_type* find_pubkey_type(crypto::sig_id id) noexcept;

struct parsed_pubkey {
    crypto::sig_id algorithm{};
    std::string_view name;
    std::span<const std::byte> a;
    std::span<const std::byte> b;
};

[[nodiscard]] std::error_code parse_pubkey_blob(std::span<const std::byte> blob,
                                                parsed_pubkey& out);

std::error_code encode_pubkey_material(const crypto::public_key_material& key,
                                       wire::writer& out);

}  // namespace yanterm::ssh::keys::detail

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/keys/detail/impl/wire_key.ipp>
#endif
