#pragma once

#include <yanterm-ssh/keys/detail/wire_key.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/keys/detail/impl/wire_key.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/detail/error.hpp>

namespace yanterm::ssh::keys::detail {

[[nodiscard]] YANTERM_SSH_INLINE std::error_code map_key_read_error(const wire::reader& r) noexcept {
    const auto ec = r.error();
    if (ec == code::unsupported_algorithm) return ec;
    return code::invalid_host_key;
}

[[nodiscard]] YANTERM_SSH_INLINE const pubkey_type* find_pubkey_type(crypto::sig_id id) noexcept {
    if (crypto::is_rsa_sig(id)) return find_pubkey_type(std::string_view{"ssh-rsa"});
    if (crypto::is_sm2_sig(id)) return find_pubkey_type(std::string_view{"sm2"});
    for (const auto& e : pubkey_types) {
        if (e.id == id) return &e;
    }
    return nullptr;
}

YANTERM_SSH_INLINE std::error_code parse_pubkey_blob(std::span<const std::byte> blob,
                                                       parsed_pubkey& out) {
    wire::reader r{blob};
    std::string_view name;
    if (!r.read_string(name)) return map_key_read_error(r);

    if (is_cert_or_sk(name)) return code::unsupported_key_format;

    const pubkey_type* type = find_pubkey_type(name);
    if (type == nullptr) return code::unsupported_algorithm;

    parsed_pubkey parsed{};
    parsed.algorithm = type->id;
    parsed.name = name;

    if (type->kind == pubkey_kind::ed25519) {
        std::span<const std::byte> key;
        if (!r.read_string(key)) return map_key_read_error(r);
        if (key.size() != 32) return code::invalid_host_key;
        parsed.a = key;
    } else if (type->kind == pubkey_kind::ecdsa) {
        std::string_view curve;
        std::span<const std::byte> q;
        if (!r.read_string(curve) || !r.read_string(q)) return map_key_read_error(r);
        if (curve != type->curve) return code::invalid_host_key;
        if (q.empty() || std::to_integer<std::uint8_t>(q[0]) != 0x04u) {
            return code::invalid_host_key;
        }
        parsed.a = q;
    } else if (type->kind == pubkey_kind::rsa) {
        std::span<const std::byte> e;
        std::span<const std::byte> n;
        if (!r.read_mpint(e) || !r.read_mpint(n)) return map_key_read_error(r);
        if (e.empty() || n.empty()) return code::invalid_host_key;
        parsed.a = n;
        parsed.b = e;
    } else {
        return code::unsupported_algorithm;
    }

    if (!r.empty()) return code::invalid_host_key;

    out = parsed;
    return {};
}

YANTERM_SSH_INLINE std::error_code encode_pubkey_material(const crypto::public_key_material& key,
                                              wire::writer& out) {
    const pubkey_type* type = find_pubkey_type(key.algorithm);
    if (type == nullptr) return code::unsupported_algorithm;

    out.write_string(type->name);

    if (type->kind == pubkey_kind::ed25519) {
        if (key.a.size() != 32) return code::invalid_host_key;
        out.write_string(key.a);
        return {};
    }
    if (type->kind == pubkey_kind::ecdsa) {
        if (type->curve.empty() || key.a.empty()
            || std::to_integer<std::uint8_t>(key.a[0]) != 0x04u) {
            return code::invalid_host_key;
        }
        out.write_string(type->curve);
        out.write_string(key.a);
        return {};
    }
    if (type->kind == pubkey_kind::rsa) {
        if (key.a.empty() || key.b.empty()) return code::invalid_host_key;
        out.write_mpint(key.b);
        out.write_mpint(key.a);
        return {};
    }
    return code::unsupported_algorithm;
}

}  // namespace yanterm::ssh::keys::detail
