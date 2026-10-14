#pragma once

#include <yanterm-ssh/core/detail/host_key.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/core/detail/impl/host_key.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/detail/error.hpp>
#include <yanterm-ssh/kex/detail/tables.hpp>
#include <yanterm-ssh/keys/public_key.hpp>

#include <cstdint>

namespace yanterm::ssh::core::detail {

[[nodiscard]] YANTERM_SSH_INLINE bool der_read_len(std::span<const std::byte>& p,
                                                   std::size_t& n) noexcept {
    if (p.empty()) return false;
    const auto b = std::to_integer<std::uint8_t>(p[0]);
    p = p.subspan(1);
    if (b < 0x80u) {
        n = b;
        return true;
    }
    if (b == 0x81u) {
        if (p.empty()) return false;
        n = std::to_integer<std::uint8_t>(p[0]);
        p = p.subspan(1);
        return true;
    }
    return false;
}

[[nodiscard]] YANTERM_SSH_INLINE bool parse_der_ecdsa_rs(std::span<const std::byte> inner,
                                                         std::span<const std::byte>& r,
                                                         std::span<const std::byte>& s) noexcept {
    if (inner.size() < 8 || std::to_integer<std::uint8_t>(inner[0]) != 0x30u) return false;
    auto p = inner.subspan(1);
    std::size_t seq_len = 0;
    if (!der_read_len(p, seq_len) || p.size() != seq_len) return false;
    if (p.empty() || std::to_integer<std::uint8_t>(p[0]) != 0x02u) return false;
    p = p.subspan(1);
    std::size_t rlen = 0;
    if (!der_read_len(p, rlen) || rlen == 0 || p.size() < rlen) return false;
    r = p.first(rlen);
    p = p.subspan(rlen);
    if (p.empty() || std::to_integer<std::uint8_t>(p[0]) != 0x02u) return false;
    p = p.subspan(1);
    std::size_t slen = 0;
    if (!der_read_len(p, slen) || slen == 0 || p.size() < slen) return false;
    s = p.first(slen);
    p = p.subspan(slen);
    return p.empty();
}

[[nodiscard]] YANTERM_SSH_INLINE bool parse_mpint_ecdsa_rs(std::span<const std::byte> inner,
                                                           std::span<const std::byte>& r,
                                                           std::span<const std::byte>& s) noexcept {
    wire::reader in{inner};
    return in.read_mpint(r) && in.read_mpint(s) && in.empty() && !r.empty() && !s.empty();
}

// Kylin mpint first, then openEuler DER.
[[nodiscard]] YANTERM_SSH_INLINE bool parse_sm2_inner(std::span<const std::byte> inner,
                                                      std::span<const std::byte>& r,
                                                      std::span<const std::byte>& s,
                                                      crypto::sig_id& dialect) noexcept {
    if (parse_mpint_ecdsa_rs(inner, r, s)) {
        dialect = crypto::sig_id::sm2_ecdsa;
        return true;
    }
    if (parse_der_ecdsa_rs(inner, r, s)) {
        dialect = crypto::sig_id::sm2_za;
        return true;
    }
    return false;
}

YANTERM_SSH_INLINE std::error_code parse_host_key(std::span<const std::byte> blob, host_key_view& out) {
    keys::public_key tmp;
    if (auto ec = keys::public_key::parse_blob(blob, tmp)) return ec;

    const auto owned = tmp.blob();
    auto remap_span = [&](std::span<const std::byte> s) -> std::span<const std::byte> {
        if (s.empty() || s.data() == nullptr) return {};
        const auto off = static_cast<std::size_t>(s.data() - owned.data());
        return blob.subspan(off, s.size());
    };
    auto remap_sv = [&](std::string_view s) -> std::string_view {
        if (s.empty()) return {};
        const auto off = static_cast<std::size_t>(
            reinterpret_cast<const std::byte*>(s.data()) - owned.data());
        return std::string_view{reinterpret_cast<const char*>(blob.data() + off), s.size()};
    };

    const auto mat = tmp.material();
    out.algorithm_name = remap_sv(tmp.algorithm_name());
    out.algorithm = tmp.algorithm();
    out.material.algorithm = mat.algorithm;
    out.material.a = remap_span(mat.a);
    out.material.b = remap_span(mat.b);
    out.blob = blob;
    return {};
}

YANTERM_SSH_INLINE std::error_code verify_signature(crypto::provider p, const host_key_view& key,
                                        std::string_view expected_algorithm,
                                        std::span<const std::byte> signature_blob,
                                        std::span<const std::byte> message,
                                        crypto::sig_id* detected) {
    if (!p) return code::crypto_backend_failure;

    wire::reader r{signature_blob};
    std::string_view sig_name;
    std::span<const std::byte> payload;
    if (!r.read_string(sig_name) || !r.read_string(payload) || !r.empty()) {
        return code::invalid_host_key;
    }

    // Negotiated name must match the name inside the signature blob.
    if (sig_name != expected_algorithm) {
        return code::signature_verification_failed;
    }

    const kex::detail::host_key_entry* entry = kex::detail::find_host_key(sig_name);
    if (entry == nullptr) return code::unsupported_algorithm;
    if (!p.supports(entry->id)) return code::unsupported_algorithm;
    if (!key_compatible_with_sig(key, entry->id)) {
        return code::signature_verification_failed;
    }

    crypto::public_key_material verify_key = key.material;
    // Digest choice follows the signature / negotiated algorithm, not the
    // pubkey blob name (RSA pubkey is always "ssh-rsa").
    verify_key.algorithm = entry->id;

    crypto::signature_material sig{};
    if (entry->id == crypto::sig_id::ed25519) {
        if (payload.size() != 64) return code::invalid_host_key;
        sig.a = payload;
    } else if (crypto::is_ecdsa_sig(entry->id)) {
        wire::reader inner{payload};
        std::span<const std::byte> rr;
        std::span<const std::byte> ss;
        if (!inner.read_mpint(rr) || !inner.read_mpint(ss) || !inner.empty()) {
            return code::invalid_host_key;
        }
        if (rr.empty() || ss.empty()) return code::invalid_host_key;
        sig.a = rr;
        sig.b = ss;
    } else if (crypto::is_sm2_sig(entry->id)) {
        std::span<const std::byte> rr;
        std::span<const std::byte> ss;
        crypto::sig_id dialect{};
        if (!parse_sm2_inner(payload, rr, ss, dialect)) return code::invalid_host_key;
        verify_key.algorithm = dialect;
        sig.a = rr;
        sig.b = ss;
    } else if (crypto::is_rsa_sig(entry->id)) {
        if (payload.empty()) return code::invalid_host_key;
        sig.a = payload;
    } else {
        return code::unsupported_algorithm;
    }

    if (!p.verify(verify_key, message, sig)) {
        return code::signature_verification_failed;
    }
    if (detected != nullptr) *detected = verify_key.algorithm;
    return {};
}

YANTERM_SSH_INLINE std::error_code encode_host_key(const crypto::public_key_material& key, wire::writer& out) {
    yanterm::ssh::keys::public_key pk;
    if (auto ec = yanterm::ssh::keys::public_key::from_material(key, pk)) return ec;
    out.write_bytes(pk.blob());
    return {};
}

YANTERM_SSH_INLINE std::error_code encode_signature(std::string_view algorithm_name,
                                        std::span<const std::byte> raw_signature,
                                        wire::writer& out) {
    if (kex::detail::find_host_key(algorithm_name) == nullptr) {
        return code::unsupported_algorithm;
    }
    out.write_string(algorithm_name);
    out.write_string(raw_signature);
    return {};
}

}  // namespace yanterm::ssh::core::detail
