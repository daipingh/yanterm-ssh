#pragma once

#include <yanterm-ssh/core/detail/kex_negotiation.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/core/detail/impl/kex_negotiation.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/detail/error.hpp>

#include <utility>

namespace yanterm::ssh::core::detail {

YANTERM_SSH_INLINE local_algorithms::local_algorithms(crypto::provider p,
                                          const ::yanterm::ssh::core::config& cfg,
                                          ::yanterm::ssh::core::role r,
                                          bool advertise_ext_info, bool advertise_strict_kex,
                                          std::span<const std::string_view> host_key_allowlist) {
    if (!cfg.preferred_kex.empty()) {
        for (std::string_view name : wire::name_list{cfg.preferred_kex}) {
            if (kex::detail::is_kex_marker(name)) continue;
            const kex::detail::kex_entry* e = kex::detail::find_kex(name);
            if (e == nullptr) continue;
            if (!kex::detail::provider_supports_kex(p, *e)) continue;
            kex_.push_back(e->name);
        }
    } else {
        for (const auto& e : kex::detail::kex_table) {
            if (e.name == "diffie-hellman-group14-sha1") continue;
            if (!kex::detail::provider_supports_kex(p, e)) continue;
            kex_.push_back(e.name);
        }
    }
    if (advertise_ext_info) {
        kex_.push_back(r == ::yanterm::ssh::core::role::client ? kex::detail::ext_info_c : kex::detail::ext_info_s);
    }
    if (advertise_strict_kex) {
        kex_.push_back(r == ::yanterm::ssh::core::role::client ? kex::detail::strict_kex_c : kex::detail::strict_kex_s);
    }

    if (!cfg.preferred_host_key.empty()) {
        for (std::string_view name : wire::name_list{cfg.preferred_host_key}) {
            const kex::detail::host_key_entry* e = kex::detail::find_host_key(name);
            if (e == nullptr) continue;
            if (!kex::detail::provider_supports_host_key(p, *e)) continue;
            host_key_.push_back(e->name);
        }
    } else {
        for (const auto& e : kex::detail::host_key_table) {
            if (e.name == "ssh-rsa") continue;
            if (!kex::detail::provider_supports_host_key(p, e)) continue;
            host_key_.push_back(e.name);
        }
    }
    if (!host_key_allowlist.empty()) {
        std::vector<std::string_view> filtered;
        filtered.reserve(host_key_.size());
        for (std::string_view name : host_key_) {
            bool allowed = false;
            for (std::string_view a : host_key_allowlist) {
                if (a == name) {
                    allowed = true;
                    break;
                }
            }
            if (allowed) filtered.push_back(name);
        }
        host_key_ = std::move(filtered);
    }

    if (!cfg.preferred_cipher.empty()) {
        for (std::string_view name : wire::name_list{cfg.preferred_cipher}) {
            const kex::detail::cipher_entry* e = kex::detail::find_cipher(name);
            if (e == nullptr) continue;
            if (!kex::detail::provider_supports_cipher(p, *e)) continue;
            cipher_.push_back(e->name);
        }
    } else {
        for (const auto& e : kex::detail::cipher_table) {
            if (e.name == "sm4-cbc") continue;
            if (!kex::detail::provider_supports_cipher(p, e)) continue;
            cipher_.push_back(e.name);
        }
    }

    if (!cfg.preferred_mac.empty()) {
        for (std::string_view name : wire::name_list{cfg.preferred_mac}) {
            const kex::detail::mac_entry* e = kex::detail::find_mac(name);
            if (e == nullptr) continue;
            if (!kex::detail::provider_supports_mac(p, *e)) continue;
            mac_.push_back(e->name);
        }
    } else {
        for (const auto& e : kex::detail::mac_table) {
            if (e.name == "hmac-sha1") continue;
            if (!kex::detail::provider_supports_mac(p, e)) continue;
            mac_.push_back(e.name);
        }
    }

    compression_.push_back("none");
}

[[nodiscard]] YANTERM_SSH_INLINE std::size_t usable_name_count(std::span<const std::string_view> names) noexcept {
    std::size_t n = 0;
    for (std::string_view name : names) {
        if (!kex::detail::is_kex_marker(name)) ++n;
    }
    return n;
}

YANTERM_SSH_INLINE kex::detail::algorithm_names local_algorithms::names() const noexcept {
    return {
        std::span<const std::string_view>{kex_},
        std::span<const std::string_view>{host_key_},
        std::span<const std::string_view>{cipher_},
        std::span<const std::string_view>{mac_},
        std::span<const std::string_view>{compression_},
    };
}

YANTERM_SSH_INLINE std::error_code negotiate(crypto::provider p, ::yanterm::ssh::core::role r,
                                 const wire::detail::kexinit& client,
                                 const wire::detail::kexinit& server,
                                 ::yanterm::ssh::kex::negotiated& out) {
    out = ::yanterm::ssh::kex::negotiated{};

    out.strict_kex = client.kex_algorithms.contains(kex::detail::strict_kex_c)
                     && server.kex_algorithms.contains(kex::detail::strict_kex_s);
    // peer_supports_ext_info: whether the peer advertised *their* marker
    // (ext-info-s when we are client; ext-info-c when we are server).
    out.peer_supports_ext_info =
        r == ::yanterm::ssh::core::role::client ? server.kex_algorithms.contains(kex::detail::ext_info_s)
                          : client.kex_algorithms.contains(kex::detail::ext_info_c);

    const auto kex_name = kex::detail::first_common(
        client.kex_algorithms, server.kex_algorithms, [&](std::string_view name) {
            if (kex::detail::is_kex_marker(name)) return false;
            const kex::detail::kex_entry* e = kex::detail::find_kex(name);
            return e != nullptr && kex::detail::provider_supports_kex(p, *e);
        });
    if (!kex_name) return code::no_common_kex_algorithm;
    const kex::detail::kex_entry* kex_e = kex::detail::find_kex(*kex_name);
    out.kex_name = kex_e->name;
    out.kex = kex_e->id;
    out.exchange_hash = kex_e->hash;

    const auto host_name = kex::detail::first_common(
        client.server_host_key_algorithms, server.server_host_key_algorithms,
        [&](std::string_view name) {
            const kex::detail::host_key_entry* e = kex::detail::find_host_key(name);
            return e != nullptr && kex::detail::provider_supports_host_key(p, *e);
        });
    if (!host_name) return code::no_common_host_key_algorithm;
    const kex::detail::host_key_entry* host_e = kex::detail::find_host_key(*host_name);
    out.host_key_name = host_e->name;
    out.host_key = host_e->id;

    auto pick_cipher = [&](const wire::name_list& c, const wire::name_list& s,
                           crypto::cipher_id& id, kex::detail::cipher_kind& kind) -> std::error_code {
        const auto name = kex::detail::first_common(c, s, [&](std::string_view n) {
            const kex::detail::cipher_entry* e = kex::detail::find_cipher(n);
            return e != nullptr && kex::detail::provider_supports_cipher(p, *e);
        });
        if (!name) return code::no_common_cipher;
        const kex::detail::cipher_entry* e = kex::detail::find_cipher(*name);
        id = e->id;
        kind = e->kind;
        return {};
    };

    kex::detail::cipher_kind kind_c2s{};
    kex::detail::cipher_kind kind_s2c{};
    if (auto ec = pick_cipher(client.encryption_c2s, server.encryption_c2s, out.cipher_c2s,
                              kind_c2s)) {
        return ec;
    }
    if (auto ec = pick_cipher(client.encryption_s2c, server.encryption_s2c, out.cipher_s2c,
                              kind_s2c)) {
        return ec;
    }

    auto pick_mac = [&](const wire::name_list& c, const wire::name_list& s, bool aead,
                        crypto::hash_id& hash, bool& etm) -> std::error_code {
        if (aead) {
            // 留意M: AEAD ignores MAC; empty / no-common MAC must not fail.
            const auto name = kex::detail::first_common(c, s, [&](std::string_view n) {
                const kex::detail::mac_entry* e = kex::detail::find_mac(n);
                return e != nullptr && kex::detail::provider_supports_mac(p, *e);
            });
            if (name) {
                const kex::detail::mac_entry* e = kex::detail::find_mac(*name);
                hash = e->hash;
                etm = e->etm;
            }
            return {};
        }
        const auto name = kex::detail::first_common(c, s, [&](std::string_view n) {
            const kex::detail::mac_entry* e = kex::detail::find_mac(n);
            return e != nullptr && kex::detail::provider_supports_mac(p, *e);
        });
        if (!name) return code::no_common_mac;
        const kex::detail::mac_entry* e = kex::detail::find_mac(*name);
        hash = e->hash;
        etm = e->etm;
        return {};
    };

    bool etm_c2s = false;
    bool etm_s2c = false;
    if (auto ec = pick_mac(client.mac_c2s, server.mac_c2s, kex::detail::is_aead(kind_c2s), out.mac_c2s,
                           etm_c2s)) {
        return ec;
    }
    if (auto ec = pick_mac(client.mac_s2c, server.mac_s2c, kex::detail::is_aead(kind_s2c), out.mac_s2c,
                           etm_s2c)) {
        return ec;
    }

    out.mode_c2s = kex::detail::mode_for(kind_c2s, etm_c2s);
    out.mode_s2c = kex::detail::mode_for(kind_s2c, etm_s2c);

    auto pick_comp = [&](const wire::name_list& c, const wire::name_list& s) -> std::error_code {
        const auto name = kex::detail::first_common(c, s, [](std::string_view n) { return n == "none"; });
        if (!name) return code::no_common_compression;
        return {};
    };
    if (auto ec = pick_comp(client.compression_c2s, server.compression_c2s)) return ec;
    if (auto ec = pick_comp(client.compression_s2c, server.compression_s2c)) return ec;

    return {};
}

}  // namespace yanterm::ssh::core::detail
