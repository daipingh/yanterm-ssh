#pragma once

#include <yanterm-ssh/kex/algorithms.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/kex/impl/algorithms.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/kex/detail/tables.hpp>

namespace yanterm::ssh::kex {

YANTERM_SSH_INLINE std::string default_kex_algorithms(crypto::provider p) {
    std::string out;
    for (const auto& e : detail::kex_table) {
        if (e.name == "diffie-hellman-group14-sha1") continue;
        if (!detail::provider_supports_kex(p, e)) continue;
        if (!out.empty()) out.push_back(',');
        out.append(e.name);
    }
    return out;
}

YANTERM_SSH_INLINE std::string supported_kex_algorithms(crypto::provider p) {
    std::string out;
    for (const auto& e : detail::kex_table) {
        if (!detail::provider_supports_kex(p, e)) continue;
        if (!out.empty()) out.push_back(',');
        out.append(e.name);
    }
    return out;
}

YANTERM_SSH_INLINE std::string default_host_key_algorithms(crypto::provider p) {
    std::string out;
    for (const auto& e : detail::host_key_table) {
        if (e.name == "ssh-rsa") continue;
        if (!detail::provider_supports_host_key(p, e)) continue;
        if (!out.empty()) out.push_back(',');
        out.append(e.name);
    }
    return out;
}

YANTERM_SSH_INLINE std::string supported_host_key_algorithms(crypto::provider p) {
    std::string out;
    for (const auto& e : detail::host_key_table) {
        if (!detail::provider_supports_host_key(p, e)) continue;
        if (!out.empty()) out.push_back(',');
        out.append(e.name);
    }
    return out;
}

YANTERM_SSH_INLINE std::string default_cipher_algorithms(crypto::provider p) {
    std::string out;
    for (const auto& e : detail::cipher_table) {
        if (e.name == "sm4-cbc") continue;
        if (!detail::provider_supports_cipher(p, e)) continue;
        if (!out.empty()) out.push_back(',');
        out.append(e.name);
    }
    return out;
}

YANTERM_SSH_INLINE std::string supported_cipher_algorithms(crypto::provider p) {
    std::string out;
    for (const auto& e : detail::cipher_table) {
        if (!detail::provider_supports_cipher(p, e)) continue;
        if (!out.empty()) out.push_back(',');
        out.append(e.name);
    }
    return out;
}

YANTERM_SSH_INLINE std::string default_mac_algorithms(crypto::provider p) {
    std::string out;
    for (const auto& e : detail::mac_table) {
        if (e.name == "hmac-sha1") continue;
        if (!detail::provider_supports_mac(p, e)) continue;
        if (!out.empty()) out.push_back(',');
        out.append(e.name);
    }
    return out;
}

YANTERM_SSH_INLINE std::string supported_mac_algorithms(crypto::provider p) {
    std::string out;
    for (const auto& e : detail::mac_table) {
        if (!detail::provider_supports_mac(p, e)) continue;
        if (!out.empty()) out.push_back(',');
        out.append(e.name);
    }
    return out;
}

}  // namespace yanterm::ssh::kex
