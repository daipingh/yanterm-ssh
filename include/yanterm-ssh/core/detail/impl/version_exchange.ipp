#pragma once

#include <yanterm-ssh/core/detail/version_exchange.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/core/detail/impl/version_exchange.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/detail/error.hpp>
#include <yanterm-ssh/version.hpp>

namespace yanterm::ssh::core::detail {

YANTERM_SSH_INLINE version_exchange::version_exchange(role r, std::string_view software)
    : role_{r} {
    local_ = "SSH-2.0-";
    local_ += valid_software(software) ? software : ::yanterm::ssh::default_software();
}

YANTERM_SSH_INLINE std::span<const std::byte> version_exchange::outgoing() const noexcept {
    // Materialised lazily so that local_ and the sent bytes cannot diverge.
    if (wire_.empty()) {
        wire_ = local_;
        wire_ += "\r\n";
    }
    return {reinterpret_cast<const std::byte*>(wire_.data()), wire_.size()};
}

YANTERM_SSH_INLINE std::error_code version_exchange::feed(std::span<const std::byte> in, std::size_t& accepted) {
    accepted = 0;
    while (!done_ && accepted < in.size()) {
        const auto rest = in.subspan(accepted);
        std::size_t nl = rest.size();
        for (std::size_t i = 0; i < rest.size(); ++i) {
            if (static_cast<char>(rest[i]) == '\n') {
                nl = i;
                break;
            }
        }

        if (nl == rest.size()) {
            // No terminator yet. Reject only when even a bare LF would push
            // the line past the limit; otherwise wait for more bytes.
            if (rest.size() + 1u > max_identification_line) {
                return code::version_line_too_long;
            }
            return {};
        }

        const bool crlf = nl > 0 && static_cast<char>(rest[nl - 1]) == '\r';
        const std::size_t content_len = crlf ? nl - 1u : nl;
        const std::size_t term_bytes = crlf ? 2u : 1u;
        if (content_len + term_bytes > max_identification_line) {
            return code::version_line_too_long;
        }

        const std::string_view line{reinterpret_cast<const char*>(rest.data()), content_len};
        if (auto ec = finish_line(line)) {
            // The offending line is consumed so the caller does not loop on it.
            accepted += nl + 1u;
            return ec;
        }
        accepted += nl + 1u;
    }
    return {};
}

YANTERM_SSH_INLINE bool version_exchange::valid_software(std::string_view s) noexcept {
    if (s.empty()) return false;
    // "SSH-2.0-" (8) + software + CR LF (2) must fit in 255.
    constexpr std::size_t prefix_and_crlf = 10;
    if (s.size() > max_identification_line - prefix_and_crlf) return false;
    for (char c : s) {
        const auto u = static_cast<unsigned char>(c);
        if (u <= 0x20u || u >= 0x7fu || c == '-') return false;
    }
    return true;
}

YANTERM_SSH_INLINE std::error_code version_exchange::finish_line(std::string_view line) {
    if (line.rfind("SSH-", 0) != 0) {
        // Only a client tolerates preamble lines, and only from a server.
        if (role_ == role::client) return {};
        return code::missing_version_banner;
    }
    if (line.rfind("SSH-2.0-", 0) != 0 && line.rfind("SSH-1.99-", 0) != 0) {
        return code::unsupported_protocol_version;
    }
    peer_.assign(line);
    done_ = true;
    return {};
}

}  // namespace yanterm::ssh::core::detail
