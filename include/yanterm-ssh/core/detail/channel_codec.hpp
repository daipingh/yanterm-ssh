#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/channels/types.hpp>
#include <yanterm-ssh/core/detail/packet.hpp>
#include <yanterm-ssh/wire/types.hpp>

#include <algorithm>
#include <cstdint>
#include <string_view>

namespace yanterm::ssh::wire::detail {
struct channel_open;
}

namespace yanterm::ssh::core::detail {

static_assert(channels::max_channel_data_payload
              == static_cast<std::uint32_t>(
                  core::detail::max_packet_length
                  - (1u + 4u + 4u + 4u)));

[[nodiscard]] inline std::uint32_t clamp_remote_max_packet(std::uint32_t advertised) noexcept {
    return std::clamp(advertised, 1u, channels::max_channel_data_payload);
}

// RFC 4251 section 6: printable US-ASCII, no comma or whitespace, at most 64
// characters. An at-sign, if present, appears once and has text on both sides.
[[nodiscard]] inline bool ssh_name_ok(std::string_view name) noexcept {
    if (name.empty() || name.size() > 64) return false;
    const auto at = name.find('@');
    if (at != std::string_view::npos) {
        if (at == 0 || at + 1 == name.size()) return false;
        if (name.find('@', at + 1) != std::string_view::npos) return false;
    }
    for (const char ch : name) {
        const auto c = static_cast<unsigned char>(ch);
        if (c < 0x21 || c > 0x7E || c == ',') return false;
    }
    return true;
}

// `fixed` is the encoded size aside from the name and the raw tail.
[[nodiscard]] inline bool control_message_fits(std::size_t fixed, std::string_view name,
                                               std::span<const std::byte> tail) noexcept {
    if (name.size() > max_control_payload || tail.size() > max_control_payload) return false;
    const std::size_t n = fixed + name.size() + tail.size();
    return n >= fixed && n <= max_control_payload;
}

[[nodiscard]] channels::open_request_view make_open_view(const wire::detail::channel_open& msg);

}  // namespace yanterm::ssh::core::detail

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/core/detail/impl/channel_codec.ipp>
#endif
