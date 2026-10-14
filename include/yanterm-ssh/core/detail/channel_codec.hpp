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

[[nodiscard]] inline std::string_view type_string(const channels::channel_open_spec& spec) noexcept {
    if (spec.type == channels::channel_type::unknown) return spec.extra_type;
    return channels::type_name(spec.type);
}

void encode_open_extra(const channels::channel_open_spec& spec, wire::writer& extra);

[[nodiscard]] channels::open_request_view make_open_view(const wire::detail::channel_open& msg);

}  // namespace yanterm::ssh::core::detail

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/core/detail/impl/channel_codec.ipp>
#endif
