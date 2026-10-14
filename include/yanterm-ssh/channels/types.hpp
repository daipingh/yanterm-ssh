#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace yanterm::ssh::channels {

using channel_id = std::uint32_t;

inline constexpr std::uint32_t extended_data_stderr = 1;

inline constexpr std::string_view type_session = "session";
inline constexpr std::string_view type_direct_tcpip = "direct-tcpip";
inline constexpr std::string_view type_forwarded_tcpip = "forwarded-tcpip";
inline constexpr std::string_view type_x11 = "x11";
inline constexpr std::string_view type_direct_streamlocal = "direct-streamlocal@openssh.com";
inline constexpr std::string_view type_forwarded_streamlocal = "forwarded-streamlocal@openssh.com";

// Largest CHANNEL_DATA / CHANNEL_EXTENDED_DATA payload we will emit. Derived
// from transport::max_packet_length (35000) minus the extended-data header:
// msg(1) + recipient(4) + data_type(4) + string length(4).
inline constexpr std::uint32_t max_channel_data_payload = 35000u - (1u + 4u + 4u + 4u);

enum class channel_type : std::uint8_t {
    session, direct_tcpip, forwarded_tcpip, x11, direct_streamlocal, forwarded_streamlocal, unknown
};

enum class channel_open_reason : std::uint32_t {
    administratively_prohibited = 1,
    connect_failed = 2,
    unknown_channel_type = 3,
    resource_shortage = 4,
};

[[nodiscard]] inline std::string_view type_name(channel_type t) noexcept {
    switch (t) {
    case channel_type::session: return type_session;
    case channel_type::direct_tcpip: return type_direct_tcpip;
    case channel_type::forwarded_tcpip: return type_forwarded_tcpip;
    case channel_type::x11: return type_x11;
    case channel_type::direct_streamlocal: return type_direct_streamlocal;
    case channel_type::forwarded_streamlocal: return type_forwarded_streamlocal;
    case channel_type::unknown: return {};
    }
    return {};
}

[[nodiscard]] inline channel_type parse_type(std::string_view n) noexcept {
    if (n == type_session) return channel_type::session;
    if (n == type_direct_tcpip) return channel_type::direct_tcpip;
    if (n == type_forwarded_tcpip) return channel_type::forwarded_tcpip;
    if (n == type_x11) return channel_type::x11;
    if (n == type_direct_streamlocal) return channel_type::direct_streamlocal;
    if (n == type_forwarded_streamlocal) return channel_type::forwarded_streamlocal;
    return channel_type::unknown;
}

struct channel_open_spec {
    channel_type type = channel_type::session;
    std::uint32_t initial_window = 0;  // 0 → config.initial_window
    std::uint32_t max_packet = 0;      // 0 → config.max_channel_packet
    std::string host;
    std::uint32_t port = 0;
    std::string originator_host;
    std::uint32_t originator_port = 0;
    std::string socket_path;
    std::string extra_type;  // when type==unknown
    std::span<const std::byte> extra{};
};

struct channel_open_verdict {
    bool accept = false;
    channel_open_reason reason = channel_open_reason::administratively_prohibited;
    std::string description;
    std::uint32_t initial_window = 0;
    std::uint32_t max_packet = 0;

    static channel_open_verdict accepted(std::uint32_t win = 0, std::uint32_t pkt = 0) {
        channel_open_verdict v;
        v.accept = true;
        v.initial_window = win;
        v.max_packet = pkt;
        return v;
    }
    static channel_open_verdict rejected(channel_open_reason r, std::string_view desc) {
        channel_open_verdict v;
        v.reason = r;
        v.description.assign(desc.begin(), desc.end());
        return v;
    }
};

struct channel_request_spec {
    std::string_view type;
    std::span<const std::byte> payload{};
    bool want_reply = true;
};

struct open_request_view {
    channel_type type = channel_type::unknown;
    std::string_view type_name;
    std::uint32_t window = 0;
    std::uint32_t max_packet = 0;
    std::string_view host;
    std::uint32_t port = 0;
    std::string_view originator_host;
    std::uint32_t originator_port = 0;
    std::string_view socket_path;
    std::span<const std::byte> extra;
};

struct open_result_view {
    bool success = false;
    std::uint32_t window = 0;
    std::uint32_t max_packet = 0;
    channel_open_reason reason = channel_open_reason::administratively_prohibited;
    std::string_view description;
};

struct request_view {
    std::string_view type;
    std::span<const std::byte> payload;
    bool want_reply = false;
};

struct window_size {
    std::uint32_t cols = 80;
    std::uint32_t rows = 24;
    std::uint32_t pixel_width = 0;
    std::uint32_t pixel_height = 0;
};

struct pty_spec {
    std::string_view term = "xterm";
    std::uint32_t width = 80;
    std::uint32_t height = 24;
    std::uint32_t pixel_width = 0;
    std::uint32_t pixel_height = 0;
    std::span<const std::byte> modes{};
};

struct x11_req_spec {
    bool single_connection = false;
    std::string_view protocol{};
    std::string_view cookie{};
    std::uint32_t screen = 0;
};

struct exit_signal {
    std::string_view name;
    bool core_dumped = false;
    std::string_view message{};
    std::string_view language{};
};

}  // namespace yanterm::ssh::channels
