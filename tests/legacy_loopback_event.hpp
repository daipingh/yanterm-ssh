#pragma once

#include "recording_handler.hpp"

#include <yanterm-ssh/auth/types.hpp>
#include <yanterm-ssh/channels/types.hpp>
#include <yanterm-ssh/core/types.hpp>

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace yanterm::ssh::testing {

enum class legacy_event_type : std::uint8_t {
    none,
    peer_identification,
    verify_host_key,
    handshake_done,
    rekey_done,
    debug_message,
    ignore_message,
    disconnected,
    auth_banner,
    auth_response,
    auth_request,
    auth_info_request,
    auth_info_response,
    channel_opened,
    channel_open_failed,
    channel_open_request,
    channel_readable,
    channel_writable,
    channel_eof,
    channel_closed,
    channel_request,
    channel_response,
    global_request,
    global_response,
};

struct legacy_event {
    legacy_event_type type = legacy_event_type::none;
    core::channel_ref ref{};
    core::host_key_ticket host_key{};
    core::auth_ticket auth_ticket{};
    core::kbdint_ticket kbdint{};
    core::open_ticket inbound_open{};
    core::channel_request_ticket channel_req{};
    core::global_request_ticket global_req{};

    std::string_view request_type;
    std::span<const std::byte> request_payload;
    bool want_reply = false;
    std::string_view tcp_host;
    std::uint32_t tcp_port = 0;
    std::string_view originator_host;
    std::uint32_t originator_port = 0;
    std::string_view socket_path;
    channels::channel_open_reason open_reason{};
    std::string_view text;
    channels::channel_id ch = 0;
    std::uint32_t ext_type = 0;
    std::uint32_t window = 0;
    std::uint32_t max_packet = 0;
    bool request_success = false;

    auth::auth_result auth{};

    struct scratch {
        std::string request_type;
        std::vector<std::byte> request_payload;
        std::string text;
        std::string host;
        std::string originator_host;
        std::string socket_path;
        auth::auth_result auth;
    };
};

inline std::optional<legacy_event> legacy_event_from_recorded(
    const recording_handler::recorded_event& rec, legacy_event::scratch& scratch) {
    return std::visit(
        [&](const auto& value) -> std::optional<legacy_event> {
            using T = std::decay_t<decltype(value)>;
            legacy_event ev{};
            if constexpr (std::is_same_v<T, recording_handler::channel_open_request>) {
                ev.type = legacy_event_type::channel_open_request;
                ev.inbound_open = value.ticket;
                ev.ref = value.ref;
                ev.ch = value.ref.index;
                scratch.request_type = value.type_name;
                scratch.request_payload = value.extra;
                ev.request_type = scratch.request_type;
                ev.request_payload = scratch.request_payload;
                scratch.host = value.host;
                scratch.originator_host = value.originator_host;
                ev.tcp_host = scratch.host;
                ev.tcp_port = value.port;
                ev.originator_host = scratch.originator_host;
                ev.originator_port = value.originator_port;
                scratch.socket_path = value.socket_path;
                ev.socket_path = scratch.socket_path;
                return ev;
            }
            if constexpr (std::is_same_v<T, recording_handler::channel_opened>) {
                ev.type = legacy_event_type::channel_opened;
                ev.ref = value.ref;
                ev.ch = value.ref.index;
                ev.window = value.window;
                ev.max_packet = value.max_packet;
                return ev;
            }
            if constexpr (std::is_same_v<T, recording_handler::channel_open_failed>) {
                ev.type = legacy_event_type::channel_open_failed;
                ev.ref = value.ref;
                ev.ch = value.ref.index;
                ev.open_reason = value.reason;
                scratch.text = value.description;
                ev.text = scratch.text;
                return ev;
            }
            if constexpr (std::is_same_v<T, recording_handler::channel_request>) {
                ev.type = legacy_event_type::channel_request;
                ev.channel_req = value.ticket;
                ev.ref = core::connection::channel_ref_of(value.ticket);
                ev.ch = ev.ref.index;
                scratch.request_type = value.type;
                scratch.request_payload = value.payload;
                ev.request_type = scratch.request_type;
                ev.request_payload = scratch.request_payload;
                ev.want_reply = value.want_reply;
                return ev;
            }
            if constexpr (std::is_same_v<T, recording_handler::channel_response>) {
                ev.type = legacy_event_type::channel_response;
                ev.ref = value.ref;
                ev.ch = value.ref.index;
                ev.request_success = value.success;
                return ev;
            }
            if constexpr (std::is_same_v<T, recording_handler::global_request>) {
                ev.type = legacy_event_type::global_request;
                ev.global_req = value.ticket;
                scratch.request_type = value.type;
                scratch.request_payload = value.payload;
                ev.request_type = scratch.request_type;
                ev.request_payload = scratch.request_payload;
                ev.want_reply = value.want_reply;
                return ev;
            }
            if constexpr (std::is_same_v<T, recording_handler::global_response>) {
                ev.type = legacy_event_type::global_response;
                ev.request_success = value.success;
                scratch.request_payload = value.payload;
                ev.request_payload = scratch.request_payload;
                return ev;
            }
            if constexpr (std::is_same_v<T, recording_handler::channel_readable>) {
                ev.type = legacy_event_type::channel_readable;
                ev.ref = value.ref;
                ev.ch = value.ref.index;
                ev.ext_type = value.ext_type;
                return ev;
            }
            if constexpr (std::is_same_v<T, recording_handler::channel_writable>) {
                ev.type = legacy_event_type::channel_writable;
                ev.ref = value.ref;
                ev.ch = value.ref.index;
                return ev;
            }
            if constexpr (std::is_same_v<T, recording_handler::channel_eof>) {
                ev.type = legacy_event_type::channel_eof;
                ev.ref = value.ref;
                ev.ch = value.ref.index;
                return ev;
            }
            if constexpr (std::is_same_v<T, recording_handler::channel_closed>) {
                ev.type = legacy_event_type::channel_closed;
                ev.ref = value.ref;
                ev.ch = value.ref.index;
                return ev;
            }
            if constexpr (std::is_same_v<T, recording_handler::auth_response>) {
                ev.type = legacy_event_type::auth_response;
                scratch.auth.success = value.success;
                scratch.auth.partial_success = value.partial_success;
                scratch.auth.pk_ok = value.pk_ok;
                scratch.auth.methods = value.methods;
                ev.auth = scratch.auth;
                return ev;
            }
            if constexpr (std::is_same_v<T, recording_handler::auth_request>) {
                ev.type = legacy_event_type::auth_request;
                ev.auth_ticket = value.ticket;
                return ev;
            }
            return std::nullopt;
        },
        rec);
}

template <class Fn>
inline void dispatch_legacy_recorded(recording_handler& handler, Fn&& fn) {
    while (!handler.events.empty()) {
        legacy_event::scratch scratch;
        auto rec = handler.events.front();
        handler.events.erase(handler.events.begin());
        if (auto ev = legacy_event_from_recorded(rec, scratch)) fn(*ev);
    }
}

}  // namespace yanterm::ssh::testing
