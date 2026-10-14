#pragma once

#include "handshake_fixture.hpp"
#include "legacy_loopback_event.hpp"
#include "loopback.hpp"
#include "recording_handler.hpp"

#include <yanterm-ssh/channels/types.hpp>
#include <yanterm-ssh/core/connection.hpp>

#include <cstddef>
#include <optional>
#include <vector>

namespace yanterm::ssh::testing {

struct session_ids {
    core::channel_ref client_ch{};
    core::channel_ref server_ch{};
};

inline void transfer_once(core::connection& from, core::connection& to) {
    const auto out = from.pending_output0();
    REQUIRE_FALSE(out.empty());
    std::size_t n = 0;
    REQUIRE_FALSE(to.feed(out, n));
    REQUIRE(n > 0);
    from.consume_output(n);
}

inline void transfer_all(core::connection& from, core::connection& to) {
    while (!from.pending_output0().empty()) {
        transfer_once(from, to);
    }
}

inline void transfer_all(wired_connection& from, wired_connection& to) {
    transfer_all(from.conn, to.conn);
}

inline void append_recorded(wired_connection& side, std::vector<recording_handler::recorded_event>& out) {
    out.insert(out.end(), side.handler.events.begin(), side.handler.events.end());
    side.handler.events.clear();
}

inline void transfer_once_capture(wired_connection& from, wired_connection& to,
                                  std::vector<recording_handler::recorded_event>& cap) {
    const auto out = from.conn.pending_output0();
    REQUIRE_FALSE(out.empty());
    std::size_t n = 0;
    REQUIRE_FALSE(to.conn.feed(out, n));
    REQUIRE(n > 0);
    from.conn.consume_output(n);
    append_recorded(to, cap);
}

inline void transfer_all_capture(wired_connection& from, wired_connection& to,
                                 std::vector<recording_handler::recorded_event>& cap) {
    while (!from.conn.pending_output0().empty()) {
        transfer_once_capture(from, to, cap);
    }
}

inline session_ids open_session(wired_connection& client, wired_connection& server, int rounds = 256) {
    core::channel_ref cid{};
    REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, cid));
    session_ids ids;
    bool opened = false;
    bool accepted = false;
    REQUIRE(run_loopback_recorded(
        client, server,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (!is_client) {
                if (const auto* o = std::get_if<recording_handler::channel_open_request>(&ev)) {
                    ids.server_ch = o->ref;
                    server.conn.resolve(o->ticket, channels::channel_open_verdict::accepted());
                    accepted = true;
                }
            }
            if (is_client) {
                if (const auto* r = std::get_if<recording_handler::channel_opened>(&ev)) {
                    ids.client_ch = r->ref;
                    opened = true;
                }
            }
        },
        rounds));
    REQUIRE(opened);
    REQUIRE(accepted);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
    return ids;
}

inline std::optional<legacy_event> pop_legacy_event(wired_connection& side) {
    for (auto it = side.handler.events.begin(); it != side.handler.events.end(); ++it) {
        if (auto ev = legacy_event_from_recorded(*it, side.legacy_scratch)) {
            side.handler.events.erase(it);
            return ev;
        }
    }
    return std::nullopt;
}

inline std::optional<legacy_event> peek_legacy_event(wired_connection& side) {
    for (const auto& rec : side.handler.events) {
        if (auto ev = legacy_event_from_recorded(rec, side.legacy_scratch)) return ev;
    }
    return std::nullopt;
}

inline void accept_inbound_open(core::connection& side, bool for_client, bool is_client,
                                const recording_handler::recorded_event& ev) {
    if (is_client != for_client) return;
    if (const auto* o = std::get_if<recording_handler::channel_open_request>(&ev)) {
        side.resolve(o->ticket, channels::channel_open_verdict::accepted());
    }
}

}  // namespace yanterm::ssh::testing
