#pragma once

#include <yanterm-ssh/core/config.hpp>
#include <yanterm-ssh/core/connection.hpp>

#include "legacy_loopback_event.hpp"
#include "recording_handler.hpp"

#include <cstddef>
#include <memory_resource>
#include <system_error>

namespace yanterm::ssh::testing {

struct wired_connection {
    recording_handler handler;
    core::connection conn;
    legacy_event::scratch legacy_scratch{};

    wired_connection(core::role r, crypto::provider p, const core::config& cfg = {},
                     std::pmr::memory_resource* mr = std::pmr::get_default_resource())
        : conn{r, p, cfg, handler, mr} {}

    operator core::connection&() noexcept { return conn; }
    operator const core::connection&() const noexcept { return conn; }

    [[nodiscard]] core::connection* operator->() noexcept { return &conn; }
    [[nodiscard]] const core::connection* operator->() const noexcept { return &conn; }
};

inline void accept_client_host_key(wired_connection& client,
                                   const recording_handler::recorded_event& ev) {
    if (const auto* host = std::get_if<recording_handler::verify_host_key>(&ev)) {
        client.conn.resolve(host->ticket, core::host_key_verdict::accept);
    }
}

template <class OnRecorded>
bool run_loopback(core::connection& client, recording_handler& client_handler,
                  core::connection& server, recording_handler& server_handler,
                  wired_connection* client_wired, wired_connection* server_wired,
                  OnRecorded on_recorded, int max_rounds = 64) {
    auto drain_recorded = [&](recording_handler& handler, wired_connection* wired_side,
                              bool is_client) {
        while (!handler.events.empty()) {
            auto rec = handler.events.front();
            handler.events.erase(handler.events.begin());
            on_recorded(is_client, rec);
        }
        (void)wired_side;
    };

    drain_recorded(client_handler, client_wired, true);
    if (&server_handler != &client_handler) drain_recorded(server_handler, server_wired, false);

    for (int round = 0; round < max_rounds; ++round) {
        bool progress = false;
        auto transfer = [&](core::connection& from, core::connection& to,
                            recording_handler& to_handler, wired_connection* to_wired,
                            bool to_is_client) {
            const auto out = from.pending_output0();
            if (out.empty()) return;
            std::size_t accepted = 0;
            (void)to.feed(out, accepted);
            if (accepted > 0) {
                from.consume_output(accepted);
                progress = true;
            }
            drain_recorded(to_handler, to_wired, to_is_client);
        };
        transfer(client, server, server_handler, server_wired, false);
        transfer(server, client, client_handler, client_wired, true);
        if (!progress) return !client.failure() && !server.failure();
    }
    return false;
}

inline bool run_loopback(wired_connection& client, wired_connection& server, int max_rounds = 64) {
    return run_loopback(
        client.conn, client.handler, server.conn, server.handler, &client, &server,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (is_client) accept_client_host_key(client, ev);
        },
        max_rounds);
}

template <class OnRecorded>
bool run_loopback(wired_connection& client, wired_connection& server, OnRecorded on_recorded,
                  int max_rounds = 64) {
    return run_loopback(client.conn, client.handler, server.conn, server.handler, &client, &server,
                        std::move(on_recorded), max_rounds);
}

template <class OnRecorded>
bool run_loopback_recorded(wired_connection& client, wired_connection& server, OnRecorded on_recorded,
                           int max_rounds = 64) {
    return run_loopback(client, server, std::move(on_recorded), max_rounds);
}

// Adapts handler records into legacy_event views for tests not yet on recorded_event.
template <class OnLegacy>
bool run_loopback_legacy(wired_connection& client, wired_connection& server, OnLegacy on_event,
                         int max_rounds = 64) {
    return run_loopback(
        client, server,
        [&](bool is_client, const recording_handler::recorded_event& rec) {
            legacy_event::scratch scratch;
            if (auto ev = legacy_event_from_recorded(rec, scratch)) on_event(is_client, *ev);
        },
        max_rounds);
}

template <class OnLegacy>
bool run_loopback_legacy(core::connection& client, recording_handler& client_handler,
                         core::connection& server, recording_handler& server_handler,
                         wired_connection* client_wired, wired_connection* server_wired,
                         OnLegacy on_event, int max_rounds = 64) {
    return run_loopback(
        client, client_handler, server, server_handler, client_wired, server_wired,
        [&](bool is_client, const recording_handler::recorded_event& rec) {
            legacy_event::scratch scratch;
            if (auto ev = legacy_event_from_recorded(rec, scratch)) on_event(is_client, *ev);
        },
        max_rounds);
}

}  // namespace yanterm::ssh::testing
