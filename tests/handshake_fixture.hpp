#pragma once

#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/auth/types.hpp>
#include <yanterm-ssh/core/config.hpp>
#include <yanterm-ssh/core/connection.hpp>
#include <yanterm-ssh/core/detail/host_key.hpp>
#include <yanterm-ssh/core/types.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>

#include "loopback.hpp"
#include "recording_handler.hpp"

#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#ifndef YANTERM_SSH_FIXTURE_DIR
#error "YANTERM_SSH_FIXTURE_DIR must be defined"
#endif

namespace yanterm::ssh::testing {

inline crypto::provider prov() {
    static crypto::openssl_backend backend;
    return crypto::provider::wrap(backend);
}

inline std::vector<std::byte> load_fixture(std::string_view name) {
    const std::string path = std::string{YANTERM_SSH_FIXTURE_DIR} + "/" + std::string{name};
    std::ifstream in{path, std::ios::binary};
    REQUIRE(in);
    in.seekg(0, std::ios::end);
    const auto n = static_cast<std::size_t>(in.tellg());
    in.seekg(0, std::ios::beg);
    std::vector<std::byte> out(n);
    if (n > 0) {
        in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(n));
        REQUIRE(in);
    }
    return out;
}

struct host_material {
    std::vector<std::byte> blob;
    std::vector<std::byte> seed;
    std::vector<std::byte> pub;
    crypto::private_key_material priv{};
};

inline host_material make_ed25519_host(crypto::provider p) {
    (void)p;
    host_material hm;
    hm.blob = load_fixture("ed25519.blob");
    hm.seed = load_fixture("ed25519.seed");
    core::detail::host_key_view view;
    REQUIRE_FALSE(core::detail::parse_host_key(hm.blob, view));
    hm.pub.assign(view.material.a.begin(), view.material.a.end());
    hm.priv = {crypto::sig_id::ed25519, hm.seed, hm.pub};
    return hm;
}

inline wired_connection make_client(crypto::provider p, const core::config& cfg = {}) {
    return wired_connection{core::role::client, p, cfg};
}

inline wired_connection make_server(crypto::provider p, const core::config& cfg = {}) {
    return wired_connection{core::role::server, p, cfg};
}

inline void configure_server(core::connection& server, host_material& hm) {
    REQUIRE_FALSE(server.set_host_key(hm.blob, hm.priv));
}

inline void configure_server(wired_connection& server, host_material& hm) {
    configure_server(server.conn, hm);
}

struct handshake_capture {
    std::vector<std::string_view> client_types;
    std::vector<std::string_view> server_types;
    std::vector<std::byte> client_session_id;
    std::vector<std::byte> server_session_id;
    std::string client_kex_name;
    std::string server_kex_name;
    std::string_view last_server = "none";
};

inline bool run_handshake(wired_connection& client, wired_connection& server,
                          handshake_capture& cap) {
    return run_loopback(
        client, server,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            const auto name = recorded_event_name(ev);
            if (is_client) {
                cap.client_types.push_back(name);
                accept_client_host_key(client, ev);
                if (const auto* done = std::get_if<recording_handler::handshake_done>(&ev)) {
                    cap.client_kex_name = done->algorithms.kex_name;
                    cap.client_session_id = done->session_id;
                }
            } else {
                cap.server_types.push_back(name);
                cap.last_server = name;
                if (const auto* done = std::get_if<recording_handler::handshake_done>(&ev)) {
                    cap.server_kex_name = done->algorithms.kex_name;
                    cap.server_session_id = done->session_id;
                }
            }
        });
}

inline bool run_password_auth(wired_connection& client, wired_connection& server,
                              std::string_view user = "alice",
                              std::string_view password = "s3cret") {
    if (client.conn.auth_password(user, password)) return false;
    return run_loopback(
        client, server,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (const auto* req = std::get_if<recording_handler::auth_request>(&ev)) {
                if (!is_client) {
                    server.conn.resolve(req->ticket, auth::auth_verdict::success());
                }
            }
        });
}

inline void consume_pending_output(core::connection& c) {
    const auto n = c.pending_output_bytes();
    if (n > 0) c.consume_output(n);
}

template <class OnRecorded>
bool run_auth_loopback(wired_connection& client, wired_connection& server, OnRecorded on_recorded,
                       int max_rounds = 64) {
    return run_loopback(client, server, std::move(on_recorded), max_rounds);
}

inline void bring_up_authed(wired_connection& client, wired_connection& server, host_material& hm) {
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));
    REQUIRE(run_password_auth(client, server));
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

}  // namespace yanterm::ssh::testing
