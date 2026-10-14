#include <catch2/catch_test_macros.hpp>
#include "handshake_fixture.hpp"
#include "scripted_peer.hpp"

#include <yanterm-ssh/wire/detail/messages.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/detail/error.hpp>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

using auth::auth_verdict;
using auth::service_userauth;

TEST_CASE("handshake does not send SERVICE_REQUEST", "[auth][service]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));
    REQUIRE(client.conn.pending_output_bytes() == 0);
    REQUIRE(server.conn.pending_output_bytes() == 0);
}

TEST_CASE("auth_none triggers service request then none", "[auth][service][none]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    REQUIRE_FALSE(client.conn.auth_none("alice"));

    bool saw_req = false;
    bool saw_resp = false;
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client, const recording_handler::recorded_event& ev) {
        if (!is_client && std::holds_alternative<recording_handler::auth_request>(ev)) {
            REQUIRE(std::get<recording_handler::auth_request>(ev).user == "alice");
            REQUIRE(std::get<recording_handler::auth_request>(ev).service == "ssh-connection");
            REQUIRE(std::get<recording_handler::auth_request>(ev).method == "none");
            saw_req = true;
            server.conn.resolve(std::get<recording_handler::auth_request>(ev).ticket, auth_verdict::failure("publickey,password"));
        }
        if (is_client && std::holds_alternative<recording_handler::auth_response>(ev)) {
            REQUIRE_FALSE(std::get<recording_handler::auth_response>(ev).success);
            REQUIRE(std::get<recording_handler::auth_response>(ev).methods == "publickey,password");
            REQUIRE_FALSE(std::get<recording_handler::auth_response>(ev).partial_success);
            saw_resp = true;
        }
    }));
    REQUIRE(saw_req);
    REQUIRE(saw_resp);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("second auth_none while outstanding is invalid_state", "[auth][service]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));
    REQUIRE_FALSE(client.conn.auth_none("alice"));
    const auto ec = client.conn.auth_none("alice");
    REQUIRE(ec == code::invalid_state);
    REQUIRE_FALSE(client.conn.failure());
}

TEST_CASE("auth_none before handshake is invalid_state", "[auth][service]") {
    auto p = prov();
    auto client = make_client(p);
    REQUIRE(client->auth_none("alice") == code::invalid_state);
}

TEST_CASE("none success authenticates", "[auth][none]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));
    REQUIRE_FALSE(client.conn.auth_none("alice"));
    bool ok = false;
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client, const recording_handler::recorded_event& ev) {
        if (!is_client && std::holds_alternative<recording_handler::auth_request>(ev)) {
            server.conn.resolve(std::get<recording_handler::auth_request>(ev).ticket, auth_verdict::success());
        }
        if (is_client && std::holds_alternative<recording_handler::auth_response>(ev)) {
            REQUIRE(std::get<recording_handler::auth_response>(ev).success);
            ok = true;
        }
    }));
    REQUIRE(ok);
    REQUIRE(client->auth_none("alice") == code::invalid_state);
}

TEST_CASE("feed pauses on server auth_request until resolve", "[auth][service][pause]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));
    REQUIRE_FALSE(client.conn.auth_none("alice"));

    core::auth_ticket pending{};
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client, const recording_handler::recorded_event& ev) {
        if (!is_client && std::holds_alternative<recording_handler::auth_request>(ev)) {
            pending = std::get<recording_handler::auth_request>(ev).ticket;
            // do not resolve
        }
    }));
    REQUIRE(pending != core::auth_ticket{});
    // Client still has no auth_response; server is paused. Resolving later
    // then looping should complete.
    server.conn.resolve(pending, auth_verdict::failure("publickey"));
    bool saw = false;
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client, const recording_handler::recorded_event& ev) {
        if (is_client && std::holds_alternative<recording_handler::auth_response>(ev)) saw = true;
    }));
    REQUIRE(saw);
}

TEST_CASE("unknown service name disconnects service_not_available", "[auth][service]") {
    peer_session s{core::role::server};
    s.handshake();
    s.peer.send_msg(wire::detail::service_msg{wire::msg::service_request, "ssh-connection"});
    REQUIRE(s.peer.deliver(s.sut) == code::unsupported_service);
    REQUIRE(s.sut.handler.events.empty());
    s.peer.collect(s.sut);
    const auto disc = s.peer.take(wire::msg::disconnect);
    REQUIRE(disc);
    wire::reader r{*disc};
    wire::detail::disconnect_msg d;
    REQUIRE(d.decode(r));
    REQUIRE(d.reason == wire::disconnect_reason::service_not_available);
}

TEST_CASE("post-auth SERVICE_REQUEST is unexpected_message", "[auth][service]") {
    peer_session s{core::role::server};
    s.authenticate();
    s.peer.send_msg(wire::detail::service_msg{wire::msg::service_request, service_userauth});
    REQUIRE(s.peer.deliver(s.sut) == code::unexpected_message);
    REQUIRE(s.sut.handler.events.empty());
}

TEST_CASE("configured auth_banner follows SERVICE_ACCEPT", "[auth][banner]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);

    SECTION("non-empty banner arrives before auth_response") {
        core::config scfg;
        scfg.auth_banner = "Authorized use only.\n";
        auto client = make_client(p);
        auto server = make_server(p, scfg);
        configure_server(server, hm);
        handshake_capture cap;
        REQUIRE(run_handshake(client, server, cap));

        REQUIRE_FALSE(client.conn.auth_none("alice"));

        bool saw_banner = false;
        bool saw_response = false;
        std::string banner_text;
        REQUIRE(run_auth_loopback(client, server, [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (is_client && std::holds_alternative<recording_handler::auth_banner>(ev)) {
                saw_banner = true;
                banner_text.assign(std::get<recording_handler::auth_banner>(ev).text.begin(),
                                   std::get<recording_handler::auth_banner>(ev).text.end());
            }
            if (is_client && std::holds_alternative<recording_handler::auth_response>(ev)) {
                saw_response = true;
            }
            if (!is_client && std::holds_alternative<recording_handler::auth_request>(ev)) {
                server.conn.resolve(std::get<recording_handler::auth_request>(ev).ticket,
                                    auth_verdict::success());
            }
        }));
        REQUIRE(saw_banner);
        REQUIRE(saw_response);
        REQUIRE(banner_text == "Authorized use only.\n");
        REQUIRE_FALSE(client.conn.failure());
        REQUIRE_FALSE(server.conn.failure());
    }

    SECTION("empty banner is not sent") {
        auto client = make_client(p);
        auto server = make_server(p);
        configure_server(server, hm);
        handshake_capture cap;
        REQUIRE(run_handshake(client, server, cap));

        REQUIRE_FALSE(client.conn.auth_none("alice"));

        bool saw_banner = false;
        REQUIRE(run_auth_loopback(client, server, [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (is_client && std::holds_alternative<recording_handler::auth_banner>(ev)) saw_banner = true;
            if (!is_client && std::holds_alternative<recording_handler::auth_request>(ev)) {
                server.conn.resolve(std::get<recording_handler::auth_request>(ev).ticket,
                                    auth_verdict::success());
            }
        }));
        REQUIRE_FALSE(saw_banner);
        REQUIRE_FALSE(client.conn.failure());
        REQUIRE_FALSE(server.conn.failure());
    }
}

TEST_CASE("SERVICE_REQUEST during a pending verdict stalls and is rejected after resolve",
          "[auth][service]") {
    peer_session s{core::role::server};
    s.peer.request_userauth_service(s.sut);
    s.peer.send_msg(wire::detail::userauth_request_none{"alice", "ssh-connection"});
    s.peer.send_msg(wire::detail::service_msg{wire::msg::service_request, service_userauth});
    REQUIRE_FALSE(s.peer.deliver(s.sut));
    REQUIRE(s.sut.conn.inbound_requests_stalled());
    REQUIRE(s.peer.pending_bytes() > 0);              // SERVICE_REQUEST 尚未被消费
    REQUIRE(s.sut.handler.events.size() == 1);
    const auto* req = std::get_if<recording_handler::auth_request>(&s.sut.handler.events[0]);
    REQUIRE(req != nullptr);

    REQUIRE_FALSE(s.sut.conn.resolve(req->ticket, auth_verdict::failure("password")));
    s.peer.collect(s.sut);
    REQUIRE(s.peer.take(wire::msg::userauth_failure));   // 裁决未丢失
    REQUIRE(s.peer.deliver(s.sut) == code::unexpected_message);
}
