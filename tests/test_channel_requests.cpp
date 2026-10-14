#include <catch2/catch_test_macros.hpp>
#include "channel_test_helpers.hpp"

#include <yanterm-ssh/channels/requests.hpp>
#include <yanterm-ssh/channels/types.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/detail/error.hpp>

#include <cstddef>
#include <string_view>
#include <vector>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

namespace {

constexpr int k_rounds = 256;

template <class T>
const T* find_first(const std::vector<recording_handler::recorded_event>& evs) {
    for (const auto& ev : evs) {
        if (const auto* p = std::get_if<T>(&ev)) return p;
    }
    return nullptr;
}

template <class T>
std::vector<const T*> find_all(const std::vector<recording_handler::recorded_event>& evs) {
    std::vector<const T*> out;
    for (const auto& ev : evs) {
        if (const auto* p = std::get_if<T>(&ev)) out.push_back(p);
    }
    return out;
}

}  // namespace

TEST_CASE("pipelined pty-req then shell is serial on the server", "[channel][request]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    REQUIRE_FALSE(client.conn.request_pty(ids.client_ch, {}));
    REQUIRE_FALSE(client.conn.request_shell(ids.client_ch));

    std::vector<recording_handler::recorded_event> cap;
    transfer_all_capture(client, server, cap);
    const auto reqs = find_all<recording_handler::channel_request>(cap);
    REQUIRE(reqs.size() == 2);
    REQUIRE(reqs[0]->type == "pty-req");
    REQUIRE(reqs[0]->want_reply);
    REQUIRE(reqs[1]->type == "shell");
    REQUIRE(reqs[1]->want_reply);
    const auto first_ticket = reqs[0]->ticket;
    const auto second_ticket = reqs[1]->ticket;
    REQUIRE(first_ticket != second_ticket);

    REQUIRE_FALSE(server.conn.resolve(first_ticket, true));

    transfer_once_capture(server, client, cap);
    const auto* cr = find_first<recording_handler::channel_response>(cap);
    REQUIRE(cr);
    REQUIRE(cr->ref == ids.client_ch);
    REQUIRE(cr->success);

    REQUIRE_FALSE(server.conn.resolve(second_ticket, true));
    transfer_once_capture(server, client, cap);
    const auto* cr2 = find_first<recording_handler::channel_response>(cap);
    REQUIRE(cr2);
    REQUIRE(cr2->ref == ids.client_ch);
    REQUIRE(cr2->success);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("channel request failure does not fail the session", "[channel][request]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    REQUIRE_FALSE(client.conn.request_pty(ids.client_ch, {}));
    std::vector<recording_handler::recorded_event> cap;
    transfer_all_capture(client, server, cap);
    const auto* req = find_first<recording_handler::channel_request>(cap);
    REQUIRE(req);
    server.conn.resolve(req->ticket, false);

    transfer_once_capture(server, client, cap);
    const auto* cr = find_first<recording_handler::channel_response>(cap);
    REQUIRE(cr);
    REQUIRE(cr->ref == ids.client_ch);
    REQUIRE_FALSE(cr->success);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("window-change want_reply false needs resolve but sends no SUCCESS", "[channel][request]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    REQUIRE_FALSE(client.conn.request_window_change(ids.client_ch, {}));
    std::vector<recording_handler::recorded_event> cap;
    transfer_all_capture(client, server, cap);
    const auto* req = find_first<recording_handler::channel_request>(cap);
    REQUIRE(req);
    REQUIRE(req->type == "window-change");
    REQUIRE_FALSE(req->want_reply);
    REQUIRE(server.conn.pending_output0().empty());

    server.conn.resolve(req->ticket, true);
    REQUIRE(server.conn.pending_output0().empty());
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("resolving a non-head channel request id is invalid_state", "[channel][request]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    REQUIRE_FALSE(client.conn.request_pty(ids.client_ch, {}));
    REQUIRE_FALSE(client.conn.request_pty(ids.client_ch, {}));
    std::vector<recording_handler::recorded_event> cap;
    transfer_all_capture(client, server, cap);
    const auto reqs = find_all<recording_handler::channel_request>(cap);
    REQUIRE(reqs.size() == 2);

    const auto before = server.conn.pending_output0().size();
    REQUIRE(server.conn.resolve(core::channel_request_ticket{}, true) == code::invalid_state);
    REQUIRE_FALSE(server.conn.failure());
    REQUIRE(server.conn.pending_output0().size() == before);

    REQUIRE_FALSE(server.conn.resolve(reqs[0]->ticket, true));
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("many inbound channel requests are all delivered without stalling feed", "[channel][request]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    for (int i = 0; i < 33; ++i) {
        REQUIRE_FALSE(client.conn.request_env(ids.client_ch, "K", "V"));
    }
    std::vector<recording_handler::recorded_event> cap;
    transfer_all_capture(client, server, cap);
    const auto reqs = find_all<recording_handler::channel_request>(cap);
    REQUIRE(reqs.size() == 33);
    REQUIRE_FALSE(server.conn.failure());
    REQUIRE_FALSE(server.conn.inbound_requests_stalled());
    for (const auto* req : reqs) {
        REQUIRE_FALSE(server.conn.resolve(req->ticket, true));
    }
    (void)ids;
}

TEST_CASE("request_exec payload round-trips", "[channel][request]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    REQUIRE_FALSE(client.conn.request_exec(ids.client_ch, "ls"));
    std::vector<recording_handler::recorded_event> cap;
    transfer_all_capture(client, server, cap);
    const auto* req = find_first<recording_handler::channel_request>(cap);
    REQUIRE(req);
    REQUIRE(req->type == "exec");
    std::string_view command;
    REQUIRE(channels::decode_exec(req->payload, command));
    REQUIRE(command == "ls");
}

TEST_CASE("send_exit_status is want_reply false and decodes", "[channel][request]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    REQUIRE_FALSE(server.conn.send_exit_status(ids.server_ch, 7));
    std::vector<recording_handler::recorded_event> cap;
    transfer_all_capture(server, client, cap);
    const auto* req = find_first<recording_handler::channel_request>(cap);
    REQUIRE(req);
    REQUIRE(req->type == "exit-status");
    REQUIRE_FALSE(req->want_reply);
    std::uint32_t status = 0;
    REQUIRE(channels::decode_exit_status(req->payload, status));
    REQUIRE(status == 7);

    client.conn.resolve(req->ticket, true);
    REQUIRE(client.conn.pending_output0().empty());
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("channel_request after close is invalid_state", "[channel][request]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    REQUIRE_FALSE(client.conn.channel_close(ids.client_ch));
    REQUIRE(client.conn.request_pty(ids.client_ch, {}) == code::invalid_state);
    REQUIRE_FALSE(client.conn.failure());
}

TEST_CASE("x11-req extra round-trips through a session channel", "[channel][request]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    channels::x11_req_spec spec;
    spec.single_connection = true;
    spec.protocol = "MIT-MAGIC-COOKIE-1";
    spec.cookie = "aabbccdd";
    spec.screen = 12;
    REQUIRE_FALSE(client.conn.request_x11(ids.client_ch, spec));
    std::vector<recording_handler::recorded_event> cap;
    transfer_all_capture(client, server, cap);
    const auto* req = find_first<recording_handler::channel_request>(cap);
    REQUIRE(req);
    REQUIRE(req->type == "x11-req");
    REQUIRE(req->want_reply);
    bool single = false;
    std::string_view protocol;
    std::string_view cookie;
    std::uint32_t screen = 0;
    REQUIRE(channels::decode_x11_req(req->payload, single, protocol, cookie, screen));
    REQUIRE(single);
    REQUIRE(protocol == "MIT-MAGIC-COOKIE-1");
    REQUIRE(cookie == "aabbccdd");
    REQUIRE(screen == 12);
    server.conn.resolve(req->ticket, true);

    transfer_once_capture(server, client, cap);
    const auto* cr = find_first<recording_handler::channel_response>(cap);
    REQUIRE(cr);
    REQUIRE(cr->ref == ids.client_ch);
    REQUIRE(cr->success);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("all inbound channel requests are delivered while earlier views stay valid",
          "[channel][request][memory]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    REQUIRE_FALSE(client.conn.request_shell(ids.client_ch));
    std::vector<recording_handler::recorded_event> cap;
    transfer_all_capture(client, server, cap);
    const auto* head = find_first<recording_handler::channel_request>(cap);
    REQUIRE(head);
    REQUIRE(head->type == "shell");
    const std::string head_type = head->type;
    const auto head_ticket = head->ticket;

    for (int i = 0; i < 20; ++i) {
        REQUIRE_FALSE(client.conn.request_env(ids.client_ch, "K", "V"));
    }
    transfer_all_capture(client, server, cap);
    const auto reqs = find_all<recording_handler::channel_request>(cap);
    REQUIRE(reqs.size() >= 21);
    CHECK(head_type == "shell");
    REQUIRE(server.conn.resolve(reqs[1]->ticket, true) == code::invalid_state);
    REQUIRE_FALSE(server.conn.resolve(head_ticket, true));
    (void)ids;
}
