#include <catch2/catch_test_macros.hpp>
#include "handshake_fixture.hpp"
#include "channel_test_helpers.hpp"
#include "legacy_loopback_event.hpp"

#include <yanterm-ssh/channels/requests.hpp>
#include <yanterm-ssh/channels/types.hpp>
#include <yanterm-ssh/wire/types.hpp>
#include <yanterm-ssh/error.hpp>

#include <array>
#include <cstddef>
#include <span>
#include <string_view>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

namespace {

constexpr int k_rounds = 256;

bool feed_until_stalled(core::connection& from, core::connection& to) {
    bool saw = false;
    while (!from.pending_output0().empty()) {
        const auto out = from.pending_output0();
        std::size_t n = 0;
        REQUIRE_FALSE(to.feed(out, n));
        from.consume_output(n);
        if (to.inbound_requests_stalled()) {
            saw = true;
            break;
        }
        REQUIRE(n > 0);
    }
    return saw;
}

void accept_inbound(core::connection& side, bool for_client, bool is_client, const legacy_event& ev) {
    if (is_client == for_client && ev.type == legacy_event_type::channel_open_request) {
        side.resolve(ev.inbound_open, channels::channel_open_verdict::accepted());
    }
}

bool decode_bound_port(std::span<const std::byte> extra, std::uint32_t& port) {
    wire::reader r{extra};
    return r.read_uint32(port) && r.empty();
}

}  // namespace

TEST_CASE("tcpip-forward success carries the bound port", "[channel][global]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    REQUIRE_FALSE(client.conn.request_tcpip_forward("127.0.0.1", 0));
    transfer_all(client, server);

    auto ev = pop_legacy_event(server);
    REQUIRE(ev);
    REQUIRE(ev->type == legacy_event_type::global_request);
    REQUIRE(ev->request_type == "tcpip-forward");
    REQUIRE(ev->want_reply);
    std::string_view addr;
    std::uint32_t port = 99;
    REQUIRE(channels::decode_tcpip_forward(ev->request_payload, addr, port));
    REQUIRE(addr == "127.0.0.1");
    REQUIRE(port == 0);

    wire::writer bound;
    bound.write_uint32(1234);
    server.conn.resolve(ev->global_req, true, bound.data());

    transfer_once(server, client);
    auto resp = pop_legacy_event(client);
    REQUIRE(resp);
    REQUIRE(resp->type == legacy_event_type::global_response);
    REQUIRE(resp->request_success);
    std::uint32_t got = 0;
    REQUIRE(decode_bound_port(resp->request_payload, got));
    REQUIRE(got == 1234);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("global request failure does not fail the session", "[channel][global]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    REQUIRE_FALSE(client.conn.request_tcpip_forward("127.0.0.1", 22));
    transfer_all(client, server);

    auto ev = pop_legacy_event(server);
    REQUIRE(ev);
    REQUIRE(ev->type == legacy_event_type::global_request);
    server.conn.resolve(ev->global_req, false);

    transfer_once(server, client);
    auto resp = pop_legacy_event(client);
    REQUIRE(resp);
    REQUIRE(resp->type == legacy_event_type::global_response);
    REQUIRE_FALSE(resp->request_success);
    REQUIRE(resp->request_payload.empty());
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("pipelined global requests are serial on the server", "[channel][global]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    REQUIRE_FALSE(client.conn.request_tcpip_forward("127.0.0.1", 0));
    REQUIRE_FALSE(client.conn.request_tcpip_forward("127.0.0.1", 1));
    transfer_all(client, server);

    auto ev = pop_legacy_event(server);
    REQUIRE(ev);
    REQUIRE(ev->type == legacy_event_type::global_request);
    std::string_view addr;
    std::uint32_t port = 99;
    REQUIRE(channels::decode_tcpip_forward(ev->request_payload, addr, port));
    REQUIRE(port == 0);

    auto ev2 = pop_legacy_event(server);
    REQUIRE(ev2);
    REQUIRE(ev2->type == legacy_event_type::global_request);
    REQUIRE(channels::decode_tcpip_forward(ev2->request_payload, addr, port));
    REQUIRE(port == 1);

    wire::writer first;
    first.write_uint32(1111);
    server.conn.resolve(ev->global_req, true, first.data());

    wire::writer second;
    second.write_uint32(2222);
    server.conn.resolve(ev2->global_req, true, second.data());

    transfer_all(server, client);
    auto r1 = pop_legacy_event(client);
    REQUIRE(r1);
    REQUIRE(r1->type == legacy_event_type::global_response);
    REQUIRE(r1->request_success);
    std::uint32_t p1 = 0;
    REQUIRE(decode_bound_port(r1->request_payload, p1));
    REQUIRE(p1 == 1111);

    auto r2 = pop_legacy_event(client);
    REQUIRE(r2);
    REQUIRE(r2->type == legacy_event_type::global_response);
    REQUIRE(r2->request_success);
    std::uint32_t p2 = 0;
    REQUIRE(decode_bound_port(r2->request_payload, p2));
    REQUIRE(p2 == 2222);
    REQUIRE(r1->request_payload.size() == 4);
    REQUIRE(p1 == 1111);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("direct-tcpip open extras round-trip", "[channel][global]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    channels::channel_open_spec spec;
    spec.type = channels::channel_type::direct_tcpip;
    spec.host = "example";
    spec.port = 443;
    spec.originator_host = "127.0.0.1";
    spec.originator_port = 9;
    core::channel_ref cid{};
    REQUIRE_FALSE(client.conn.open_channel(spec, nullptr, cid));

    bool opened = false;
    bool accepted = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_open_request) {
                REQUIRE(ev.request_type == "direct-tcpip");
                REQUIRE(ev.tcp_host == "example");
                REQUIRE(ev.tcp_port == 443);
                REQUIRE(ev.originator_host == "127.0.0.1");
                REQUIRE(ev.originator_port == 9);
                server.conn.resolve(ev.inbound_open, channels::channel_open_verdict::accepted());
                accepted = true;
            }
            if (is_client && ev.type == legacy_event_type::channel_opened) {
                REQUIRE(ev.ref == cid);
                opened = true;
            }
        },
        k_rounds));
    REQUIRE(accepted);
    REQUIRE(opened);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("forwarded-tcpip opens after tcpip-forward success", "[channel][global]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    REQUIRE_FALSE(client.conn.request_tcpip_forward("127.0.0.1", 0));
    transfer_all(client, server);
    auto gev = pop_legacy_event(server);
    REQUIRE(gev);
    REQUIRE(gev->type == legacy_event_type::global_request);
    wire::writer bound;
    bound.write_uint32(1234);
    server.conn.resolve(gev->global_req, true, bound.data());
    transfer_once(server, client);
    auto resp = pop_legacy_event(client);
    REQUIRE(resp);
    REQUIRE(resp->type == legacy_event_type::global_response);
    REQUIRE(resp->request_success);

    channels::channel_open_spec spec;
    spec.type = channels::channel_type::forwarded_tcpip;
    spec.host = "127.0.0.1";
    spec.port = 1234;
    spec.originator_host = "10.0.0.1";
    spec.originator_port = 99;
    core::channel_ref sid{};
    REQUIRE_FALSE(server.conn.open_channel(spec, nullptr, sid));

    bool opened = false;
    bool accepted = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (is_client && ev.type == legacy_event_type::channel_open_request) {
                REQUIRE(ev.request_type == "forwarded-tcpip");
                REQUIRE(ev.tcp_host == "127.0.0.1");
                REQUIRE(ev.tcp_port == 1234);
                REQUIRE(ev.originator_host == "10.0.0.1");
                REQUIRE(ev.originator_port == 99);
                client.conn.resolve(ev.inbound_open, channels::channel_open_verdict::accepted());
                accepted = true;
            }
            if (!is_client && ev.type == legacy_event_type::channel_opened) {
                REQUIRE(ev.ref == sid);
                opened = true;
            }
        },
        k_rounds));
    REQUIRE(accepted);
    REQUIRE(opened);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("x11 open extras round-trip", "[channel][global]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    channels::channel_open_spec spec;
    spec.type = channels::channel_type::x11;
    spec.originator_host = "127.0.0.1";
    spec.originator_port = 6010;
    core::channel_ref cid{};
    REQUIRE_FALSE(client.conn.open_channel(spec, nullptr, cid));

    bool opened = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_open_request) {
                REQUIRE(ev.request_type == "x11");
                REQUIRE(ev.originator_host == "127.0.0.1");
                REQUIRE(ev.originator_port == 6010);
                server.conn.resolve(ev.inbound_open, channels::channel_open_verdict::accepted());
            }
            if (is_client && ev.type == legacy_event_type::channel_opened) opened = true;
        },
        k_rounds));
    REQUIRE(opened);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("streamlocal-forward extra round-trips", "[channel][global]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    REQUIRE_FALSE(client.conn.request_streamlocal_forward("/tmp/agent.sock"));
    transfer_all(client, server);

    auto ev = pop_legacy_event(server);
    REQUIRE(ev);
    REQUIRE(ev->type == legacy_event_type::global_request);
    REQUIRE(ev->request_type == "streamlocal-forward@openssh.com");
    REQUIRE(ev->want_reply);
    std::string_view path;
    REQUIRE(channels::decode_streamlocal_forward(ev->request_payload, path));
    REQUIRE(path == "/tmp/agent.sock");
    server.conn.resolve(ev->global_req, true);

    transfer_once(server, client);
    auto resp = pop_legacy_event(client);
    REQUIRE(resp);
    REQUIRE(resp->type == legacy_event_type::global_response);
    REQUIRE(resp->request_success);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("cancel-streamlocal-forward is a want_reply global request", "[channel][global]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    REQUIRE_FALSE(client.conn.cancel_streamlocal_forward("/tmp/agent.sock"));
    transfer_all(client, server);

    auto ev = pop_legacy_event(server);
    REQUIRE(ev);
    REQUIRE(ev->type == legacy_event_type::global_request);
    REQUIRE(ev->request_type == "cancel-streamlocal-forward@openssh.com");
    REQUIRE(ev->want_reply);
    std::string_view path;
    REQUIRE(channels::decode_streamlocal_forward(ev->request_payload, path));
    REQUIRE(path == "/tmp/agent.sock");
    server.conn.resolve(ev->global_req, true);

    transfer_once(server, client);
    auto resp = pop_legacy_event(client);
    REQUIRE(resp);
    REQUIRE(resp->type == legacy_event_type::global_response);
    REQUIRE(resp->request_success);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("direct-streamlocal open extras round-trip", "[channel][global]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    channels::channel_open_spec spec;
    spec.type = channels::channel_type::direct_streamlocal;
    spec.socket_path = "/tmp/s.sock";
    core::channel_ref cid{};
    REQUIRE_FALSE(client.conn.open_channel(spec, nullptr, cid));

    bool opened = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_open_request) {
                REQUIRE(ev.request_type == "direct-streamlocal@openssh.com");
                REQUIRE(ev.socket_path == "/tmp/s.sock");
                server.conn.resolve(ev.inbound_open, channels::channel_open_verdict::accepted());
            }
            if (is_client && ev.type == legacy_event_type::channel_opened) opened = true;
        },
        k_rounds));
    REQUIRE(opened);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("forwarded-streamlocal open extras round-trip", "[channel][global]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    channels::channel_open_spec spec;
    spec.type = channels::channel_type::forwarded_streamlocal;
    spec.socket_path = "/tmp/fwd.sock";
    core::channel_ref cid{};
    REQUIRE_FALSE(client.conn.open_channel(spec, nullptr, cid));

    bool opened = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_open_request) {
                REQUIRE(ev.request_type == "forwarded-streamlocal@openssh.com");
                REQUIRE(ev.socket_path == "/tmp/fwd.sock");
                server.conn.resolve(ev.inbound_open, channels::channel_open_verdict::accepted());
            }
            if (is_client && ev.type == legacy_event_type::channel_opened) opened = true;
        },
        k_rounds));
    REQUIRE(opened);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("unknown channel open type is rejected as unknown_channel_type", "[channel][global]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    channels::channel_open_spec spec;
    spec.type = channels::channel_type::unknown;
    spec.extra_type = "foo@bar";
    core::channel_ref cid{};
    REQUIRE_FALSE(client.conn.open_channel(spec, nullptr, cid));

    bool failed = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_open_request) {
                REQUIRE(ev.request_type == "foo@bar");
                REQUIRE(channels::parse_type(ev.request_type) == channels::channel_type::unknown);
                server.conn.resolve(ev.inbound_open, channels::channel_open_verdict::rejected(
                                          channels::channel_open_reason::unknown_channel_type, "no"));
            }
            if (is_client && ev.type == legacy_event_type::channel_open_failed) {
                REQUIRE(ev.ref == cid);
                REQUIRE(ev.open_reason == channels::channel_open_reason::unknown_channel_type);
                failed = true;
            }
        },
        k_rounds));
    REQUIRE(failed);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("both EOF then both CLOSE frees the slot", "[channel][global]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    core::config cfg;
    cfg.max_channels = 1;
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    REQUIRE_FALSE(client.conn.channel_eof(ids.client_ch));
    REQUIRE_FALSE(server.conn.channel_eof(ids.server_ch));
    bool c_eof = false;
    bool s_eof = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (is_client && ev.type == legacy_event_type::channel_eof) c_eof = true;
            if (!is_client && ev.type == legacy_event_type::channel_eof) s_eof = true;
        },
        k_rounds));
    REQUIRE(c_eof);
    REQUIRE(s_eof);

    REQUIRE_FALSE(client.conn.channel_close(ids.client_ch));
    REQUIRE_FALSE(server.conn.channel_close(ids.server_ch));
    bool c_closed = false;
    bool s_closed = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (is_client && ev.type == legacy_event_type::channel_closed) c_closed = true;
            if (!is_client && ev.type == legacy_event_type::channel_closed) s_closed = true;
        },
        k_rounds));
    REQUIRE(c_closed);
    REQUIRE(s_closed);

    core::channel_ref cid2{};
    REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, cid2));
    bool opened = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            accept_inbound(server, false, is_client, ev);
            if (is_client && ev.type == legacy_event_type::channel_opened) opened = true;
        },
        k_rounds));
    REQUIRE(opened);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("CLOSE without EOF does not synthesize channel_eof and frees the slot",
          "[channel][global]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    core::config cfg;
    cfg.max_channels = 1;
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    REQUIRE_FALSE(client.conn.channel_close(ids.client_ch));
    bool saw_eof = false;
    bool saw_closed = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_eof) saw_eof = true;
            if (!is_client && ev.type == legacy_event_type::channel_closed) saw_closed = true;
        },
        k_rounds));
    REQUIRE_FALSE(saw_eof);
    REQUIRE(saw_closed);

    core::channel_ref cid2{};
    REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, cid2));
    bool opened = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            accept_inbound(server, false, is_client, ev);
            if (is_client && ev.type == legacy_event_type::channel_opened) opened = true;
        },
        k_rounds));
    REQUIRE(opened);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("peer CLOSE without unread data frees the slot via C9", "[channel][global]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    core::config cfg;
    cfg.max_channels = 1;
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    REQUIRE_FALSE(client.conn.channel_close(ids.client_ch));
    bool closed = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_closed) closed = true;
        },
        k_rounds));
    REQUIRE(closed);

    core::channel_ref cid2{};
    REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, cid2));
    bool opened = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            accept_inbound(server, false, is_client, ev);
            if (is_client && ev.type == legacy_event_type::channel_opened) opened = true;
        },
        k_rounds));
    REQUIRE(opened);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("peer CLOSE keeps unread data until channel_read empties the slot", "[channel][global]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    core::config cfg;
    cfg.max_channels = 1;
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    const auto keep = std::as_bytes(std::span{"keepme", 6});
    std::span<const std::byte> frags[] = {keep};
    std::size_t accepted = 0;
    REQUIRE_FALSE(client.conn.channel_write(ids.client_ch, frags, accepted));
    REQUIRE(accepted == 6);
    REQUIRE_FALSE(client.conn.channel_close(ids.client_ch));

    bool readable = false;
    bool closed = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_readable) readable = true;
            if (!is_client && ev.type == legacy_event_type::channel_closed) closed = true;
        },
        k_rounds));
    REQUIRE(readable);
    REQUIRE(closed);

    core::channel_ref cid2{};
    REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, cid2));
    int open_reqs = 0;
    bool failed = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_open_request) ++open_reqs;
            if (is_client && ev.type == legacy_event_type::channel_open_failed) {
                REQUIRE(ev.open_reason == channels::channel_open_reason::resource_shortage);
                failed = true;
            }
        },
        k_rounds));
    REQUIRE(open_reqs == 0);
    REQUIRE(failed);

    std::array<std::byte, 16> buf{};
    const auto n = server.conn.channel_read(ids.server_ch, 0, buf);
    REQUIRE(n == 6);
    REQUIRE(std::string_view{reinterpret_cast<const char*>(buf.data()), 6} == "keepme");

    core::channel_ref cid3{};
    REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, cid3));
    bool opened = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            accept_inbound(server, false, is_client, ev);
            if (is_client && ev.type == legacy_event_type::channel_opened) opened = true;
        },
        k_rounds));
    REQUIRE(opened);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("simultaneous CLOSE delivers channel_closed and reuses the slot", "[channel][global]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    core::config cfg;
    cfg.max_channels = 1;
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    REQUIRE_FALSE(client.conn.channel_close(ids.client_ch));
    REQUIRE_FALSE(server.conn.channel_close(ids.server_ch));
    bool c_closed = false;
    bool s_closed = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (is_client && ev.type == legacy_event_type::channel_closed) c_closed = true;
            if (!is_client && ev.type == legacy_event_type::channel_closed) s_closed = true;
        },
        k_rounds));
    REQUIRE(c_closed);
    REQUIRE(s_closed);

    core::channel_ref cid2{};
    REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, cid2));
    bool opened = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            accept_inbound(server, false, is_client, ev);
            if (is_client && ev.type == legacy_event_type::channel_opened) opened = true;
        },
        k_rounds));
    REQUIRE(opened);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("keepalive@openssh.com global request succeeds", "[channel][global]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    REQUIRE_FALSE(client.conn.send_global_request("keepalive@openssh.com", {}, true));
    transfer_all(client, server);

    auto ev = pop_legacy_event(server);
    REQUIRE(ev);
    REQUIRE(ev->type == legacy_event_type::global_request);
    REQUIRE(ev->request_type == "keepalive@openssh.com");
    REQUIRE(ev->want_reply);
    REQUIRE(ev->request_payload.empty());
    server.conn.resolve(ev->global_req, true);

    transfer_once(server, client);
    auto resp = pop_legacy_event(client);
    REQUIRE(resp);
    REQUIRE(resp->type == legacy_event_type::global_response);
    REQUIRE(resp->request_success);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("cancel-tcpip-forward is a want_reply global request", "[channel][global]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    REQUIRE_FALSE(client.conn.cancel_tcpip_forward("127.0.0.1", 1234));
    transfer_all(client, server);

    auto ev = pop_legacy_event(server);
    REQUIRE(ev);
    REQUIRE(ev->type == legacy_event_type::global_request);
    REQUIRE(ev->request_type == "cancel-tcpip-forward");
    REQUIRE(ev->want_reply);
    std::string_view addr;
    std::uint32_t port = 0;
    REQUIRE(channels::decode_tcpip_forward(ev->request_payload, addr, port));
    REQUIRE(addr == "127.0.0.1");
    REQUIRE(port == 1234);
    server.conn.resolve(ev->global_req, true);

    transfer_once(server, client);
    auto resp = pop_legacy_event(client);
    REQUIRE(resp);
    REQUIRE(resp->type == legacy_event_type::global_response);
    REQUIRE(resp->request_success);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("many inbound global requests are delivered without stalling feed", "[channel][global]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    REQUIRE_FALSE(client.conn.request_tcpip_forward("127.0.0.1", 0));
    REQUIRE_FALSE(client.conn.request_tcpip_forward("127.0.0.1", 1));
    std::vector<recording_handler::recorded_event> cap;
    transfer_all_capture(client, server, cap);
    std::size_t globals = 0;
    for (const auto& ev : cap) {
        if (std::holds_alternative<recording_handler::global_request>(ev)) ++globals;
    }
    REQUIRE(globals == 2);
    REQUIRE_FALSE(server.conn.inbound_requests_stalled());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("inbound global requests are not stalled by core limits", "[channel][global]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    REQUIRE_FALSE(client.conn.request_tcpip_forward("127.0.0.1", 0));
    std::vector<recording_handler::recorded_event> cap;
    transfer_all_capture(client, server, cap);
    REQUIRE_FALSE(server.conn.inbound_requests_stalled());
    REQUIRE(std::any_of(cap.begin(), cap.end(), [](const auto& ev) {
        return std::holds_alternative<recording_handler::global_request>(ev);
    }));
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("want_reply false global request needs resolve but sends no SUCCESS",
          "[channel][global]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    REQUIRE_FALSE(client.conn.send_global_request("tcpip-forward", {}, false));
    transfer_all(client, server);

    auto ev = pop_legacy_event(server);
    REQUIRE(ev);
    REQUIRE(ev->type == legacy_event_type::global_request);
    REQUIRE_FALSE(ev->want_reply);
    REQUIRE(server.conn.pending_output0().empty());

    server.conn.resolve(ev->global_req, true);
    REQUIRE(server.conn.pending_output0().empty());
    REQUIRE_FALSE(pop_legacy_event(client));
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("an emitted global request keeps its views while more requests queue behind it",
          "[global][request][memory]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    REQUIRE_FALSE(client.conn.send_global_request("keepalive@openssh.com", {}, true));
    transfer_all(client, server);
    auto head = peek_legacy_event(server);
    REQUIRE(head);
    REQUIRE(head->type == legacy_event_type::global_request);
    REQUIRE(head->request_type == "keepalive@openssh.com");
    const auto head_ticket = head->global_req;
    const std::string head_type{head->request_type};

    const auto payload = std::as_bytes(std::span{"abc", 3});
    for (int i = 0; i < 20; ++i) {
        REQUIRE_FALSE(client.conn.send_global_request("x@example.com", payload, true));
    }
    transfer_all(client, server);

    CHECK(head_type == "keepalive@openssh.com");
    server.conn.resolve(head_ticket, true);
    (void)pop_legacy_event(server);
    auto next = pop_legacy_event(server);
    REQUIRE(next);
    CHECK(next->request_type == "x@example.com");
    REQUIRE(next->request_payload.size() == 3);
    CHECK(next->request_payload[0] == std::byte{'a'});
    CHECK(next->request_payload[1] == std::byte{'b'});
    CHECK(next->request_payload[2] == std::byte{'c'});
}
