#include <catch2/catch_test_macros.hpp>
#include "handshake_fixture.hpp"
#include "scripted_peer.hpp"

#include <yanterm-ssh/channels/requests.hpp>
#include <yanterm-ssh/channels/types.hpp>
#include <yanterm-ssh/wire/detail/messages.hpp>
#include <yanterm-ssh/wire/types.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/detail/error.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

namespace {

constexpr int k_rounds = 256;

std::vector<std::byte> copied(std::span<const std::byte> s) {
    return {s.begin(), s.end()};
}

void accept_inbound(core::connection& side, bool for_client, bool is_client, const legacy_event& ev) {
    if (is_client == for_client && ev.type == legacy_event_type::channel_open_request) {
        side.resolve(ev.inbound_open, channels::channel_open_verdict::accepted());
    }
}

template <class Ev>
bool only_event(const recording_handler& h) {
    return h.events.size() == 1 && std::holds_alternative<Ev>(h.events[0]);
}

}  // namespace

TEST_CASE("session open both directions", "[channel][open]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    core::channel_ref cid{};
    REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, cid));

    bool client_opened = false;
    core::channel_ref client_ch{};
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_open_request) {
                REQUIRE(ev.request_type == channels::type_session);
                REQUIRE(ev.request_payload.empty());
            }
            accept_inbound(server, false, is_client, ev);
            if (is_client && ev.type == legacy_event_type::channel_opened) {
                REQUIRE(ev.ref == cid);
                REQUIRE(ev.window == 2u * 1024u * 1024u);
                REQUIRE(ev.max_packet == 32768);
                client_ch = ev.ref;
                client_opened = true;
            }
        },
        k_rounds));
    REQUIRE(client_opened);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());

    core::channel_ref sid{};
    REQUIRE_FALSE(server.conn.open_channel(channels::channel_open_spec{}, nullptr, sid));
    bool server_opened = false;
    channels::channel_id server_local = 0;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (is_client && ev.type == legacy_event_type::channel_open_request) {
                REQUIRE(ev.request_type == channels::type_session);
                REQUIRE(ev.request_payload.empty());
            }
            accept_inbound(client, true, is_client, ev);
            if (!is_client && ev.type == legacy_event_type::channel_opened) {
                REQUIRE(ev.ref == sid);
                REQUIRE(ev.window == 2u * 1024u * 1024u);
                REQUIRE(ev.max_packet == 32768);
                server_local = ev.ch;
                server_opened = true;
            }
        },
        k_rounds));
    REQUIRE(server_opened);
    REQUIRE(server_local != client_ch.index);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("open failure does not fail the session", "[channel][open]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    core::channel_ref cid{};
    REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, cid));

    bool failed = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_open_request) {
                server.conn.resolve(ev.inbound_open, channels::channel_open_verdict::rejected(
                                          channels::channel_open_reason::unknown_channel_type, "no"));
            }
            if (is_client && ev.type == legacy_event_type::channel_open_failed) {
                REQUIRE(ev.ref == cid);
                REQUIRE(ev.open_reason == channels::channel_open_reason::unknown_channel_type);
                REQUIRE(ev.text == "no");
                failed = true;
            }
        },
        k_rounds));
    REQUIRE(failed);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("concurrent opens get distinct local ids", "[channel][open]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    core::channel_ref a{};
    core::channel_ref b{};
    REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, a));
    REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, b));

    std::vector<channels::channel_id> opened;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            accept_inbound(server, false, is_client, ev);
            if (is_client && ev.type == legacy_event_type::channel_opened) {
                opened.push_back(ev.ch);
            }
        },
        k_rounds));
    REQUIRE(opened.size() == 2);
    REQUIRE(opened[0] != opened[1]);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("abandon_open suppresses channel_opened and reuses the slot", "[channel][open]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    core::config cfg;
    cfg.max_channels = 1;
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);

    core::channel_ref cid{};
    REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, cid));
    REQUIRE_FALSE(client.conn.abandon_open(cid));

    bool client_opened = false;
    bool server_closed = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            accept_inbound(server, false, is_client, ev);
            if (is_client && ev.type == legacy_event_type::channel_opened) client_opened = true;
            if (!is_client && ev.type == legacy_event_type::channel_closed) server_closed = true;
        },
        k_rounds));
    REQUIRE_FALSE(client_opened);
    REQUIRE(server_closed);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());

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

TEST_CASE("slot reuse after close does not hit too_many_channels", "[channel][open]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    core::config cfg;
    cfg.max_channels = 2;
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);

    for (int i = 0; i < 8; ++i) {
        core::channel_ref cid{};
        REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, cid));
        core::channel_ref cch{};
        core::channel_ref sch{};
        REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
                if (!is_client && ev.type == legacy_event_type::channel_open_request) {
                    sch = ev.ref;
                    server.conn.resolve(ev.inbound_open, channels::channel_open_verdict::accepted());
                }
                if (is_client && ev.type == legacy_event_type::channel_opened) cch = ev.ref;
            },
            k_rounds));
        REQUIRE_FALSE(client.conn.channel_close(cch));
        REQUIRE_FALSE(server.conn.channel_close(sch));
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
        REQUIRE_FALSE(client.conn.failure());
        REQUIRE_FALSE(server.conn.failure());
    }
}

TEST_CASE("freed channel ids are reused in FIFO order", "[channel][open]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    core::config cfg;
    cfg.max_channels = 4;
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);

    auto open_one = [&](core::channel_ref& cch, core::channel_ref& sch) {
        core::channel_ref cid{};
        REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, cid));
        REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
                if (!is_client && ev.type == legacy_event_type::channel_open_request) {
                    sch = ev.ref;
                    server.conn.resolve(ev.inbound_open, channels::channel_open_verdict::accepted());
                }
                if (is_client && ev.type == legacy_event_type::channel_opened) cch = ev.ref;
            },
            k_rounds));
    };
    auto close_one = [&](core::channel_ref cch, core::channel_ref sch) {
        REQUIRE_FALSE(client.conn.channel_close(cch));
        REQUIRE_FALSE(server.conn.channel_close(sch));
        REQUIRE(run_loopback_legacy(client, server, [&](bool, const legacy_event&) {}, k_rounds));
    };

    core::channel_ref c0{}, s0{}, c1{}, s1{};
    open_one(c0, s0);
    open_one(c1, s1);
    REQUIRE(c0.index != c1.index);
    close_one(c0, s0);
    close_one(c1, s1);

    core::channel_ref c2{}, s2{};
    open_one(c2, s2);
    REQUIRE(c2.index == c0.index);
}

TEST_CASE("too_many_channels is not a session latch", "[channel][open]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    core::config one;
    one.max_channels = 1;
    auto client = make_client(p, one);
    auto server = make_server(p, one);
    bring_up_authed(client, server, hm);

    core::channel_ref id1{};
    REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, id1));
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) { accept_inbound(server, false, is_client, ev); },
        k_rounds));
    core::channel_ref id2{};
    REQUIRE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, id2) == code::too_many_channels);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());

    core::config two;
    two.max_channels = 2;
    core::config s1;
    s1.max_channels = 1;
    auto c2 = make_client(p, two);
    auto srv2 = make_server(p, s1);
    bring_up_authed(c2, srv2, hm);

    core::channel_ref a{};
    REQUIRE_FALSE(c2.conn.open_channel(channels::channel_open_spec{}, nullptr, a));
    int open_reqs = 0;
    REQUIRE(run_loopback_legacy(c2, srv2,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_open_request) {
                ++open_reqs;
                srv2.conn.resolve(ev.inbound_open, channels::channel_open_verdict::accepted());
            }
        },
        k_rounds));
    REQUIRE(open_reqs == 1);

    core::channel_ref b{};
    REQUIRE_FALSE(c2.conn.open_channel(channels::channel_open_spec{}, nullptr, b));
    int open_reqs2 = 0;
    bool failed = false;
    REQUIRE(run_loopback_legacy(c2, srv2,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_open_request) ++open_reqs2;
            if (is_client && ev.type == legacy_event_type::channel_open_failed) {
                REQUIRE(ev.open_reason == channels::channel_open_reason::resource_shortage);
                failed = true;
            }
        },
        k_rounds));
    REQUIRE(open_reqs2 == 0);
    REQUIRE(failed);
    REQUIRE_FALSE(c2.conn.failure());
    REQUIRE_FALSE(srv2.conn.failure());
}

TEST_CASE("open_channel before auth is invalid_state", "[channel][open]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    core::channel_ref id{};
    REQUIRE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, id) == code::invalid_state);
    REQUIRE_FALSE(client.conn.failure());
}

TEST_CASE("EOF then CLOSE delivers eof before closed", "[channel][open]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    core::channel_ref cid{};
    REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, cid));
    core::channel_ref cch{};
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            accept_inbound(server, false, is_client, ev);
            if (is_client && ev.type == legacy_event_type::channel_opened) cch = ev.ref;
        },
        k_rounds));

    REQUIRE_FALSE(client.conn.channel_eof(cch));
    REQUIRE_FALSE(client.conn.channel_close(cch));
    std::vector<legacy_event_type> server_seq;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client
                && (ev.type == legacy_event_type::channel_eof
                    || ev.type == legacy_event_type::channel_closed)) {
                server_seq.push_back(ev.type);
            }
        },
        k_rounds));
    REQUIRE(server_seq.size() >= 2);
    REQUIRE(server_seq[0] == legacy_event_type::channel_eof);
    REQUIRE(server_seq[1] == legacy_event_type::channel_closed);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("CLOSE without EOF does not synthesize channel_eof", "[channel][open]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    core::channel_ref cid{};
    REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, cid));
    core::channel_ref cch{};
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            accept_inbound(server, false, is_client, ev);
            if (is_client && ev.type == legacy_event_type::channel_opened) cch = ev.ref;
        },
        k_rounds));

    REQUIRE_FALSE(client.conn.channel_close(cch));
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
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("peer CLOSE keeps unread data until channel_read", "[channel][open]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    core::config cfg;
    cfg.max_channels = 1;
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);

    core::channel_ref cid{};
    REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, cid));
    core::channel_ref cch{};
    core::channel_ref sch{};
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_open_request) {
                sch = ev.ref;
                server.conn.resolve(ev.inbound_open, channels::channel_open_verdict::accepted());
            }
            if (is_client && ev.type == legacy_event_type::channel_opened) cch = ev.ref;
        },
        k_rounds));

    const auto keep = std::as_bytes(std::span{"keepme", 6});
    std::span<const std::byte> frags[] = {keep};
    std::size_t accepted = 0;
    REQUIRE_FALSE(client.conn.channel_write(cch, frags, accepted));
    REQUIRE(accepted == 6);
    REQUIRE_FALSE(client.conn.channel_close(cch));

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
    const auto n = server.conn.channel_read(sch, 0, buf);
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

TEST_CASE("app channel_close after peer CLOSE does not send a second CLOSE", "[channel][open]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    core::config cfg;
    cfg.max_channels = 1;
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);

    core::channel_ref cid{};
    REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, cid));
    core::channel_ref cch{};
    core::channel_ref sch{};
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_open_request) {
                sch = ev.ref;
                server.conn.resolve(ev.inbound_open, channels::channel_open_verdict::accepted());
            }
            if (is_client && ev.type == legacy_event_type::channel_opened) cch = ev.ref;
        },
        k_rounds));

    const auto keep = std::as_bytes(std::span{"keepme", 6});
    std::span<const std::byte> frags[] = {keep};
    std::size_t accepted = 0;
    REQUIRE_FALSE(client.conn.channel_write(cch, frags, accepted));
    REQUIRE(accepted == 6);
    REQUIRE_FALSE(client.conn.channel_close(cch));
    REQUIRE(run_loopback_legacy(client, server, [&](bool, const legacy_event&) {}, k_rounds));

    REQUIRE_FALSE(server.conn.channel_close(sch));
    REQUIRE(run_loopback_legacy(client, server, [&](bool, const legacy_event&) {}, k_rounds));
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());

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

TEST_CASE("inbound extended data with unknown type is discarded", "[channel][open]") {
    auto cfg = scripted_peer::sut_config();
    cfg.initial_window = 4;
    cfg.max_channels = 4;
    peer_session s{core::role::client, cfg};
    s.authenticate();
    const auto ch = open_confirmed(s, 100, 32);

    wire::detail::channel_extended_data ext;
    ext.recipient = ch.sut_id;
    ext.data_type = 2;
    ext.data = std::as_bytes(std::span{"x", 1});
    s.peer.send_msg(ext);
    REQUIRE_FALSE(s.peer.exchange(s.sut));
    REQUIRE(s.sut.handler.events.empty());
    const auto adj_bytes = s.peer.take(wire::msg::channel_window_adjust);
    REQUIRE(adj_bytes);
    wire::reader ar{*adj_bytes};
    wire::detail::channel_window_adjust adj;
    REQUIRE(adj.decode(ar));
    REQUIRE(adj.recipient == ch.peer_id);
    REQUIRE(adj.bytes == 1);

    wire::detail::channel_data data;
    data.recipient = ch.sut_id;
    data.data = std::as_bytes(std::span{"abcd", 4});
    s.peer.send_msg(data);
    REQUIRE_FALSE(s.peer.exchange(s.sut));
    REQUIRE(only_event<recording_handler::channel_readable>(s.sut.handler));
}

TEST_CASE("OPEN_FAILURE after confirmation is unexpected_message", "[channel][open]") {
    peer_session s{core::role::client};
    s.authenticate();
    const auto ch = open_confirmed(s, 100, 32);

    wire::detail::channel_open_failure fail;
    fail.recipient = ch.sut_id;
    fail.reason = static_cast<std::uint32_t>(channels::channel_open_reason::connect_failed);
    fail.description = "late";
    s.peer.send_msg(fail);
    REQUIRE(s.peer.deliver(s.sut) == code::unexpected_message);
    REQUIRE(s.sut.handler.events.empty());
}

TEST_CASE("second OPEN_CONFIRMATION is unexpected_message", "[channel][open]") {
    peer_session s{core::role::client};
    s.authenticate();
    const auto ch = open_confirmed(s, 100, 32);

    wire::detail::channel_open_confirmation again;
    again.recipient = ch.sut_id;
    again.sender = 10;
    again.window = 200;
    again.max_packet = 64;
    s.peer.send_msg(again);
    REQUIRE(s.peer.deliver(s.sut) == code::unexpected_message);
    REQUIRE(s.sut.handler.events.empty());
}

TEST_CASE("two concurrent open failures keep distinct descriptions", "[channel][open]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    core::channel_ref a{};
    core::channel_ref b{};
    REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, a));
    REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, b));

    int rejects = 0;
    std::string text_a;
    std::string text_b;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_open_request) {
                const auto desc = (rejects == 0) ? "fail-a" : "fail-b";
                ++rejects;
                server.conn.resolve(ev.inbound_open, channels::channel_open_verdict::rejected(
                                          channels::channel_open_reason::connect_failed, desc));
            }
            if (is_client && ev.type == legacy_event_type::channel_open_failed) {
                if (ev.ref == a) text_a = std::string{ev.text};
                if (ev.ref == b) text_b = std::string{ev.text};
            }
        },
        k_rounds));
    REQUIRE(rejects == 2);
    REQUIRE(text_a == "fail-a");
    REQUIRE(text_b == "fail-b");
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("second resolve of an accepted inbound open is invalid_state", "[channel][open]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    core::channel_ref cid{};
    REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, cid));
    core::open_ticket inbound{};
    bool opened = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_open_request) {
                inbound = ev.inbound_open;
                server.conn.resolve(ev.inbound_open, channels::channel_open_verdict::accepted());
            }
            if (is_client && ev.type == legacy_event_type::channel_opened) opened = true;
        },
        k_rounds));
    REQUIRE(opened);
    REQUIRE(inbound != core::open_ticket{});
    REQUIRE_FALSE(server.conn.failure());

    const auto before = server.conn.pending_output0().size();
    REQUIRE(server.conn.resolve(inbound, channels::channel_open_verdict::accepted()) == code::invalid_state);
    REQUIRE_FALSE(server.conn.failure());
    REQUIRE(server.conn.pending_output0().size() == before);
}

TEST_CASE("abandon_open after confirmation is invalid_state", "[channel][open]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    core::channel_ref cid{};
    REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, cid));
    core::channel_ref cch{};
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            accept_inbound(server, false, is_client, ev);
            if (is_client && ev.type == legacy_event_type::channel_opened) cch = ev.ref;
        },
        k_rounds));
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());

    REQUIRE(client.conn.abandon_open(cid) == code::invalid_state);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(client.conn.channel_close(cch));
    bool closed = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_closed) closed = true;
        },
        k_rounds));
    REQUIRE(closed);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("unknown CHANNEL_OPEN extra is inbound request_payload", "[channel][open]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    wire::writer extra_w;
    extra_w.write_string("raw");
    extra_w.write_uint32(42);
    const auto extra = extra_w.take();

    channels::channel_open_spec spec;
    spec.type = channels::channel_type::unknown;
    spec.extra_type = "foo@ex";
    spec.extra = extra;

    core::channel_ref cid{};
    REQUIRE_FALSE(client.conn.open_channel(spec, nullptr, cid));

    bool opened = false;
    bool saw_open = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_open_request) {
                REQUIRE(ev.request_type == "foo@ex");
                REQUIRE(copied(ev.request_payload) == extra);
                REQUIRE(ev.ref.seq != 0);
                server.conn.resolve(ev.inbound_open, channels::channel_open_verdict::accepted());
                saw_open = true;
            }
            if (is_client && ev.type == legacy_event_type::channel_opened) {
                REQUIRE(ev.ref == cid);
                opened = true;
            }
        },
        k_rounds));
    REQUIRE(saw_open);
    REQUIRE(opened);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("session CHANNEL_OPEN extra is inbound request_payload", "[channel][open]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    wire::writer extra_w;
    extra_w.write_string("sess");
    extra_w.write_uint32(7);
    const auto extra = extra_w.take();

    channels::channel_open_spec spec;
    spec.type = channels::channel_type::session;
    spec.extra = extra;

    core::channel_ref cid{};
    REQUIRE_FALSE(client.conn.open_channel(spec, nullptr, cid));

    bool opened = false;
    bool saw_open = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_open_request) {
                REQUIRE(ev.request_type == channels::type_session);
                REQUIRE(copied(ev.request_payload) == extra);
                server.conn.resolve(ev.inbound_open, channels::channel_open_verdict::accepted());
                saw_open = true;
            }
            if (is_client && ev.type == legacy_event_type::channel_opened) opened = true;
        },
        k_rounds));
    REQUIRE(saw_open);
    REQUIRE(opened);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("direct-tcpip CHANNEL_OPEN ignores extra", "[channel][open]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    const std::array<std::byte, 4> junk{std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE},
                                        std::byte{0xEF}};

    channels::channel_open_spec spec;
    spec.type = channels::channel_type::direct_tcpip;
    spec.host = "example";
    spec.port = 443;
    spec.originator_host = "127.0.0.1";
    spec.originator_port = 9;
    spec.extra = junk;

    wire::writer encoded;
    channels::encode_direct_tcpip(encoded, spec.host, spec.port, spec.originator_host,
                            spec.originator_port);
    const auto want = encoded.take();

    core::channel_ref cid{};
    REQUIRE_FALSE(client.conn.open_channel(spec, nullptr, cid));

    bool opened = false;
    bool saw_open = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_open_request) {
                REQUIRE(ev.request_type == channels::type_direct_tcpip);
                REQUIRE(ev.tcp_host == "example");
                REQUIRE(ev.tcp_port == 443);
                REQUIRE(ev.originator_host == "127.0.0.1");
                REQUIRE(ev.originator_port == 9);
                const auto got = copied(ev.request_payload);
                REQUIRE(got == want);
                REQUIRE(got != copied(junk));
                server.conn.resolve(ev.inbound_open, channels::channel_open_verdict::accepted());
                saw_open = true;
            }
            if (is_client && ev.type == legacy_event_type::channel_opened) {
                REQUIRE(ev.ref == cid);
                opened = true;
            }
        },
        k_rounds));
    REQUIRE(saw_open);
    REQUIRE(opened);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("inbound direct-tcpip request_payload is encoded four fields", "[channel][open]") {
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

    wire::writer encoded;
    channels::encode_direct_tcpip(encoded, spec.host, spec.port, spec.originator_host,
                            spec.originator_port);
    const auto want = encoded.take();

    core::channel_ref cid{};
    REQUIRE_FALSE(client.conn.open_channel(spec, nullptr, cid));

    bool opened = false;
    bool saw_open = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_open_request) {
                REQUIRE(ev.request_type == channels::type_direct_tcpip);
                REQUIRE(ev.tcp_host == "example");
                REQUIRE(ev.tcp_port == 443);
                REQUIRE(ev.originator_host == "127.0.0.1");
                REQUIRE(ev.originator_port == 9);
                REQUIRE(copied(ev.request_payload) == want);
                server.conn.resolve(ev.inbound_open, channels::channel_open_verdict::accepted());
                saw_open = true;
            }
            if (is_client && ev.type == legacy_event_type::channel_opened) {
                REQUIRE(ev.ref == cid);
                opened = true;
            }
        },
        k_rounds));
    REQUIRE(saw_open);
    REQUIRE(opened);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

namespace {

struct stray_msg {
    const char* name;
    std::vector<std::byte> (*encode)(std::uint32_t recipient);
};

std::vector<std::byte> enc_data(std::uint32_t r) {
    wire::detail::channel_data m;
    m.recipient = r;
    m.data = std::as_bytes(std::span{"x", 1});
    wire::writer w;
    m.encode(w);
    return w.take();
}
std::vector<std::byte> enc_adjust(std::uint32_t r) {
    wire::detail::channel_window_adjust m;
    m.recipient = r;
    m.bytes = 5;
    wire::writer w;
    m.encode(w);
    return w.take();
}
std::vector<std::byte> enc_eof(std::uint32_t r) {
    wire::detail::channel_eof_msg m;
    m.recipient = r;
    wire::writer w;
    m.encode(w);
    return w.take();
}
std::vector<std::byte> enc_close(std::uint32_t r) {
    wire::detail::channel_close_msg m;
    m.recipient = r;
    wire::writer w;
    m.encode(w);
    return w.take();
}
std::vector<std::byte> enc_request(std::uint32_t r) {
    wire::detail::channel_request m;
    m.recipient = r;
    m.type = "env";
    m.want_reply = false;
    wire::writer w;
    m.encode(w);
    return w.take();
}
std::vector<std::byte> enc_success(std::uint32_t r) {
    wire::detail::channel_success_msg m;
    m.recipient = r;
    wire::writer w;
    m.encode(w);
    return w.take();
}

const stray_msg stray_msgs[] = {
    {"DATA", enc_data},           {"WINDOW_ADJUST", enc_adjust}, {"EOF", enc_eof},
    {"CLOSE", enc_close},         {"REQUEST", enc_request},      {"SUCCESS", enc_success},
};

}  // namespace

TEST_CASE("messages on an unconfirmed outbound open are unexpected_message", "[channel][open]") {
    for (const auto& m : stray_msgs) {
        DYNAMIC_SECTION(m.name) {
            peer_session s{core::role::client};
            s.authenticate();
            channels::channel_open_spec spec{};
            core::channel_ref ref{};
            REQUIRE_FALSE(s.sut.conn.open_channel(spec, nullptr, ref));
            REQUIRE_FALSE(s.peer.exchange(s.sut));
            REQUIRE(s.peer.take(wire::msg::channel_open));
            s.sut.handler.events.clear();
            s.peer.send(m.encode(ref.index));
            REQUIRE(s.peer.deliver(s.sut) == code::unexpected_message);
            REQUIRE(s.sut.handler.events.empty());
        }
    }
}

TEST_CASE("messages on an inbound open awaiting a verdict are unexpected_message", "[channel][open]") {
    for (const auto& m : stray_msgs) {
        DYNAMIC_SECTION(m.name) {
            peer_session s{core::role::server};
            s.authenticate();
            wire::detail::channel_open open;
            open.type = "session";
            open.sender = 9;
            open.window = 100;
            open.max_packet = 32;
            s.peer.send_msg(open);
            REQUIRE_FALSE(s.peer.exchange(s.sut));
            REQUIRE(s.sut.handler.events.size() == 1);
            const auto* req =
                std::get_if<recording_handler::channel_open_request>(&s.sut.handler.events[0]);
            REQUIRE(req != nullptr);
            s.sut.handler.events.clear();
            s.peer.send(m.encode(req->ref.index));
            REQUIRE(s.peer.deliver(s.sut) == code::unexpected_message);
            REQUIRE(s.sut.handler.events.empty());
        }
    }
}
