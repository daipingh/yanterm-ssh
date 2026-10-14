#include <catch2/catch_test_macros.hpp>
#include "drive.hpp"
#include "handshake_fixture.hpp"
#include "scripted_peer.hpp"

#include <yanterm-ssh/channels/types.hpp>
#include <yanterm-ssh/wire/detail/messages.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/detail/error.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

namespace {

constexpr int k_rounds = 256;

struct session_ids {
    core::channel_ref client_ch{};
    core::channel_ref server_ch{};
};

core::config data_cfg() {
    core::config cfg;
    cfg.initial_window = 32;
    cfg.max_channel_packet = 16;
    return cfg;
}

constexpr std::string_view k_aes256_gcm = "aes256-gcm@openssh.com";

core::config gcm_cfg(std::uint32_t window, std::uint32_t max_packet) {
    core::config cfg;
    cfg.initial_window = window;
    cfg.max_channel_packet = max_packet;
    cfg.preferred_cipher = k_aes256_gcm;
    return cfg;
}

std::uint32_t load_be32(std::span<const std::byte> in) {
    return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[0])) << 24)
         | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[1])) << 16)
         | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[2])) << 8)
         |  static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[3]));
}

// AES-GCM packet_length is AAD (unencrypted). Do not use pending_output iovec
// count: adjacent packets on one page merge into a single segment.
std::vector<std::span<const std::byte>> split_gcm_packets(std::span<const std::byte> wire) {
    std::vector<std::span<const std::byte>> pkts;
    std::size_t i = 0;
    while (i < wire.size()) {
        REQUIRE(i + 4 <= wire.size());
        const auto plen = load_be32(wire.subspan(i, 4));
        const auto ws = static_cast<std::size_t>(4u) + static_cast<std::size_t>(plen) + 16u;
        REQUIRE(i + ws <= wire.size());
        pkts.push_back(wire.subspan(i, ws));
        i += ws;
    }
    return pkts;
}

std::span<const std::byte> bytes_of(std::string_view s) {
    return std::as_bytes(std::span<const char>{s.data(), s.size()});
}

std::error_code write_text(core::connection& c, core::channel_ref ch, std::string_view text,
                           std::size_t& accepted) {
    const auto b = bytes_of(text);
    std::span<const std::byte> frags[] = {b};
    return c.channel_write(ch, frags, accepted);
}

std::string read_text(core::connection& c, core::channel_ref id, std::uint32_t ext, std::size_t n) {
    std::vector<std::byte> buf(n);
    const auto got = c.channel_read(id, ext, buf);
    return {reinterpret_cast<const char*>(buf.data()), got};
}

session_ids open_session(wired_connection& client, wired_connection& server) {
    core::channel_ref cid{};
    REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, cid));
    session_ids ids;
    bool opened = false;
    bool accepted = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_open_request) {
                ids.server_ch = ev.ref;
                server.conn.resolve(ev.inbound_open, channels::channel_open_verdict::accepted());
                accepted = true;
            }
            if (is_client && ev.type == legacy_event_type::channel_opened) {
                ids.client_ch = ev.ref;
                opened = true;
            }
        },
        k_rounds));
    REQUIRE(opened);
    REQUIRE(accepted);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
    return ids;
}

}  // namespace

TEST_CASE("write then read does not WINDOW_ADJUST before read", "[channel][data]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    const auto cfg = data_cfg();
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    std::size_t accepted = 0;
    REQUIRE_FALSE(write_text(client, ids.client_ch, "hello", accepted));
    REQUIRE(accepted == 5);

    bool readable = false;
    bool server_writable = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client && ev.type == legacy_event_type::channel_readable) {
                REQUIRE(ev.ref == ids.server_ch);
                REQUIRE(ev.ext_type == 0);
                readable = true;
            }
            if (!is_client && ev.type == legacy_event_type::channel_writable) {
                server_writable = true;
            }
        },
        k_rounds));
    REQUIRE(readable);
    REQUIRE_FALSE(server_writable);

    std::array<std::byte, 32> more{};
    std::span<const std::byte> fill[] = {more};
    accepted = 0;
    REQUIRE_FALSE(client.conn.channel_write(ids.client_ch, fill, accepted));
    REQUIRE(accepted < 32);
    REQUIRE(accepted == 27);

    REQUIRE(read_text(server, ids.server_ch, 0, 5) == "hello");
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("never pre-fill window; read restores writable", "[channel][data]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    const auto cfg = data_cfg();
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    std::array<std::byte, 32> payload{};
    for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<std::byte>(i + 1);
    std::span<const std::byte> full[] = {payload};
    std::size_t accepted = 0;
    REQUIRE_FALSE(client.conn.channel_write(ids.client_ch, full, accepted));
    REQUIRE(accepted == 32);

    std::array<std::byte, 1> extra{};
    std::span<const std::byte> one[] = {extra};
    accepted = 0;
    REQUIRE_FALSE(client.conn.channel_write(ids.client_ch, one, accepted));
    REQUIRE(accepted == 0);

    REQUIRE(run_loopback_legacy(client, server, [&](bool, const legacy_event&) {}, k_rounds));

    std::array<std::byte, 32> buf{};
    REQUIRE(server.conn.channel_read(ids.server_ch, 0, std::span{buf.data(), 16}) == 16);
    REQUIRE(std::memcmp(buf.data(), payload.data(), 16) == 0);

    bool writable = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (is_client && ev.type == legacy_event_type::channel_writable) {
                REQUIRE(ev.ref == ids.client_ch);
                writable = true;
            }
        },
        k_rounds));
    REQUIRE(writable);

    accepted = 0;
    REQUIRE_FALSE(client.conn.channel_write(ids.client_ch, one, accepted));
    REQUIRE(accepted >= 1);
    REQUIRE(server.conn.channel_read(ids.server_ch, 0, std::span{buf.data() + 16, 16}) == 16);
    REQUIRE(std::memcmp(buf.data(), payload.data(), 32) == 0);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("scatter write concatenates fragments", "[channel][data]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    const auto cfg = data_cfg();
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    const auto ab = bytes_of("ab");
    const auto cd = bytes_of("cd");
    std::span<const std::byte> frags[] = {ab, cd};
    std::size_t accepted = 0;
    REQUIRE_FALSE(client.conn.channel_write(ids.client_ch, frags, accepted));
    REQUIRE(accepted == 4);

    REQUIRE(run_loopback_legacy(client, server, [&](bool, const legacy_event&) {}, k_rounds));
    REQUIRE(read_text(server, ids.server_ch, 0, 4) == "abcd");
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("scatter write stops when window has room for 3", "[channel][data]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    const auto cfg = data_cfg();
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    std::array<std::byte, 29> filler{};
    std::span<const std::byte> fill[] = {filler};
    std::size_t accepted = 0;
    REQUIRE_FALSE(client.conn.channel_write(ids.client_ch, fill, accepted));
    REQUIRE(accepted == 29);

    const auto ab = bytes_of("ab");
    const auto cd = bytes_of("cd");
    std::span<const std::byte> frags[] = {ab, cd};
    accepted = 0;
    REQUIRE_FALSE(client.conn.channel_write(ids.client_ch, frags, accepted));
    REQUIRE(accepted == 3);

    REQUIRE(run_loopback_legacy(client, server, [&](bool, const legacy_event&) {}, k_rounds));
    REQUIRE(read_text(server, ids.server_ch, 0, 32) == std::string(29, '\0') + "abc");
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("max_packet splits a write into one coalesced readable event", "[channel][data]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    core::config cfg;
    cfg.initial_window = 32;
    cfg.max_channel_packet = 4;
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    std::size_t accepted = 0;
    REQUIRE_FALSE(write_text(client, ids.client_ch, "0123456789", accepted));
    REQUIRE(accepted == 10);

    while (!client.conn.pending_output0().empty()) {
        const auto out = client.conn.pending_output0();
        std::size_t n = 0;
        REQUIRE_FALSE(server.conn.feed(out, n));
        REQUIRE(n > 0);
        client.conn.consume_output(n);
    }
    int readable = 0;
    for (const auto& rec : server.handler.events) {
        if (const auto* r = std::get_if<recording_handler::channel_readable>(&rec)) {
            REQUIRE(r->ext_type == 0);
            ++readable;
        }
    }
    REQUIRE(readable == 1);
    REQUIRE(read_text(server, ids.server_ch, 0, 10) == "0123456789");
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("stderr write_extended is readable on ext 1 not stdout", "[channel][data]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    const auto cfg = data_cfg();
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    const auto err = bytes_of("err");
    std::span<const std::byte> frags[] = {err};
    std::size_t accepted = 0;
    REQUIRE_FALSE(server.conn.channel_write_extended(ids.server_ch, channels::extended_data_stderr, frags,
                                                accepted));
    REQUIRE(accepted == 3);

    bool readable = false;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (is_client && ev.type == legacy_event_type::channel_readable) {
                REQUIRE(ev.ref == ids.client_ch);
                REQUIRE(ev.ext_type == channels::extended_data_stderr);
                readable = true;
            }
        },
        k_rounds));
    REQUIRE(readable);
    REQUIRE(read_text(client, ids.client_ch, channels::extended_data_stderr, 3) == "err");
    REQUIRE(read_text(client, ids.client_ch, 0, 8).empty());
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("channel_read of unknown ext type does not consume stderr", "[channel][data]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    const auto cfg = data_cfg();
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    const auto err = bytes_of("err");
    std::span<const std::byte> frags[] = {err};
    std::size_t accepted = 0;
    REQUIRE_FALSE(server.conn.channel_write_extended(ids.server_ch, channels::extended_data_stderr, frags,
                                                accepted));
    REQUIRE(accepted == 3);

    REQUIRE(run_loopback_legacy(client, server, [&](bool, const legacy_event&) {}, k_rounds));

    std::array<std::byte, 8> buf{};
    REQUIRE(client.conn.channel_read(ids.client_ch, 2, buf) == 0);
    REQUIRE(read_text(client, ids.client_ch, channels::extended_data_stderr, 3) == "err");
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("channel_write_extended rejects non-stderr types", "[channel][data]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    const auto cfg = data_cfg();
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    const auto err = bytes_of("x");
    std::span<const std::byte> frags[] = {err};
    std::size_t accepted = 99;
    REQUIRE(server.conn.channel_write_extended(ids.server_ch, 2, frags, accepted)
            == code::invalid_state);
    REQUIRE(accepted == 0);
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("stderr and stdout share the send window", "[channel][data]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    const auto cfg = data_cfg();
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    std::array<std::byte, 30> stdout_bytes{};
    std::span<const std::byte> out_frags[] = {stdout_bytes};
    std::size_t accepted = 0;
    REQUIRE_FALSE(client.conn.channel_write(ids.client_ch, out_frags, accepted));
    REQUIRE(accepted == 30);

    const auto err = bytes_of("stderr");
    std::span<const std::byte> err_frags[] = {err};
    accepted = 0;
    REQUIRE_FALSE(
        client.conn.channel_write_extended(ids.client_ch, channels::extended_data_stderr, err_frags, accepted));
    REQUIRE(accepted == 2);

    accepted = 0;
    REQUIRE_FALSE(
        client.conn.channel_write_extended(ids.client_ch, channels::extended_data_stderr, err_frags, accepted));
    REQUIRE(accepted == 0);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("inbound data larger than window is channel_window_exceeded", "[channel][data]") {
    auto cfg = scripted_peer::sut_config();
    cfg.initial_window = 4;
    cfg.max_channels = 4;
    peer_session s{core::role::client, cfg};
    s.authenticate();
    const auto ch = open_confirmed(s, 100, 32);
    wire::detail::channel_data msg;
    msg.recipient = ch.sut_id;
    msg.data = std::as_bytes(std::span{"abcdef", 6});
    s.peer.send_msg(msg);
    REQUIRE(s.peer.deliver(s.sut) == code::channel_window_exceeded);
}

TEST_CASE("inbound WINDOW_ADJUST overflow is channel_window_exceeded", "[channel][data]") {
    auto cfg = scripted_peer::sut_config();
    cfg.initial_window = 4;
    cfg.max_channels = 4;
    peer_session s{core::role::client, cfg};
    s.authenticate();
    const auto ch = open_confirmed(s, 100, 32);
    wire::detail::channel_window_adjust msg;
    msg.recipient = ch.sut_id;
    msg.bytes = std::numeric_limits<std::uint32_t>::max();
    s.peer.send_msg(msg);
    REQUIRE(s.peer.deliver(s.sut) == code::channel_window_exceeded);
}

TEST_CASE("unread data then EOF is readable before eof and then empty", "[channel][data]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    const auto cfg = data_cfg();
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    std::size_t accepted = 0;
    REQUIRE_FALSE(write_text(client, ids.client_ch, "xy", accepted));
    REQUIRE(accepted == 2);
    REQUIRE_FALSE(client.conn.channel_eof(ids.client_ch));

    std::vector<legacy_event_type> server_events;
    REQUIRE(run_loopback_legacy(client, server,
        [&](bool is_client, const legacy_event& ev) {
            if (!is_client
                && (ev.type == legacy_event_type::channel_readable
                    || ev.type == legacy_event_type::channel_eof)) {
                server_events.push_back(ev.type);
            }
        },
        k_rounds));
    REQUIRE(server_events.size() >= 2);
    REQUIRE(server_events[0] == legacy_event_type::channel_readable);
    REQUIRE(server_events[1] == legacy_event_type::channel_eof);
    REQUIRE(read_text(server, ids.server_ch, 0, 2) == "xy");
    REQUIRE(server.conn.channel_read(ids.server_ch, 0, std::span<std::byte>{}) == 0);
    std::array<std::byte, 8> leftover{};
    REQUIRE(server.conn.channel_read(ids.server_ch, 0, leftover) == 0);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("write after local EOF is invalid_state", "[channel][data]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    const auto cfg = data_cfg();
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    REQUIRE_FALSE(client.conn.channel_eof(ids.client_ch));
    std::size_t accepted = 99;
    REQUIRE(write_text(client, ids.client_ch, "no", accepted) == code::invalid_state);
    REQUIRE(accepted == 0);
    REQUIRE_FALSE(client.conn.failure());
}

TEST_CASE("rekey with in-flight data still delivers concatenated payload", "[channel][data][rekey]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    core::config cfg;
    cfg.initial_window = 11;
    cfg.max_channel_packet = 16;
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    std::size_t accepted = 0;
    REQUIRE_FALSE(write_text(client, ids.client_ch, "before", accepted));
    REQUIRE(accepted == 6);
    REQUIRE_FALSE(client.conn.rekey());
    const auto n0 = client.conn.pending_output_bytes();
    accepted = 99;
    REQUIRE_FALSE(write_text(client, ids.client_ch, "after", accepted));
    REQUIRE(accepted == 0);
    REQUIRE(client.conn.pending_output_bytes() == n0);

    std::optional<std::size_t> client_rekey_pos;
    std::optional<std::size_t> client_wr_pos;
    std::size_t client_pos = 0;
    bool server_rekey_done = false;
    REQUIRE(run_loopback(
        client, server,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (is_client) {
                if (std::holds_alternative<recording_handler::rekey_done>(ev)) {
                    client_rekey_pos = client_pos++;
                } else if (std::holds_alternative<recording_handler::channel_writable>(ev)) {
                    client_wr_pos = client_pos;
                    ++client_pos;
                } else {
                    ++client_pos;
                }
            }
            if (!is_client && std::holds_alternative<recording_handler::rekey_done>(ev)) {
                server_rekey_done = true;
            }
        },
        k_rounds));
    REQUIRE(server_rekey_done);
    REQUIRE(client_rekey_pos.has_value());
    REQUIRE(client_wr_pos.has_value());
    REQUIRE(*client_rekey_pos < *client_wr_pos);

    accepted = 0;
    REQUIRE_FALSE(write_text(client, ids.client_ch, "after", accepted));
    REQUIRE(accepted == 5);
    REQUIRE(run_loopback_legacy(client, server, [&](bool, const legacy_event&) {}, k_rounds));
    REQUIRE(read_text(server, ids.server_ch, 0, 16) == "beforeafter");
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("64 one-byte fragments merge into 16-byte CHANNEL_DATA packets", "[channel][data]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    const auto cfg = gcm_cfg(256, 16);
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    std::array<std::byte, 64> payload{};
    for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<std::byte>(i + 1);
    std::array<std::span<const std::byte>, 64> frags{};
    for (std::size_t i = 0; i < frags.size(); ++i) frags[i] = std::span<const std::byte>{payload}.subspan(i, 1);

    std::size_t accepted = 0;
    REQUIRE_FALSE(client.conn.channel_write(ids.client_ch, frags, accepted));
    REQUIRE(accepted == 64);

    const auto wire = collect_output(client.conn);
    const auto pkts = split_gcm_packets(wire);
    REQUIRE(pkts.size() == 4);

    std::string got;
    for (const auto pkt : pkts) {
        std::size_t n = 0;
        REQUIRE_FALSE(server.conn.feed(pkt, n));
        REQUIRE(n == pkt.size());
        got += read_text(server, ids.server_ch, 0, 64);
    }
    REQUIRE(got.size() == 64);
    REQUIRE(got == std::string(reinterpret_cast<const char*>(payload.data()), payload.size()));
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("40 KiB write splits when peer max_packet is huge", "[channel][data]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    core::config cfg;
    cfg.initial_window = 256 * 1024;
    cfg.max_channel_packet = std::numeric_limits<std::uint32_t>::max();
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    std::vector<std::byte> payload(40 * 1024);
    for (std::size_t i = 0; i < payload.size(); ++i) payload[i] = static_cast<std::byte>(i & 0xff);
    std::span<const std::byte> frags[] = {payload};
    std::size_t accepted = 0;
    REQUIRE_FALSE(client.conn.channel_write(ids.client_ch, frags, accepted));
    REQUIRE(accepted == payload.size());

    REQUIRE(run_loopback_legacy(client, server, [&](bool, const legacy_event&) {}, k_rounds));
    std::vector<std::byte> got(payload.size());
    REQUIRE(server.conn.channel_read(ids.server_ch, 0, got) == payload.size());
    REQUIRE(got == payload);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("auto rekey during channel_write accepts only completed packets", "[channel][data][rekey]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    core::config cfg;
    cfg.rekey_packets = 64;
    cfg.initial_window = 1024 * 1024;
    cfg.max_channel_packet = 16;
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    std::vector<std::byte> payload(3200, std::byte{'x'});
    std::span<const std::byte> frags[] = {payload};
    std::size_t accepted = 0;
    REQUIRE_FALSE(client.conn.channel_write(ids.client_ch, frags, accepted));
    REQUIRE(accepted > 0);
    REQUIRE(accepted < payload.size());
    REQUIRE(accepted % 16 == 0);

    std::optional<std::size_t> client_rekey_pos;
    std::optional<std::size_t> client_wr_pos;
    std::size_t client_pos = 0;
    REQUIRE(run_loopback(
        client, server,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (!is_client) return;
            if (std::holds_alternative<recording_handler::rekey_done>(ev)) {
                client_rekey_pos = client_pos++;
            } else if (std::holds_alternative<recording_handler::channel_writable>(ev)) {
                client_wr_pos = client_pos;
                ++client_pos;
            } else {
                ++client_pos;
            }
        },
        k_rounds));
    REQUIRE(client_rekey_pos.has_value());
    REQUIRE(client_wr_pos.has_value());
    REQUIRE(*client_rekey_pos < *client_wr_pos);

    std::size_t sent = accepted;
    while (sent < payload.size()) {
        const auto rest = std::span<const std::byte>{payload}.subspan(sent);
        std::span<const std::byte> rest_frags[] = {rest};
        std::size_t n = 0;
        REQUIRE_FALSE(client.conn.channel_write(ids.client_ch, rest_frags, n));
        REQUIRE(n > 0);
        REQUIRE(n % 16 == 0);
        sent += n;
        if (sent < payload.size()) {
            bool got_done = false;
            bool got_wr = false;
            REQUIRE(run_loopback(
                client, server,
                [&](bool is_client, const recording_handler::recorded_event& ev) {
                    if (!is_client) return;
                    if (std::holds_alternative<recording_handler::rekey_done>(ev)) {
                        got_done = true;
                    }
                    if (std::holds_alternative<recording_handler::channel_writable>(ev)) {
                        got_wr = true;
                    }
                },
                k_rounds));
            REQUIRE(got_done);
            REQUIRE(got_wr);
        }
    }
    REQUIRE(run_loopback_legacy(client, server, [&](bool, const legacy_event&) {}, k_rounds));
    std::vector<std::byte> got(payload.size());
    REQUIRE(server.conn.channel_read(ids.server_ch, 0, got) == payload.size());
    REQUIRE(got == payload);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("control packets during rekey are deferred until rekey_done", "[channel][data][rekey]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    const auto cfg = data_cfg();
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    REQUIRE_FALSE(client.conn.rekey());
    const auto n0 = client.conn.pending_output_bytes();
    REQUIRE_FALSE(client.conn.channel_eof(ids.client_ch));
    REQUIRE(client.conn.pending_output_bytes() == n0);

    bool client_rekey_done = false;
    bool server_rekey_done = false;
    bool server_eof = false;
    bool eof_after_client_rekey = false;
    REQUIRE(run_loopback(
        client, server,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (is_client && std::holds_alternative<recording_handler::rekey_done>(ev)) {
                client_rekey_done = true;
            }
            if (!is_client) {
                if (std::holds_alternative<recording_handler::rekey_done>(ev)) {
                    server_rekey_done = true;
                }
                if (std::holds_alternative<recording_handler::channel_eof>(ev)) {
                    server_eof = true;
                    eof_after_client_rekey = client_rekey_done;
                }
            }
        },
        k_rounds));
    REQUIRE(client_rekey_done);
    REQUIRE(server_rekey_done);
    REQUIRE(server_eof);
    REQUIRE(eof_after_client_rekey);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

namespace {

core::config admission_cfg() {
    auto cfg = scripted_peer::sut_config();
    cfg.initial_window = 32;
    cfg.max_channel_packet = 16;
    cfg.max_channels = 4;
    return cfg;
}

std::size_t writable_events(const recording_handler& handler, core::channel_ref ref) {
    std::size_t n = 0;
    for (const auto& ev : handler.events) {
        if (const auto* wr = std::get_if<recording_handler::channel_writable>(&ev)) {
            REQUIRE(wr->ref == ref);
            ++n;
        }
    }
    return n;
}

void peer_window_adjust(peer_session& s, const peer_channel& ch, std::uint32_t bytes) {
    wire::detail::channel_window_adjust msg;
    msg.recipient = ch.sut_id;
    msg.bytes = bytes;
    s.peer.send_msg(msg);
    s.sut.handler.events.clear();
    REQUIRE_FALSE(s.peer.exchange(s.sut));
}

std::size_t write_n(peer_session& s, core::channel_ref ref, std::size_t n) {
    const std::string data(n, 'w');
    const std::span<const std::byte> frag = std::as_bytes(std::span{data});
    std::size_t accepted = 0;
    REQUIRE_FALSE(s.sut.conn.channel_write(ref, std::span{&frag, 1}, accepted));
    return accepted;
}

// SUT 调用 rekey()：立刻暂停出站数据。KEXINIT 留在 SUT 输出里，对端尚未回应。
void pause_by_rekey(peer_session& s) {
    REQUIRE_FALSE(s.sut.conn.rekey());
}

std::vector<std::vector<std::byte>> take_all(scripted_peer& peer, wire::msg id) {
    std::vector<std::vector<std::byte>> out;
    while (auto m = peer.take(id)) out.push_back(std::move(*m));
    return out;
}

}  // namespace

TEST_CASE("peer max_packet 0 is clamped so writes make progress", "[channel][data]") {
    peer_session s{core::role::client, admission_cfg()};
    s.authenticate();
    const auto ch = open_confirmed(s, 32, 0);
    REQUIRE(write_n(s, ch.local, 3) == 3);
    REQUIRE_FALSE(s.peer.exchange(s.sut));
    const auto pkts = take_all(s.peer, wire::msg::channel_data);
    REQUIRE(pkts.size() == 3);
    for (const auto& p : pkts) {
        wire::reader r{p};
        wire::detail::channel_data d;
        REQUIRE(d.decode(r));
        REQUIRE(d.data.size() == 1);
    }
}

TEST_CASE("peer max_packet is clamped to max_channel_data_payload", "[channel][data]") {
    auto cfg = scripted_peer::sut_config();
    cfg.initial_window = 256 * 1024;
    cfg.max_channel_packet = 32768;
    cfg.max_channels = 4;
    peer_session s{core::role::client, cfg};
    s.authenticate();
    const auto ch = open_confirmed(s, 256 * 1024, std::numeric_limits<std::uint32_t>::max());
    const std::size_t n = channels::max_channel_data_payload + 100;
    REQUIRE(write_n(s, ch.local, n) == n);
    REQUIRE_FALSE(s.peer.exchange(s.sut));
    const auto pkts = take_all(s.peer, wire::msg::channel_data);
    REQUIRE(pkts.size() == 2);
    wire::reader r{pkts[0]};
    wire::detail::channel_data first;
    REQUIRE(first.decode(r));
    // CHANNEL_DATA header (type + recipient + string length) shares the
    // packet writer's payload budget with the data string. For aes256-gcm
    // that budget equals max_channel_data_payload, so the string is 9 bytes
    // shorter than the channel-table clamp.
    REQUIRE(first.data.size() == channels::max_channel_data_payload - 9);
}

TEST_CASE("inbound data larger than local_max_packet is rejected", "[channel][data]") {
    auto cfg = scripted_peer::sut_config();
    cfg.initial_window = 64;
    cfg.max_channel_packet = 4;
    cfg.max_channels = 4;
    peer_session s{core::role::client, cfg};
    s.authenticate();
    const auto ch = open_confirmed(s, 100, 32);
    wire::detail::channel_data msg;
    msg.recipient = ch.sut_id;
    msg.data = std::as_bytes(std::span{"abcdef", 6});
    s.peer.send_msg(msg);
    REQUIRE(s.peer.deliver(s.sut) == code::unexpected_message);
}

TEST_CASE("unknown extended data type is discarded with window credit", "[channel][data]") {
    peer_session s{core::role::client, admission_cfg()};
    s.authenticate();
    const auto ch = open_confirmed(s, 100, 32);
    wire::detail::channel_extended_data msg;
    msg.recipient = ch.sut_id;
    msg.data_type = 99;
    msg.data = std::as_bytes(std::span{"abcd", 4});
    s.peer.send_msg(msg);
    REQUIRE_FALSE(s.peer.exchange(s.sut));
    REQUIRE(s.sut.handler.events.empty());
    const auto adj_bytes = s.peer.take(wire::msg::channel_window_adjust);
    REQUIRE(adj_bytes);
    wire::reader r{*adj_bytes};
    wire::detail::channel_window_adjust adj;
    REQUIRE(adj.decode(r));
    REQUIRE(adj.bytes == 4);
    std::array<std::byte, 8> buf{};
    REQUIRE(s.sut.conn.channel_read(ch.local, 0, buf) == 0);
    REQUIRE(s.sut.conn.channel_read(ch.local, channels::extended_data_stderr, buf) == 0);
}

TEST_CASE("write with no remote window accepts nothing and arms writable", "[channel][data]") {
    peer_session s{core::role::client, admission_cfg()};
    s.authenticate();
    const auto ch = open_confirmed(s, 0, 32);

    // 未登记 writable 时，重协商结束的恢复不唤醒。
    REQUIRE_FALSE(s.sut.conn.rekey());
    REQUIRE_FALSE(s.peer.exchange(s.sut));
    REQUIRE(writable_events(s.sut.handler, ch.local) == 0);

    REQUIRE(write_n(s, ch.local, 1) == 0);
    peer_window_adjust(s, ch, 7);
    REQUIRE(writable_events(s.sut.handler, ch.local) == 1);
    REQUIRE(write_n(s, ch.local, 10) == 7);
}

TEST_CASE("WINDOW_ADJUST while paused credits window without writable event", "[channel][data]") {
    peer_session s{core::role::client, admission_cfg()};
    s.authenticate();
    const auto ch = open_confirmed(s, 10, 32);

    pause_by_rekey(s);
    REQUIRE(write_n(s, ch.local, 1) == 0);
    wire::detail::channel_window_adjust adj;
    adj.recipient = ch.sut_id;
    adj.bytes = 5;
    s.peer.send_msg(adj);
    s.sut.handler.events.clear();
    REQUIRE_FALSE(s.peer.deliver(s.sut));
    REQUIRE(writable_events(s.sut.handler, ch.local) == 0);
    REQUIRE(write_n(s, ch.local, 1) == 0);

    s.sut.handler.events.clear();
    REQUIRE_FALSE(s.peer.exchange(s.sut));          // 重协商完成
    REQUIRE(writable_events(s.sut.handler, ch.local) == 1);
    REQUIRE(write_n(s, ch.local, 20) == 15);
}

TEST_CASE("rekey completion emits a single writable edge", "[channel][data]") {
    peer_session s{core::role::client, admission_cfg()};
    s.authenticate();
    const auto ch = open_confirmed(s, 10, 32);

    pause_by_rekey(s);
    REQUIRE(write_n(s, ch.local, 1) == 0);
    s.sut.handler.events.clear();
    REQUIRE_FALSE(s.peer.exchange(s.sut));
    REQUIRE(writable_events(s.sut.handler, ch.local) == 1);

    // 第二次重协商再次进入 resume_writes：want_writable 已清除，不再唤醒。
    s.sut.handler.events.clear();
    pause_by_rekey(s);
    REQUIRE_FALSE(s.peer.exchange(s.sut));
    REQUIRE(writable_events(s.sut.handler, ch.local) == 0);

    // 窗口尚未用尽，WINDOW_ADJUST 不唤醒。
    peer_window_adjust(s, ch, 4);
    REQUIRE(writable_events(s.sut.handler, ch.local) == 0);
}

TEST_CASE("rekey completion does not wake a closed channel", "[channel][data]") {
    peer_session s{core::role::client, admission_cfg()};
    s.authenticate();
    const auto ch = open_confirmed(s, 10, 32);

    pause_by_rekey(s);
    REQUIRE(write_n(s, ch.local, 1) == 0);
    REQUIRE_FALSE(s.sut.conn.channel_close(ch.local));
    s.sut.handler.events.clear();
    REQUIRE_FALSE(s.peer.exchange(s.sut));
    REQUIRE(writable_events(s.sut.handler, ch.local) == 0);
    REQUIRE(s.peer.take(wire::msg::channel_close));    // 延迟的 CLOSE 在重协商后发出

    const std::string data(1, 'w');
    const std::span<const std::byte> frag = std::as_bytes(std::span{data});
    std::size_t accepted = 0;
    REQUIRE(s.sut.conn.channel_write(ch.local, std::span{&frag, 1}, accepted) == code::invalid_state);

    peer_window_adjust(s, ch, 5);
    REQUIRE(writable_events(s.sut.handler, ch.local) == 0);
}
