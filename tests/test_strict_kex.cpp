#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/core/config.hpp>
#include <yanterm-ssh/core/connection.hpp>
#include <yanterm-ssh/core/detail/host_key.hpp>
#include <yanterm-ssh/core/types.hpp>
#include <yanterm-ssh/core/detail/packet.hpp>
#include <yanterm-ssh/wire/message_ids.hpp>
#include <yanterm-ssh/wire/detail/messages.hpp>
#include <yanterm-ssh/wire/types.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/detail/error.hpp>

#include "drive.hpp"
#include "handshake_fixture.hpp"
#include "loopback.hpp"
#include "recording_handler.hpp"

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#ifndef YANTERM_SSH_FIXTURE_DIR
#error "YANTERM_SSH_FIXTURE_DIR must be defined"
#endif

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

namespace {

std::vector<std::byte> plaintext_packet(crypto::provider p, std::span<const std::byte> payload) {
    core::detail::packet_writer w{p};
    memory::detail::page_pool pool;
    memory::detail::page_slice packet;
    REQUIRE_FALSE(w.write(payload, pool, packet));
    return {packet.bytes().begin(), packet.bytes().end()};
}

std::vector<std::byte> encode_ignore(crypto::provider p, std::string_view data = "x") {
    wire::detail::ignore_msg msg;
    msg.data = std::as_bytes(std::span{data.data(), data.size()});
    wire::writer payload;
    msg.encode(payload);
    return plaintext_packet(p, payload.data());
}

std::vector<std::byte> encode_debug(crypto::provider p) {
    wire::detail::debug_msg msg;
    msg.always_display = false;
    msg.message = "mid-kex";
    msg.language = {};
    wire::writer payload;
    msg.encode(payload);
    return plaintext_packet(p, payload.data());
}

std::vector<std::byte> encode_service_request(crypto::provider p) {
    wire::detail::service_msg svc;
    svc.id = wire::msg::service_request;
    svc.service_name = "ssh-userauth";
    wire::writer payload;
    svc.encode(payload);
    return plaintext_packet(p, payload.data());
}

std::vector<std::byte> encode_ext_info(crypto::provider p) {
    const auto value = std::as_bytes(std::span{"ssh-ed25519", 11});
    const wire::detail::ext_info::entry entries[] = {{"server-sig-algs", value}};
    wire::detail::ext_info msg;
    msg.entries = entries;
    wire::writer payload;
    msg.encode(payload);
    return plaintext_packet(p, payload.data());
}

void exchange_banners(core::connection& a, core::connection& b) {
    std::error_code ec;
    auto out_buf = collect_output(a);
    std::span<const std::byte> out{out_buf};
    const std::size_t n = feed_all(b, out, ec);
    REQUIRE_FALSE(ec);
    a.consume_output(n);

    out_buf = collect_output(b);
    out = out_buf;
    const std::size_t m = feed_all(a, out, ec);
    REQUIRE_FALSE(ec);
    b.consume_output(m);
}

void transfer(core::connection& from, core::connection& to) {
    std::error_code ec;
    auto out = from.pending_output0();
    if (out.empty()) return;
    const std::size_t n = feed_all(to, out, ec);
    from.consume_output(n);
}

void drain_events(core::connection&) {}

void drain_events(wired_connection& side) {
    side.handler.events.clear();
}

// Drive until client emits verify_host_key; server has sent NEWKEYS but client
// has not yet resolved (so server is in wait_newkeys).
core::host_key_ticket drive_to_host_key(wired_connection& client, wired_connection& server) {
    core::host_key_ticket pending{};
    for (int i = 0; i < 32 && pending == core::host_key_ticket{}; ++i) {
        transfer(client.conn, server.conn);
        transfer(server.conn, client.conn);
        for (const auto& ev : client.handler.events) {
            if (const auto* host = std::get_if<recording_handler::verify_host_key>(&ev)) {
                pending = host->ticket;
            }
        }
        client.handler.events.clear();
        drain_events(server.conn);
        if (!client.conn.failure() && !server.conn.failure() && client.conn.pending_output_bytes() == 0
            && server.conn.pending_output_bytes() == 0 && pending == core::host_key_ticket{}) {
            break;
        }
    }
    return pending;
}

bool run_handshake(wired_connection& client, wired_connection& server,
                   std::string* client_sig_algs = nullptr) {
    handshake_capture cap;
    const bool ok = run_handshake(client, server, cap);
    if (ok && client_sig_algs) {
        for (const auto& name : cap.client_types) {
            (void)name;
        }
        *client_sig_algs = client.conn.server_sig_algs();
    }
    return ok;
}

}  // namespace

TEST_CASE("default handshake negotiates strict_kex", "[strict_kex]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    REQUIRE(run_handshake(client, server));
    REQUIRE(client.conn.negotiated() != nullptr);
    REQUIRE(server.conn.negotiated() != nullptr);
    REQUIRE(client.conn.negotiated()->strict_kex);
    REQUIRE(server.conn.negotiated()->strict_kex);
}

TEST_CASE("peer without strict marker accepts IGNORE during initial KEX", "[strict_kex]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    core::config strict_off;
    strict_off.advertise_strict_kex = false;
    // One side omits the strict marker → negotiated strict_kex == false.
    auto client = make_client(p, strict_off);
    auto server = make_server(p);
    configure_server(server, hm);

    core::host_key_ticket pending = drive_to_host_key(client, server);
    REQUIRE(pending != core::host_key_ticket{});
    REQUIRE(client.conn.negotiated() != nullptr);
    REQUIRE_FALSE(client.conn.negotiated()->strict_kex);

    // Server is waiting for client's NEWKEYS; IGNORE must be accepted (non-strict).
    auto ign = encode_ignore(p, "ok");
    std::error_code ec;
    { std::size_t _n = 0; ec = server.conn.feed(ign, _n); }
    REQUIRE_FALSE(ec);
    REQUIRE_FALSE(server.conn.failure());
    bool got_ignore = false;
    for (const auto& ev : server.handler.events) {
        if (std::holds_alternative<recording_handler::ignore_message>(ev)) got_ignore = true;
    }
    server.handler.events.clear();
    REQUIRE(got_ignore);

    client.conn.resolve(pending, core::host_key_verdict::accept);
    REQUIRE(run_handshake(client, server));
    REQUIRE_FALSE(client.conn.negotiated()->strict_kex);
}

TEST_CASE("strict kex resets outbound sequence after NEWKEYS", "[strict_kex]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    REQUIRE(run_handshake(client, server));
    REQUIRE(client.conn.negotiated()->strict_kex);
    // After NEWKEYS + reset, the next outbound packet uses sequence 0.
    // Client has not sent anything after NEWKEYS → still 0.
    // Server sent EXT_INFO immediately after NEWKEYS at seq 0 → now 1.
    REQUIRE(client.conn.outbound_sequence_number() == 0);
    REQUIRE(server.conn.outbound_sequence_number() == 1);

    REQUIRE_FALSE(client.conn.send_ignore(std::as_bytes(std::span{"z", 1})));
    REQUIRE(client.conn.outbound_sequence_number() == 1);

    bool got = false;
    REQUIRE(run_loopback(
        client, server,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (!is_client && std::holds_alternative<recording_handler::ignore_message>(ev)) {
                got = true;
            }
        }));
    REQUIRE(got);

    // Contrast: without strict, sequence continues past NEWKEYS.
    core::config off;
    off.advertise_strict_kex = false;
    auto c2 = make_client(p, off);
    auto s2 = make_server(p, off);
    configure_server(s2, hm);
    REQUIRE(run_handshake(c2, s2));
    REQUIRE_FALSE(c2.conn.negotiated()->strict_kex);
    REQUIRE(c2.conn.outbound_sequence_number() > 0);
}

TEST_CASE("strict kex rejects IGNORE before KEXINIT", "[strict_kex]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);

    // Deliver only the version banners; hold binary packets.
    {
        std::error_code ec;
        // client banner → server (server emits peer_identification + KEXINIT)
        const auto out_buf = collect_output(client);
        std::span<const std::byte> out{out_buf};
        // Split: version line ends with \n. Feed only the identification line.
        std::size_t nl = 0;
        while (nl < out.size() && std::to_integer<unsigned char>(out[nl]) != '\n') ++nl;
        REQUIRE(nl < out.size());
        const std::size_t n = feed_all(server, out.first(nl + 1), ec);
        REQUIRE_FALSE(ec);
        client.conn.consume_output(n);
        drain_events(server);
    }
    {
        std::error_code ec;
        const auto out_buf = collect_output(server);
        std::span<const std::byte> out{out_buf};
        std::size_t nl = 0;
        while (nl < out.size() && std::to_integer<unsigned char>(out[nl]) != '\n') ++nl;
        REQUIRE(nl < out.size());
        // Feed only server banner to client — leave server KEXINIT in pending_output.
        const std::size_t n = feed_all(client, out.first(nl + 1), ec);
        REQUIRE_FALSE(ec);
        server.conn.consume_output(n);
        drain_events(client);
    }

    // Client is in wait_kexinit; first binary packet is IGNORE, then peer KEXINIT.
    auto ign = encode_ignore(p);
    std::error_code ec;
    { std::size_t _n = 0; ec = client.conn.feed(ign, _n); }
    REQUIRE_FALSE(client.conn.failure());

    const auto kexinit_wire = collect_output(server);
    REQUIRE_FALSE(kexinit_wire.empty());
    { std::size_t _n = 0; ec = client.conn.feed(kexinit_wire, _n); }
    server.conn.consume_output(kexinit_wire.size());
    REQUIRE(client.conn.failure() == code::strict_kex_violation);
}

TEST_CASE("strict kex rejects DEBUG mid initial KEX", "[strict_kex]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);

    // Banner-only exchange, then KEXINITs, then stop before ECDH completes so
    // DEBUG is processed while still in initial KEX (not buffered under await).
    {
        std::error_code ec;
        const auto out_buf = collect_output(client);
        std::span<const std::byte> out{out_buf};
        std::size_t nl = 0;
        while (nl < out.size() && std::to_integer<unsigned char>(out[nl]) != '\n') ++nl;
        { std::size_t _n = feed_all(server, out.first(nl + 1), ec); client.conn.consume_output(_n); }
        REQUIRE_FALSE(ec);
        drain_events(server);
    }
    {
        std::error_code ec;
        const auto out_buf = collect_output(server);
        std::span<const std::byte> out{out_buf};
        std::size_t nl = 0;
        while (nl < out.size() && std::to_integer<unsigned char>(out[nl]) != '\n') ++nl;
        // Feed banner + KEXINIT to client.conn.
        const std::size_t n = feed_all(client, out, ec);
        REQUIRE_FALSE(ec);
        server.conn.consume_output(n);
        drain_events(client);
    }
    {
        // Client KEXINIT (+ ECDH_INIT) → server; server negotiates strict.
        std::error_code ec;
        const auto out_buf = collect_output(client);
        std::span<const std::byte> out{out_buf};
        const std::size_t n = feed_all(server, out, ec);
        REQUIRE_FALSE(ec);
        client.conn.consume_output(n);
        drain_events(server);
    }
    REQUIRE(server.conn.negotiated() != nullptr);
    REQUIRE(server.conn.negotiated()->strict_kex);

    auto dbg = encode_debug(p);
    std::error_code ec;
    { std::size_t _n = 0; ec = server.conn.feed(dbg, _n); }
    REQUIRE(server.conn.failure() == code::strict_kex_violation);
}

TEST_CASE("strict kex rejects non-KEXINIT first binary packet", "[strict_kex]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);

    {
        std::error_code ec;
        const auto out_buf = collect_output(client);
        std::span<const std::byte> out{out_buf};
        std::size_t nl = 0;
        while (nl < out.size() && std::to_integer<unsigned char>(out[nl]) != '\n') ++nl;
        const std::size_t n = feed_all(server, out.first(nl + 1), ec);
        client.conn.consume_output(n);
        drain_events(server);
    }
    {
        std::error_code ec;
        const auto out_buf = collect_output(server);
        std::span<const std::byte> out{out_buf};
        std::size_t nl = 0;
        while (nl < out.size() && std::to_integer<unsigned char>(out[nl]) != '\n') ++nl;
        const std::size_t n = feed_all(client, out.first(nl + 1), ec);
        server.conn.consume_output(n);
        drain_events(client);
    }

    auto svc = encode_service_request(p);
    std::error_code ec;
    { std::size_t _n = 0; ec = client.conn.feed(svc, _n); }
    REQUIRE(client.conn.failure() == code::strict_kex_violation);
}

TEST_CASE("Terrapin: IGNORE before NEWKEYS rejected iff strict", "[strict_kex]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);

    SECTION("strict rejects") {
        auto client = make_client(p);
        auto server = make_server(p);
    configure_server(server, hm);
        core::host_key_ticket pending = drive_to_host_key(client, server);
        REQUIRE(pending != core::host_key_ticket{});
        REQUIRE(server.conn.negotiated()->strict_kex);

        auto ign = encode_ignore(p, "terrapin");
        std::error_code ec;
        { std::size_t _n = 0; ec = server.conn.feed(ign, _n); }
        REQUIRE(server.conn.failure() == code::strict_kex_violation);
    }

    SECTION("non-strict accepts") {
        core::config off;
        off.advertise_strict_kex = false;
        auto client = make_client(p, off);
        auto server = make_server(p, off);
        configure_server(server, hm);
        core::host_key_ticket pending = drive_to_host_key(client, server);
        REQUIRE(pending != core::host_key_ticket{});
        REQUIRE_FALSE(server.conn.negotiated()->strict_kex);

        auto ign = encode_ignore(p, "terrapin");
        std::error_code ec;
        { std::size_t _n = 0; ec = server.conn.feed(ign, _n); }
        REQUIRE_FALSE(server.conn.failure());
        bool got = false;
        for (const auto& ev : server.handler.events) {
            if (std::holds_alternative<recording_handler::ignore_message>(ev)) got = true;
        }
        server.handler.events.clear();
        REQUIRE(got);

        client.conn.resolve(pending, core::host_key_verdict::accept);
        REQUIRE(run_loopback(client, server));
        REQUIRE_FALSE(client.conn.failure());
        REQUIRE_FALSE(server.conn.failure());
    }
}

TEST_CASE("handshake_done carries server-sig-algs from EXT_INFO", "[strict_kex][ext_info]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    std::string sig_algs;
    REQUIRE(run_handshake(client, server, &sig_algs));
    REQUIRE_FALSE(sig_algs.empty());
    REQUIRE(sig_algs.find("ssh-ed25519") != std::string::npos);
}

TEST_CASE("no ext-info-s yields empty server_sig_algs", "[strict_kex][ext_info]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    core::config no_ext;
    no_ext.advertise_ext_info = false;
    auto client = make_client(p);
    auto server = make_server(p, no_ext);
    configure_server(server, hm);
    std::string sig_algs = "sentinel";
    REQUIRE(run_handshake(client, server, &sig_algs));
    REQUIRE(sig_algs.empty());
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

// Asymmetric: server advertises ext-info-s but never sends EXT_INFO because the
// client omitted ext-info-c (RFC 8308 MAY). Handshake must still complete.
TEST_CASE("ext-info-s advertised without EXT_INFO still completes", "[strict_kex][ext_info]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    core::config no_client_ext;
    no_client_ext.advertise_ext_info = false;
    auto client = make_client(p, no_client_ext);
    auto server = make_server(p);
    configure_server(server, hm);  // advertises ext-info-s; no EXT_INFO without ext-info-c
    std::string sig_algs = "sentinel";
    REQUIRE(run_handshake(client, server, &sig_algs));
    REQUIRE(sig_algs.empty());
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("EXT_INFO before NEWKEYS is unexpected_message", "[strict_kex][ext_info]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);

    // Get both sides into wait_kex_msg with negotiation done, then inject EXT_INFO.
    {
        std::error_code ec;
        const auto out_buf = collect_output(client);
        std::span<const std::byte> out{out_buf};
        std::size_t nl = 0;
        while (nl < out.size() && std::to_integer<unsigned char>(out[nl]) != '\n') ++nl;
        { std::size_t _n = feed_all(server, out.first(nl + 1), ec); client.conn.consume_output(_n); }
        REQUIRE_FALSE(ec);
        drain_events(server);
    }
    {
        std::error_code ec;
        const auto out_buf = collect_output(server);
        std::span<const std::byte> out{out_buf};
        const std::size_t n = feed_all(client, out, ec);
        REQUIRE_FALSE(ec);
        server.conn.consume_output(n);
        drain_events(client);
    }
    {
        std::error_code ec;
        // Feed only the client's KEXINIT (first packet), not ECDH_INIT, so the
        // server stays in wait_kex_msg after negotiating.
        const auto out_buf = collect_output(client);
        std::span<const std::byte> out{out_buf};
        core::detail::packet_reader pr{p};
        memory::detail::page_pool pool;
        memory::detail::page_slice page_payload;
        std::size_t consumed = 0;
        std::error_code rec = pr.read(out, consumed, pool, page_payload);
        REQUIRE_FALSE(rec);
        REQUIRE_FALSE(page_payload.empty());
        REQUIRE(page_payload.bytes()[0] == std::byte{static_cast<std::uint8_t>(wire::msg::kexinit)});
        // One unit from the wire prefix actually consumed.
        const auto kex_pkt = out.first(consumed);
        const std::size_t n = feed_all(server, kex_pkt, ec);
        REQUIRE_FALSE(ec);
        client.conn.consume_output(n);
        drain_events(server);
    }
    REQUIRE(server.conn.negotiated() != nullptr);

    auto ext = encode_ext_info(p);
    std::error_code ec;
    { std::size_t _n = 0; ec = server.conn.feed(ext, _n); }
    REQUIRE(server.conn.failure() == code::unexpected_message);
    REQUIRE_FALSE(server.conn.failure_detail().empty());
}
