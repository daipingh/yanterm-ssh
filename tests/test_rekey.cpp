#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/core/config.hpp>
#include <yanterm-ssh/core/connection.hpp>
#include <yanterm-ssh/core/detail/host_key.hpp>
#include <yanterm-ssh/core/types.hpp>
#include <yanterm-ssh/wire/types.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/detail/error.hpp>

#include "drive.hpp"
#include "handshake_fixture.hpp"
#include "hex_util.hpp"
#include "loopback.hpp"
#include "recording_handler.hpp"
#include "scripted_peer.hpp"

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

// RFC 8032 TEST 2 — distinct from the OpenSSH fixture key.
host_material make_alt_ed25519_host(crypto::provider p) {
    host_material hm;
    hm.seed = unhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    hm.pub = unhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    hm.priv = {crypto::sig_id::ed25519, hm.seed, hm.pub};
    crypto::public_key_material pub{crypto::sig_id::ed25519, hm.pub, {}};
    wire::writer w;
    REQUIRE_FALSE(core::detail::encode_host_key(pub, w));
    hm.blob.assign(w.data().begin(), w.data().end());
    REQUIRE(static_cast<bool>(p.new_signing_key(hm.priv)));
    return hm;
}

struct rekey_flush_handler : recording_handler {
    bool arm = false;
    bool checked = false;
    std::size_t output_before = 0;
    std::vector<std::byte> flushed_before_nested;

    void on_rekey_done(core::connection& c) override {
        const auto all = collect_output(c);
        REQUIRE(all.size() >= output_before);
        flushed_before_nested.assign(all.begin() + static_cast<std::ptrdiff_t>(output_before),
                                     all.end());
        recording_handler::on_rekey_done(c);
        if (!arm) return;
        arm = false;
        checked = true;
        REQUIRE_FALSE(flushed_before_nested.empty());
        REQUIRE_FALSE(c.rekey());
    }
};

struct rekey_capture {
    int client_verify = 0;
    int server_verify = 0;
    int client_rekey_done = 0;
    int server_rekey_done = 0;
    int client_handshake_done = 0;
    int server_handshake_done = 0;
    bool client_ignore = false;
    bool server_ignore = false;
};

auto capture_recorded(wired_connection& client, rekey_capture& cap) {
    return [&](bool is_client, const recording_handler::recorded_event& ev) {
        if (is_client) {
            if (const auto* host = std::get_if<recording_handler::verify_host_key>(&ev)) {
                ++cap.client_verify;
                client.conn.resolve(host->ticket, core::host_key_verdict::accept);
            } else if (std::holds_alternative<recording_handler::rekey_done>(ev)) {
                ++cap.client_rekey_done;
            } else if (std::holds_alternative<recording_handler::handshake_done>(ev)) {
                ++cap.client_handshake_done;
            } else if (std::holds_alternative<recording_handler::ignore_message>(ev)) {
                cap.client_ignore = true;
            }
        } else {
            if (std::holds_alternative<recording_handler::verify_host_key>(ev)) {
                ++cap.server_verify;
            } else if (std::holds_alternative<recording_handler::rekey_done>(ev)) {
                ++cap.server_rekey_done;
            } else if (std::holds_alternative<recording_handler::handshake_done>(ev)) {
                ++cap.server_handshake_done;
            } else if (std::holds_alternative<recording_handler::ignore_message>(ev)) {
                cap.server_ignore = true;
            }
        }
    };
}

bool run_handshake(wired_connection& client, wired_connection& server) {
    handshake_capture cap;
    return run_handshake(client, server, cap);
}

bool drive_rekey(wired_connection& client, wired_connection& server, rekey_capture& cap,
                 int max_rounds = 64) {
    return run_loopback(client, server, capture_recorded(client, cap), max_rounds);
}

std::vector<std::byte> big_payload(std::size_t n, char fill = 'x') {
    return std::vector<std::byte>(n, static_cast<std::byte>(fill));
}

}  // namespace

TEST_CASE("auto rekey by rekey_bytes", "[rekey]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    core::config cfg;
    cfg.rekey_bytes = 4096;
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    configure_server(server, hm);
    REQUIRE(run_handshake(client, server));

    rekey_capture cap;
    // One large IGNORE tips the wire-byte counter past 4096 on consume/feed.
    REQUIRE_FALSE(client.conn.send_ignore(big_payload(5000)));
    REQUIRE(drive_rekey(client, server, cap));
    REQUIRE(cap.client_rekey_done >= 1);
    REQUIRE(cap.server_rekey_done >= 1);
    REQUIRE(cap.client_verify == 0);  // no verify during rekey (handshake already done)
}

TEST_CASE("auto rekey by rekey_packets", "[rekey]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    core::config cfg;
    cfg.rekey_packets = 8;
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);
    configure_server(server, hm);
    REQUIRE(run_handshake(client, server));

    rekey_capture cap;
    for (int i = 0; i < 8; ++i) {
        REQUIRE_FALSE(client.conn.send_ignore(std::as_bytes(std::span{"p", 1})));
    }
    REQUIRE(drive_rekey(client, server, cap));
    REQUIRE(cap.client_rekey_done >= 1);
    REQUIRE(cap.server_rekey_done >= 1);
}

TEST_CASE("manual rekey completes with rekey_done", "[rekey]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    REQUIRE(run_handshake(client, server));

    const auto sid_before =
        std::vector<std::byte>{client.conn.session_id().begin(), client.conn.session_id().end()};
    REQUIRE_FALSE(sid_before.empty());

    rekey_capture cap;
    REQUIRE_FALSE(client.conn.rekey());
    REQUIRE(drive_rekey(client, server, cap));
    REQUIRE(cap.client_rekey_done == 1);
    REQUIRE(cap.server_rekey_done == 1);
    REQUIRE(cap.client_handshake_done == 0);
    REQUIRE(cap.server_handshake_done == 0);
    REQUIRE(cap.client_verify == 0);

    const auto sid_after =
        std::vector<std::byte>{client.conn.session_id().begin(), client.conn.session_id().end()};
    REQUIRE(sid_after == sid_before);
    REQUIRE(std::vector<std::byte>{server.conn.session_id().begin(), server.conn.session_id().end()}
            == sid_before);
}

TEST_CASE("post-rekey IGNORE still works", "[rekey]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    REQUIRE(run_handshake(client, server));

    rekey_capture cap;
    REQUIRE_FALSE(client.conn.rekey());
    REQUIRE(drive_rekey(client, server, cap));
    REQUIRE(cap.client_rekey_done == 1);

    cap = {};
    REQUIRE_FALSE(client.conn.send_ignore(std::as_bytes(std::span{"ok", 2})));
    REQUIRE(drive_rekey(client, server, cap));
    REQUIRE(cap.server_ignore);
    REQUIRE(cap.client_rekey_done == 0);
}

TEST_CASE("rekey host key change yields host_key_changed", "[rekey]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto alt = make_alt_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    REQUIRE(run_handshake(client, server));

    REQUIRE_FALSE(server.conn.rekey());
    // After local KEXINIT, phase is wait_kexinit — set_host_key is allowed.
    REQUIRE_FALSE(server.conn.set_host_key(alt.blob, alt.priv));

    rekey_capture cap;
    (void)run_loopback(client, server, capture_recorded(client, cap));
    REQUIRE(client.conn.failure() == code::host_key_changed);
    REQUIRE(cap.client_verify == 0);
    REQUIRE(cap.client_rekey_done == 0);
}

TEST_CASE("rekey emits no verify_host_key", "[rekey]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    REQUIRE(run_handshake(client, server));

    rekey_capture cap;
    REQUIRE_FALSE(client.conn.rekey());
    REQUIRE(drive_rekey(client, server, cap));
    REQUIRE(cap.client_rekey_done == 1);
    REQUIRE(cap.client_verify == 0);
    REQUIRE(cap.server_verify == 0);
}

TEST_CASE("server-initiated rekey followed by client", "[rekey]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    REQUIRE(run_handshake(client, server));

    rekey_capture cap;
    REQUIRE_FALSE(server.conn.rekey());
    REQUIRE(drive_rekey(client, server, cap));
    REQUIRE(cap.client_rekey_done == 1);
    REQUIRE(cap.server_rekey_done == 1);
    REQUIRE(cap.client_verify == 0);
}

TEST_CASE("peer KEXINIT that tips rekey_packets does not double-init", "[rekey]") {
    // Regression: note_inbound_packet → maybe_auto_rekey must not send a second
    // KEXINIT when on_peer_rekey_kexinit also responds to the same peer packet.
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    core::config cfg;
    cfg.rekey_packets = 1;  // peer KEXINIT alone tips the inbound packet counter
    auto client = make_client(p, cfg);
    auto server = make_server(p);
    configure_server(server, hm);  // default threshold — only client tips
    REQUIRE(run_handshake(client, server));

    rekey_capture cap;
    REQUIRE_FALSE(server.conn.rekey());
    REQUIRE(drive_rekey(client, server, cap));
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
    REQUIRE(cap.client_rekey_done == 1);
    REQUIRE(cap.server_rekey_done == 1);
    REQUIRE(cap.client_handshake_done == 0);
    REQUIRE(cap.server_handshake_done == 0);
}

TEST_CASE("strict kex resets sequence after rekey NEWKEYS", "[rekey]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    REQUIRE(run_handshake(client, server));
    REQUIRE(client.conn.negotiated()->strict_kex);

    REQUIRE_FALSE(client.conn.send_ignore(std::as_bytes(std::span{"a", 1})));
    rekey_capture cap;
    REQUIRE(drive_rekey(client, server, cap));
    // Handshake leaves the client at seq 1 (SERVICE_REQUEST); this IGNORE uses it.
    REQUIRE(client.conn.outbound_sequence_number() == 2);

    REQUIRE_FALSE(client.conn.rekey());
    cap = {};
    REQUIRE(drive_rekey(client, server, cap));
    REQUIRE(cap.client_rekey_done == 1);
    // After rekey NEWKEYS + strict reset, next outbound uses sequence 0.
    REQUIRE(client.conn.outbound_sequence_number() == 0);
    REQUIRE(server.conn.outbound_sequence_number() == 0);

    REQUIRE_FALSE(client.conn.send_ignore(std::as_bytes(std::span{"b", 1})));
    REQUIRE(client.conn.outbound_sequence_number() == 1);
    cap = {};
    REQUIRE(drive_rekey(client, server, cap));
    REQUIRE(cap.server_ignore);
}

TEST_CASE("two consecutive rekeys succeed", "[rekey]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    REQUIRE(run_handshake(client, server));

    const auto sid =
        std::vector<std::byte>{client.conn.session_id().begin(), client.conn.session_id().end()};

    for (int i = 0; i < 2; ++i) {
        rekey_capture cap;
        REQUIRE_FALSE(client.conn.rekey());
        REQUIRE(drive_rekey(client, server, cap));
        REQUIRE(cap.client_rekey_done == 1);
        REQUIRE(cap.server_rekey_done == 1);
        REQUIRE(cap.client_verify == 0);
        REQUIRE(std::vector<std::byte>{client.conn.session_id().begin(), client.conn.session_id().end()}
                == sid);
    }

    rekey_capture cap;
    REQUIRE_FALSE(client.conn.send_ignore(std::as_bytes(std::span{"z", 1})));
    REQUIRE(drive_rekey(client, server, cap));
    REQUIRE(cap.server_ignore);
}

TEST_CASE("IGNORE can be sent while rekey is in progress", "[rekey][channel]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    REQUIRE(run_handshake(client, server));

    REQUIRE_FALSE(client.conn.rekey());
    REQUIRE_FALSE(client.conn.send_ignore(std::as_bytes(std::span{"mid", 3})));

    rekey_capture cap;
    REQUIRE(drive_rekey(client, server, cap));
    REQUIRE(cap.client_rekey_done == 1);
    REQUIRE(cap.server_ignore);
}

TEST_CASE("mid-rekey: local IGNORE allowed; peer IGNORE still accepted", "[rekey]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    REQUIRE(run_handshake(client, server));

    REQUIRE_FALSE(client.conn.rekey());
    // C5: rekey (rekeying_) allows IGNORE/DEBUG; initial KEX does not.
    REQUIRE_FALSE(client.conn.send_ignore(std::as_bytes(std::span{"x", 1})));
    REQUIRE_FALSE(client.conn.failure());

    // Peer-initiated: client may still send IGNORE before seeing server KEXINIT;
    // server (already rekeying) must accept that IGNORE on the receive path.
    auto c2 = make_client(p);
    auto s2 = make_server(p);
    configure_server(s2, hm);
    REQUIRE(run_handshake(c2, s2));
    REQUIRE_FALSE(s2.conn.rekey());
    REQUIRE_FALSE(c2.conn.send_ignore(std::as_bytes(std::span{"mid", 3})));
    rekey_capture cap;
    REQUIRE(drive_rekey(c2, s2, cap));
    REQUIRE(cap.client_rekey_done == 1);
    REQUIRE(cap.server_rekey_done == 1);
    REQUIRE(cap.server_ignore);
}

TEST_CASE("bytes after NEWKEYS in the same buffer are decrypted with the new keys",
          "[rekey][boundary]") {
    // Pause on await_host_key so the server's NEWKEYS (+ EXT_INFO) stay queued,
    // resolve, let the server become established, append IGNORE under the new
    // keys, then feed NEWKEYS+EXT_INFO+IGNORE to the client in one feed_all.
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);

    core::host_key_ticket pending{};
    REQUIRE(run_loopback(
        client, server,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (is_client) {
                if (const auto* host =
                        std::get_if<recording_handler::verify_host_key>(&ev)) {
                    pending = host->ticket;
                }
            }
        }));
    REQUIRE(pending != core::host_key_ticket{});
    REQUIRE(server.conn.pending_output_bytes() > 0);

    client.conn.resolve(pending, core::host_key_verdict::accept);
    {
        const auto out_buf = collect_output(client.conn);
        std::error_code ec;
        const std::size_t n = feed_all(server.conn, out_buf, ec);
        REQUIRE_FALSE(ec);
        REQUIRE(n == out_buf.size());
        client.conn.consume_output(n);
        server.handler.events.clear();
    }
    REQUIRE_FALSE(server.conn.send_ignore(std::as_bytes(std::span{"x", 1})));

    bool got_handshake = false;
    bool got_ignore = false;
    {
        const auto out_buf = collect_output(server.conn);
        REQUIRE(out_buf.size() > 0);
        std::error_code ec;
        const std::size_t n = feed_all(client.conn, out_buf, ec);
        REQUIRE_FALSE(ec);
        REQUIRE(n == out_buf.size());
        server.conn.consume_output(n);

        for (const auto& ev : client.handler.events) {
            if (std::holds_alternative<recording_handler::handshake_done>(ev)) {
                got_handshake = true;
            }
            if (std::holds_alternative<recording_handler::ignore_message>(ev)) {
                got_ignore = true;
            }
        }
        client.handler.events.clear();
    }

    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
    REQUIRE(got_handshake);
    REQUIRE(got_ignore);
}

TEST_CASE("negotiated names stay valid after handshake and rekey",
          "[rekey][memory]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    REQUIRE(run_handshake(client, server));

    const auto* n = client.conn.negotiated();
    REQUIRE(n != nullptr);
    CHECK(n->kex_name == "curve25519-sha256");
    CHECK(n->host_key_name == "ssh-ed25519");

    rekey_capture cap;
    REQUIRE_FALSE(client.conn.rekey());
    REQUIRE(drive_rekey(client, server, cap));
    REQUIRE(cap.client_rekey_done == 1);
    n = client.conn.negotiated();
    REQUIRE(n != nullptr);
    CHECK(n->kex_name == "curve25519-sha256");
    CHECK(n->host_key_name == "ssh-ed25519");
    CHECK(server.conn.negotiated()->kex_name == "curve25519-sha256");
}

TEST_CASE("deferred control is flushed before on_rekey_done", "[rekey]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    rekey_flush_handler client_handler;
    core::connection client{core::role::client, p, {}, client_handler};
    auto server = make_server(p);
    configure_server(server, hm);

    auto accept_host = [&](bool is_client, const recording_handler::recorded_event& ev) {
        if (!is_client) return;
        if (const auto* host = std::get_if<recording_handler::verify_host_key>(&ev)) {
            REQUIRE_FALSE(client.resolve(host->ticket, core::host_key_verdict::accept));
        }
    };
    REQUIRE(run_loopback(client, client_handler, server.conn, server.handler, nullptr,
                                  &server, accept_host));
    REQUIRE_FALSE(client.auth_password("alice", "s3cret"));
    REQUIRE(run_loopback(
        client, client_handler, server.conn, server.handler, nullptr, &server,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (is_client) return;
            if (const auto* req = std::get_if<recording_handler::auth_request>(&ev)) {
                server.conn.resolve(req->ticket, auth::auth_verdict::success());
            }
        }));

    REQUIRE_FALSE(client.rekey());
    const auto queued = client.pending_output_bytes();
    const std::byte mark{0xab};
    REQUIRE_FALSE(client.send_global_request("test-rekey-flush@yanterm", std::span{&mark, 1}, false));
    REQUIRE(client.pending_output_bytes() == queued);

    client_handler.arm = true;
    auto transfer = [](core::connection& from, core::connection& to) {
        const auto out = from.pending_output0();
        if (out.empty()) return;
        std::size_t accepted = 0;
        REQUIRE_FALSE(to.feed(out, accepted));
        REQUIRE(accepted > 0);
        from.consume_output(accepted);
    };
    for (int round = 0; round < 64 && !client_handler.checked; ++round) {
        transfer(client, server.conn);
        client_handler.output_before = client.pending_output_bytes();
        transfer(server.conn, client);
    }
    REQUIRE(client_handler.checked);

    server.handler.events.clear();
    std::size_t accepted = 0;
    REQUIRE_FALSE(server.conn.feed(client_handler.flushed_before_nested, accepted));
    REQUIRE(accepted == client_handler.flushed_before_nested.size());
    int globals = 0;
    for (const auto& ev : server.handler.events) {
        const auto* req = std::get_if<recording_handler::global_request>(&ev);
        if (req == nullptr || req->type != "test-rekey-flush@yanterm") continue;
        ++globals;
        REQUIRE(req->payload.size() == 1);
        REQUIRE(req->payload[0] == mark);
    }
    REQUIRE(globals == 1);
    REQUIRE_FALSE(client.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("peer rekey before userauth service does not report rekey_done", "[rekey][service]") {
    auto count = [](const recording_handler& handler, auto match) {
        int n = 0;
        for (const auto& ev : handler.events) {
            if (match(ev)) ++n;
        }
        return n;
    };
    auto handshake_n = [&](const recording_handler& handler) {
        return count(handler, [](const recording_handler::recorded_event& ev) {
            return std::holds_alternative<recording_handler::handshake_done>(ev);
        });
    };
    auto rekey_n = [&](const recording_handler& handler) {
        return count(handler, [](const recording_handler::recorded_event& ev) {
            return std::holds_alternative<recording_handler::rekey_done>(ev);
        });
    };

    SECTION("client sees KEXINIT before SERVICE_ACCEPT") {
        peer_session s{core::role::client};
        s.exchange_keys();
        s.peer.start_rekey();
        REQUIRE_FALSE(s.peer.exchange(s.sut));
        REQUIRE_FALSE(s.peer.kex_in_progress());
        REQUIRE_FALSE(s.sut.conn.failure());
        REQUIRE(handshake_n(s.sut.handler) == 0);
        REQUIRE(rekey_n(s.sut.handler) == 0);

        s.peer.send_msg(wire::detail::service_msg{wire::msg::service_accept, "ssh-userauth"});
        REQUIRE_FALSE(s.peer.exchange(s.sut));
        REQUIRE(handshake_n(s.sut.handler) == 1);
        REQUIRE(rekey_n(s.sut.handler) == 0);

        s.sut.handler.events.clear();
        REQUIRE_FALSE(s.sut.conn.rekey());
        REQUIRE_FALSE(s.peer.exchange(s.sut));
        REQUIRE(rekey_n(s.sut.handler) == 1);
        REQUIRE(handshake_n(s.sut.handler) == 0);
        REQUIRE_FALSE(s.sut.conn.failure());
    }

    SECTION("server sees KEXINIT before SERVICE_REQUEST") {
        peer_session s{core::role::server};
        s.exchange_keys();
        s.peer.start_rekey();
        REQUIRE_FALSE(s.peer.exchange(s.sut));
        REQUIRE_FALSE(s.peer.kex_in_progress());
        REQUIRE_FALSE(s.sut.conn.failure());
        REQUIRE(handshake_n(s.sut.handler) == 0);
        REQUIRE(rekey_n(s.sut.handler) == 0);

        s.peer.send_msg(wire::detail::service_msg{wire::msg::service_request, "ssh-userauth"});
        REQUIRE_FALSE(s.peer.exchange(s.sut));
        REQUIRE(s.peer.take(wire::msg::service_accept));
        REQUIRE(handshake_n(s.sut.handler) == 1);
        REQUIRE(rekey_n(s.sut.handler) == 0);

        s.sut.handler.events.clear();
        REQUIRE_FALSE(s.sut.conn.rekey());
        REQUIRE_FALSE(s.peer.exchange(s.sut));
        REQUIRE(rekey_n(s.sut.handler) == 1);
        REQUIRE(handshake_n(s.sut.handler) == 0);
        REQUIRE_FALSE(s.sut.conn.failure());
    }
}

