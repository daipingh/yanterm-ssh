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
#include <yanterm-ssh/keys/private_key.hpp>
#include <yanterm-ssh/keys/public_key.hpp>

#include "drive.hpp"
#include "fixed_random_provider.hpp"
#include "handshake_fixture.hpp"
#include "loopback.hpp"
#include "recording_handler.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

namespace {

auto accept_host_key(wired_connection&) {
    return [](bool, const legacy_event&) {};
}

bool has_disconnect_packet(std::span<const std::byte> wire_bytes) {
    // Best-effort plaintext scan: look for message id byte after a plausible header.
    crypto::provider p = prov();
    core::detail::packet_reader reader{p};
    memory::detail::page_pool pool;
    std::size_t offset = 0;
    while (offset < wire_bytes.size()) {
        std::size_t accepted = 0;
        memory::detail::page_slice page_payload;
        std::error_code ec = reader.read(wire_bytes.subspan(offset), accepted, pool, page_payload);
        if (ec || accepted == 0) return false;
        offset += accepted;
        const auto payload = page_payload.bytes();
        if (payload.empty()) continue;
        if (payload[0] == std::byte{static_cast<std::uint8_t>(wire::msg::disconnect)}) return true;
    }
    return false;
}

}  // namespace

TEST_CASE("full handshake agrees on session_id and kex", "[connection][handshake]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));
    REQUIRE(cap.client_session_id == cap.server_session_id);
    REQUIRE_FALSE(cap.client_session_id.empty());
    REQUIRE(cap.client_kex_name == "curve25519-sha256");
    REQUIRE(cap.server_kex_name == "curve25519-sha256");
}

TEST_CASE("handshake event order", "[connection][handshake]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(client.conn.peer_identification().empty());
    REQUIRE(client.conn.session_id().empty());
    REQUIRE(client.conn.negotiated() == nullptr);
    REQUIRE(run_handshake(client, server, cap));

    REQUIRE(cap.client_types.size() >= 3);
    REQUIRE(cap.client_types[0] == "peer_identification");
    REQUIRE(cap.client_types[1] == "verify_host_key");
    REQUIRE(cap.client_types[2] == "handshake_done");

    REQUIRE(cap.server_types.size() >= 2);
    REQUIRE(cap.server_types[0] == "peer_identification");
    REQUIRE(cap.server_types[1] == "handshake_done");
    for (auto t : cap.server_types) {
        REQUIRE(t != "verify_host_key");
    }

    const auto banner = std::string{"SSH-2.0-"} + default_software();
    REQUIRE(client.conn.peer_identification() == banner);
    REQUIRE(server.conn.peer_identification() == banner);
    REQUIRE_FALSE(client.conn.session_id().empty());
    REQUIRE(std::equal(client.conn.session_id().begin(), client.conn.session_id().end(),
                       server.conn.session_id().begin(), server.conn.session_id().end()));
    REQUIRE(client.conn.negotiated() != nullptr);
    REQUIRE(server.conn.negotiated() != nullptr);
    REQUIRE(client.conn.negotiated()->kex_name == server.conn.negotiated()->kex_name);
}

TEST_CASE("delayed host-key verdict", "[connection][handshake]") {
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
    REQUIRE(client.conn.inbound_requests_stalled());
    REQUIRE_FALSE(server.conn.inbound_requests_stalled());
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());

    for (int i = 0; i < 5; ++i) {
        REQUIRE(client.conn.pending_output_bytes() == 0);
        // Server may still hold NEWKEYS (+ EXT_INFO): await_host_key no longer
        // accepts those bytes, so they remain in the peer's output until resolve.
        REQUIRE(server.conn.pending_output_bytes() > 0);
        REQUIRE_FALSE(client.conn.failure());
        REQUIRE_FALSE(server.conn.failure());
        {
            std::size_t n = 0;
            const std::error_code ec = client.conn.feed({}, n);
            REQUIRE_FALSE(ec);
            REQUIRE(n == 0);
        }
        {
            std::size_t n = 0;
            const std::error_code ec = server.conn.feed({}, n);
            REQUIRE_FALSE(ec);
            REQUIRE(n == 0);
        }
    }

    client.conn.resolve(pending, core::host_key_verdict::accept);
    handshake_capture cap;
    REQUIRE(run_loopback(
        client, server,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (const auto* done = std::get_if<recording_handler::handshake_done>(&ev)) {
                if (is_client) {
                    cap.client_session_id = done->session_id;
                    cap.client_kex_name = done->algorithms.kex_name;
                } else {
                    cap.server_session_id = done->session_id;
                }
            }
        }));
    REQUIRE(cap.client_session_id == cap.server_session_id);
    REQUIRE_FALSE(cap.client_session_id.empty());
    REQUIRE_FALSE(client.conn.inbound_requests_stalled());
}

TEST_CASE("host-key callback verdict controls same-feed continuation",
          "[connection][handshake]") {
    struct accepting_handler : recording_handler {
        void on_host_key(core::connection& c, core::host_key_ticket ticket,
                         std::span<const std::byte> blob) override {
            recording_handler::on_host_key(c, ticket, blob);
            REQUIRE_FALSE(c.resolve(ticket, core::host_key_verdict::accept));
        }
    };

    struct result {
        std::vector<std::byte> client_output;
        std::size_t first_accepted = 0;
        std::size_t server_flight_size = 0;
    };

    auto exercise = [&](bool inline_accept) {
        fixed_random_provider client_random{prov(), 0x12345678};
        fixed_random_provider server_random{prov(), 0x87654321};
        auto client_provider = client_random.get();
        auto server_provider = server_random.get();
        auto hm = make_ed25519_host(server_provider);
        recording_handler delayed;
        accepting_handler immediate;
        recording_handler server_handler;
        core::handler& client_handler =
            inline_accept ? static_cast<core::handler&>(immediate)
                          : static_cast<core::handler&>(delayed);
        core::connection client{core::role::client, client_provider, {}, client_handler};
        core::connection server{core::role::server, server_provider, {}, server_handler};
        configure_server(server, hm);

        auto transfer = [](core::connection& from, core::connection& to) {
            auto bytes = collect_output(from);
            std::size_t accepted = 0;
            REQUIRE_FALSE(to.feed(bytes, accepted));
            from.consume_output(accepted);
            return accepted;
        };

        REQUIRE(transfer(client, server) > 0);
        REQUIRE(transfer(server, client) > 0);
        REQUIRE(transfer(client, server) > 0);

        const auto server_flight = collect_output(server);
        REQUIRE_FALSE(server_flight.empty());
        std::size_t accepted = 0;
        REQUIRE_FALSE(client.feed(server_flight, accepted));

        auto& events = inline_accept ? immediate.events : delayed.events;
        const auto host_key = std::find_if(events.begin(), events.end(), [](const auto& event) {
            return std::holds_alternative<recording_handler::verify_host_key>(event);
        });
        REQUIRE(host_key != events.end());
        auto handshake = std::find_if(events.begin(), events.end(), [](const auto& event) {
            return std::holds_alternative<recording_handler::handshake_done>(event);
        });

        if (inline_accept) {
            REQUIRE(accepted == server_flight.size());
            REQUIRE(handshake != events.end());
        } else {
            REQUIRE(accepted < server_flight.size());
            REQUIRE(handshake == events.end());
            const auto ticket =
                std::get<recording_handler::verify_host_key>(*host_key).ticket;
            REQUIRE_FALSE(client.resolve(ticket, core::host_key_verdict::accept));
            std::size_t remainder = 0;
            REQUIRE_FALSE(client.feed(std::span{server_flight}.subspan(accepted), remainder));
            REQUIRE(accepted + remainder == server_flight.size());
            handshake = std::find_if(events.begin(), events.end(), [](const auto& event) {
                return std::holds_alternative<recording_handler::handshake_done>(event);
            });
            REQUIRE(handshake != events.end());
        }

        REQUIRE(client.negotiated() != nullptr);
        return result{collect_output(client), accepted, server_flight.size()};
    };

    const auto delayed = exercise(false);
    const auto immediate = exercise(true);
    REQUIRE(delayed.client_output == immediate.client_output);
}

TEST_CASE("resolve reject disconnects", "[connection][handshake]") {
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

    client.conn.resolve(pending, core::host_key_verdict::reject);
    REQUIRE(client.conn.failure() == code::host_key_rejected);
    REQUIRE(has_disconnect_packet(collect_output(client.conn)));

    bool server_disconnected = false;
    (void)run_loopback(
        client, server,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (!is_client) {
                if (const auto* disc = std::get_if<recording_handler::disconnected>(&ev)) {
                    server_disconnected = true;
                    REQUIRE(disc->reason == wire::disconnect_reason::host_key_not_verifiable);
                }
            }
        });
    REQUIRE(server_disconnected);
    REQUIRE(server.conn.failure() == code::peer_disconnected);
}

TEST_CASE("disconnect event copies description", "[core][disconnect]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    REQUIRE_FALSE(client.conn.disconnect(wire::disconnect_reason::by_application, "bye"));

    bool got = false;
    (void)run_loopback(
        client, server,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (!is_client) {
                if (const auto* disc = std::get_if<recording_handler::disconnected>(&ev)) {
                    got = true;
                    REQUIRE(disc->reason == wire::disconnect_reason::by_application);
                    REQUIRE(disc->description == "bye");
                }
            }
        });
    REQUIRE(got);
}

TEST_CASE("post-handshake ignore and debug", "[connection][handshake]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    const auto ignore_data = std::as_bytes(std::span{"ping", 4});
    REQUIRE_FALSE(client.conn.send_ignore(ignore_data));
    REQUIRE_FALSE(client.conn.send_debug(true, "hello-debug"));

    bool got_ignore = false;
    bool got_debug = false;
    REQUIRE(run_loopback(
        client, server,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (is_client) return;
            if (const auto* ignore = std::get_if<recording_handler::ignore_message>(&ev)) {
                got_ignore = true;
                REQUIRE(ignore->data.size() == 4);
                REQUIRE(ignore->data[0] == std::byte{'p'});
            }
            if (const auto* dbg = std::get_if<recording_handler::debug_message>(&ev)) {
                got_debug = true;
                REQUIRE(dbg->always_display);
                REQUIRE(dbg->text == "hello-debug");
            }
        }));
    REQUIRE(got_ignore);
    REQUIRE(got_debug);
}

TEST_CASE("one feed with two IGNORE keeps both payloads intact", "[connection][handshake]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    const auto d1 = std::as_bytes(std::span{"alpha", 5});
    const auto d2 = std::as_bytes(std::span{"bravo", 5});
    REQUIRE_FALSE(client.conn.send_ignore(d1));
    REQUIRE_FALSE(client.conn.send_ignore(d2));

    // Deliver both packets in a single feed (one TCP segment).
    {
        const auto out_buf = collect_output(client.conn);
        std::span<const std::byte> out{out_buf};
        REQUIRE(out.size() > 0);
        std::error_code ec;
        const std::size_t n = feed_all(server.conn, out, ec);
        REQUIRE_FALSE(ec);
        REQUIRE(n == out.size());
        client.conn.consume_output(n);
    }

    std::vector<std::vector<std::byte>> payloads;
    for (const auto& ev : server.handler.events) {
        if (const auto* ignore = std::get_if<recording_handler::ignore_message>(&ev)) {
            payloads.push_back(ignore->data);
        }
    }
    REQUIRE(payloads.size() == 2);
    REQUIRE(payloads[0].size() == 5);
    REQUIRE(payloads[1].size() == 5);
    REQUIRE(std::string_view(reinterpret_cast<const char*>(payloads[0].data()), 5) == "alpha");
    REQUIRE(std::string_view(reinterpret_cast<const char*>(payloads[1].data()), 5) == "bravo");
}

TEST_CASE("server advertises only installed host-key algorithm", "[connection][handshake]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);

    // Client prefers ECDSA first; without the server-side allowlist it would
    // negotiate ecdsa against a server that can only sign ed25519.
    core::config client_cfg;
    client_cfg.preferred_host_key = "ecdsa-sha2-nistp256,ssh-ed25519";

    auto client = make_client(p, client_cfg);
    auto server = make_server(p);
    configure_server(server, hm);  // ed25519 only via set_host_key

    std::string negotiated_host;
    std::string server_sig_algs;
    REQUIRE(run_loopback(
        client, server,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (is_client) {
                if (const auto* host =
                        std::get_if<recording_handler::verify_host_key>(&ev)) {
                    REQUIRE_FALSE(host->blob.empty());
                    keys::public_key pk;
                    REQUIRE_FALSE(keys::public_key::parse_blob(host->blob, pk));
                    REQUIRE(pk.algorithm_name() == "ssh-ed25519");
                    client.conn.resolve(host->ticket, core::host_key_verdict::accept);
                }
                if (const auto* done =
                        std::get_if<recording_handler::handshake_done>(&ev)) {
                    negotiated_host = done->algorithms.host_key_name;
                    server_sig_algs = done->server_sig_algs;
                }
            }
        }));
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
    REQUIRE(negotiated_host == "ssh-ed25519");
    REQUIRE(server_sig_algs == "ssh-ed25519");
}

TEST_CASE("byte-at-a-time feed completes handshake", "[connection][handshake]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);

    bool client_done = false;
    bool server_done = false;

    auto drain = [&](wired_connection& peer, bool is_client) {
        for (const auto& ev : peer.handler.events) {
            if (is_client) {
                if (const auto* host =
                        std::get_if<recording_handler::verify_host_key>(&ev)) {
                    peer.conn.resolve(host->ticket, core::host_key_verdict::accept);
                }
            }
            if (std::holds_alternative<recording_handler::handshake_done>(ev)) {
                if (is_client) client_done = true;
                else server_done = true;
            }
        }
        peer.handler.events.clear();
    };

    // Caller-owned re-present buffers: version_exchange consumes only through `\n`,
    // so fragmented feeds must accumulate and re-present the unconsumed prefix.
    std::vector<std::byte> pending_to_server;
    std::vector<std::byte> pending_to_client;

    for (int round = 0; round < 20000 && !(client_done && server_done); ++round) {
        bool progress = false;
        auto transfer_one = [&](wired_connection& from, wired_connection& to,
                                std::vector<std::byte>& pending, bool to_is_client) {
            auto out = from.conn.pending_output0();
            if (!out.empty()) {
                pending.push_back(out.front());
                from.conn.consume_output(1);
                progress = true;
            }
            if (pending.empty()) return;
            std::error_code ec;
            const std::size_t n = feed_all(to.conn, pending, ec);
            if (n > 0) {
                pending.erase(pending.begin(),
                              pending.begin() + static_cast<std::ptrdiff_t>(n));
                progress = true;
            }
            drain(to, to_is_client);
        };
        transfer_one(client, server, pending_to_server, false);
        transfer_one(server, client, pending_to_client, true);
        if (!progress && client.conn.pending_output_bytes() == 0 && server.conn.pending_output_bytes() == 0
            && pending_to_server.empty() && pending_to_client.empty()) {
            break;
        }
    }

    REQUIRE(client_done);
    REQUIRE(server_done);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("failure is write-once first error wins", "[connection][handshake]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);

    // Fresh pair: feed version, then inject two distinct bad packets to client.conn.
    auto client2 = make_client(p);
    auto server2 = make_server(p);
    configure_server(server2, hm);

    REQUIRE_FALSE(client2.conn.failure());
    REQUIRE(client2.conn.failure_detail().empty());

    // Deliver server banner to client (moves client into wait_kexinit).
    {
        std::error_code ec;
        const auto out_buf = collect_output(server2);
        std::span<const std::byte> out{out_buf};
        const std::size_t n = feed_all(client2, out, ec);
        REQUIRE_FALSE(ec);
        server2.conn.consume_output(n);
    }
    REQUIRE(client2.conn.failure_detail().empty());

    // Bad packet 1: SSH_MSG_SERVICE_REQUEST in wait_kexinit → strict_kex_violation
    // (we always advertise strict; first binary packet must be KEXINIT).
    {
        wire::detail::service_msg svc;
        svc.id = wire::msg::service_request;
        svc.service_name = "ssh-userauth";
        wire::writer payload;
        svc.encode(payload);
        core::detail::packet_writer w{p};
        memory::detail::page_pool pool;
        memory::detail::page_slice packet;
        REQUIRE_FALSE(w.write(payload.data(), pool, packet));
        std::error_code ec;
        { std::size_t _n = 0; ec = client2.conn.feed(packet.bytes(), _n); }
        REQUIRE(client2.conn.failure() == code::strict_kex_violation);
    }

    const auto first = client2.conn.failure();
    const auto first_detail = client2.conn.failure_detail();
    REQUIRE(client2.conn.failure_detail().data() == first_detail.data());

    // Bad packet 2: different error (invalid packet length framing) must not
    // overwrite the first failure (code or detail).
    {
        std::array<std::byte, 8> bogus{};
        bogus[0] = std::byte{0xff};
        bogus[1] = std::byte{0xff};
        bogus[2] = std::byte{0xff};
        bogus[3] = std::byte{0xff};
        std::error_code ec;
        { std::size_t _n = 0; ec = client2.conn.feed(bogus, _n); }
        REQUIRE(client2.conn.failure() == first);
        REQUIRE(ec == first);
        REQUIRE(client2.conn.failure_detail().data() == first_detail.data());
        REQUIRE(client2.conn.failure_detail() == first_detail);
    }
}

TEST_CASE("server without host key fails", "[connection][handshake]") {
    crypto::provider p = prov();
    core::config cfg;
    auto client = make_client(p, cfg);
    auto server = make_server(p, cfg);  // no set_host_key

    std::error_code ec;
    const auto out = client.conn.pending_output0();
    { std::size_t _n = 0; ec = server.conn.feed(out, _n); }
    REQUIRE(server.conn.failure() == code::invalid_state);
}

TEST_CASE("handshake for each kex algorithm", "[connection][handshake][kex]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);

    const std::string_view kex_names[] = {
        "curve25519-sha256",
        "ecdh-sha2-nistp256",
        "ecdh-sha2-nistp384",
        "ecdh-sha2-nistp521",
        "diffie-hellman-group14-sha256",
    };

    for (std::string_view kex_name : kex_names) {
        INFO(kex_name);
        core::config cfg;
        cfg.preferred_kex = kex_name;
        auto client = make_client(p, cfg);
        auto server = make_server(p, cfg);
    configure_server(server, hm);
        handshake_capture cap;
        REQUIRE(run_handshake(client, server, cap));
        REQUIRE(cap.client_kex_name == kex_name);
        REQUIRE(cap.client_session_id == cap.server_session_id);
    }
}

TEST_CASE("handshake for each cipher mode", "[connection][handshake][cipher]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);

    struct case_t {
        std::string_view cipher;
        std::string_view mac;  // empty = leave default (AEAD)
    };
    const case_t cases[] = {
        {"chacha20-poly1305@openssh.com", {}},
        {"aes256-gcm@openssh.com", {}},
        {"aes256-ctr", "hmac-sha2-256"},
        {"aes256-ctr", "hmac-sha2-256-etm@openssh.com"},
    };

    for (const auto& c : cases) {
        INFO(c.cipher);
        INFO(c.mac);
        core::config cfg;
        cfg.preferred_cipher = c.cipher;
        if (!c.mac.empty()) {
            cfg.preferred_mac = c.mac;
        }
        auto client = make_client(p, cfg);
        auto server = make_server(p, cfg);
    configure_server(server, hm);
        handshake_capture cap;
        REQUIRE(run_handshake(client, server, cap));
        REQUIRE(cap.client_session_id == cap.server_session_id);
        REQUIRE_FALSE(cap.client_session_id.empty());
    }
}

TEST_CASE("handshake for GM kex/cipher/mac/hostkey", "[connection][handshake][gm]") {
    crypto::provider p = prov();
    keys::private_key sk;
    REQUIRE_FALSE(keys::private_key::generate(p, crypto::sig_id::sm2_za, 0, "gm", sk));
    host_material hm;
    const auto blob = sk.pub().blob();
    hm.blob.assign(blob.begin(), blob.end());
    const auto m = sk.material();
    hm.seed.assign(m.seed.begin(), m.seed.end());
    hm.pub.assign(m.public_key.begin(), m.public_key.end());
    hm.priv = {crypto::sig_id::sm2_za, hm.seed, hm.pub};

    const struct {
        std::string_view kex;
        std::string_view cipher;
        std::string_view mac;
    } cases[] = {
        {"sm2-sm3", "sm4-ctr", "hmac-sm3"},
        {"ecgm-sm2-sm3", "sm4-ctr", "hmac-sm3"},
        {"sm2-sm3", "sm4-cbc", "hmac-sm3"},
    };

    for (const auto& c : cases) {
        INFO(c.kex);
        INFO(c.cipher);
        if (c.kex == "ecgm-sm2-sm3" && !p.supports(crypto::kex_id::ecdh_sm2)) continue;
        core::config cfg;
        cfg.preferred_kex = c.kex;
        cfg.preferred_host_key = "sm2";
        cfg.preferred_cipher = c.cipher;
        cfg.preferred_mac = c.mac;
        auto client = make_client(p, cfg);
        auto server = make_server(p, cfg);
        configure_server(server, hm);
        handshake_capture cap;
        REQUIRE(run_handshake(client, server, cap));
        REQUIRE(cap.client_kex_name == c.kex);
        REQUIRE(cap.client_session_id == cap.server_session_id);
        REQUIRE_FALSE(cap.client_session_id.empty());
    }
}

TEST_CASE("pending output is exposed as page segments", "[connection][output]") {
    crypto::provider p = prov();
    core::config cfg;
    auto client = make_client(p, cfg);

    // The banner is queued by the constructor.
    REQUIRE(client.conn.pending_output_bytes() > 0);

    std::span<const std::byte> segs[8];
    const std::size_t n = client.conn.pending_output(segs);
    REQUIRE(n >= 1);

    std::size_t total = 0;
    for (std::size_t i = 0; i < n; ++i) total += segs[i].size();
    REQUIRE(total == client.conn.pending_output_bytes());
    REQUIRE(segs[0].data() == client.conn.pending_output0().data());
    REQUIRE(segs[0].size() == client.conn.pending_output0().size());
}

TEST_CASE("consume_output walks across and within segments", "[connection][output]") {
    crypto::provider p = prov();
    core::config cfg;
    auto client = make_client(p, cfg);

    const auto all = collect_output(client);
    REQUIRE(all.size() == client.conn.pending_output_bytes());

    client.conn.consume_output(1);
    REQUIRE(client.conn.pending_output_bytes() == all.size() - 1);
    REQUIRE(client.conn.pending_output0()[0] == all[1]);

    client.conn.consume_output(client.conn.pending_output_bytes());
    REQUIRE(client.conn.pending_output_bytes() == 0);
    REQUIRE(client.conn.pending_output0().empty());
    REQUIRE(client.conn.pending_output(std::span<std::span<const std::byte>>{}) == 0);
}

TEST_CASE("pending_output fills only what the caller's array can hold",
          "[connection][output]") {
    crypto::provider p = prov();
    core::config cfg;
    auto client = make_client(p, cfg);

    std::span<const std::byte> one[1];
    const std::size_t n = client.conn.pending_output(one);
    REQUIRE(n == 1);
    REQUIRE(one[0].size() <= client.conn.pending_output_bytes());
}

TEST_CASE("consume_output crosses page segments", "[connection][output]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    client.conn.consume_output(client.conn.pending_output_bytes());
    server.conn.consume_output(server.conn.pending_output_bytes());

    // Two packets larger than the leftover room on a 64 KiB page, so they land
    // on different pages and stay unmerged.
    const std::vector<std::byte> blob(33000, std::byte{0xab});
    REQUIRE_FALSE(client.conn.send_ignore(blob));
    REQUIRE_FALSE(client.conn.send_ignore(blob));

    const std::size_t total = client.conn.pending_output_bytes();
    REQUIRE(total > 0);

    std::span<const std::byte> one[1];
    REQUIRE(client.conn.pending_output(one) == 1);
    REQUIRE(one[0].size() < total);

    std::span<const std::byte> many[8];
    REQUIRE(client.conn.pending_output(many) >= 2);

    const std::size_t first = one[0].size();
    client.conn.consume_output(first);
    REQUIRE(client.conn.pending_output_bytes() == total - first);
    REQUIRE_FALSE(client.conn.pending_output0().empty());

    client.conn.consume_output(client.conn.pending_output_bytes());
    REQUIRE(client.conn.pending_output_bytes() == 0);
    REQUIRE(client.conn.pending_output0().empty());
}

TEST_CASE("duplicate host key type uses the first", "[core][hostkey]") {
    crypto::provider p = prov();
    keys::private_key first;
    keys::private_key second;
    REQUIRE_FALSE(keys::private_key::generate(p, crypto::sig_id::ed25519, 0, "first", first));
    REQUIRE_FALSE(keys::private_key::generate(p, crypto::sig_id::ed25519, 0, "second", second));
    REQUIRE_FALSE(std::equal(first.pub().blob().begin(), first.pub().blob().end(),
                             second.pub().blob().begin(), second.pub().blob().end()));

    core::connection::host_key_spec specs[] = {
        {first.pub().blob(), first.material()},
        {second.pub().blob(), second.material()},
    };
    auto client = make_client(p);
    auto server = make_server(p);
    REQUIRE_FALSE(server.conn.set_host_keys(specs));

    const auto want = std::vector<std::byte>(first.pub().blob().begin(), first.pub().blob().end());
    std::vector<std::byte> seen;
    REQUIRE(run_loopback(
        client, server,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (is_client) {
                if (const auto* host =
                        std::get_if<recording_handler::verify_host_key>(&ev)) {
                    REQUIRE_FALSE(host->blob.empty());
                    seen = host->blob;
                    client.conn.resolve(host->ticket, core::host_key_verdict::accept);
                }
            }
        }));
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
    REQUIRE(seen == want);
}

TEST_CASE("non-empty preferred with no usable names fails", "[core][kex]") {
    crypto::provider p = prov();
    {
        core::config cfg;
        cfg.preferred_kex = "no-such-alg";
        auto client = make_client(p, cfg);
        const char banner[] = "SSH-2.0-test\r\n";
        std::size_t n = 0;
        auto ec = client.conn.feed(std::as_bytes(std::span{banner, sizeof(banner) - 1}), n);
        REQUIRE(client.conn.failure() == code::empty_algorithm_list);
        REQUIRE(ec == code::empty_algorithm_list);
        REQUIRE_FALSE(client.conn.failure_detail().empty());
    }
    {
        core::config cfg;
        cfg.preferred_kex = "no-such-alg,curve25519-sha256";
        auto client = make_client(p, cfg);
        auto hm = make_ed25519_host(p);
        auto server = make_server(p, cfg);
        configure_server(server, hm);
        handshake_capture cap;
        REQUIRE(run_handshake(client, server, cap));
        REQUIRE(cap.client_kex_name == "curve25519-sha256");
    }
}

namespace {

std::vector<std::byte> plaintext_packet(crypto::provider p, std::span<const std::byte> payload) {
    core::detail::packet_writer w{p};
    memory::detail::page_pool pool;
    memory::detail::page_slice packet;
    REQUIRE_FALSE(w.write(payload, pool, packet));
    return {packet.bytes().begin(), packet.bytes().end()};
}

void drain(core::connection&) {}

void feed_consume(core::connection& from, core::connection& to) {
    std::error_code ec;
    const auto out = collect_output(from);
    const std::size_t n = feed_all(to, out, ec);
    REQUIRE_FALSE(ec);
    from.consume_output(n);
    drain(to);
}

}  // namespace

TEST_CASE("no common kex records failure_detail", "[connection][handshake]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    core::config cc;
    cc.preferred_kex = "curve25519-sha256";
    core::config sc;
    sc.preferred_kex = "diffie-hellman-group14-sha256";
    auto client = make_client(p, cc);
    auto server = make_server(p, sc);
    configure_server(server, hm);
    REQUIRE_FALSE(run_loopback_legacy(client, server, accept_host_key(client)));
    const bool client_hit = client.conn.failure() == code::no_common_kex_algorithm;
    const bool server_hit = server.conn.failure() == code::no_common_kex_algorithm;
    REQUIRE((client_hit || server_hit));
    if (client_hit) REQUIRE_FALSE(client.conn.failure_detail().empty());
    if (server_hit) REQUIRE_FALSE(server.conn.failure_detail().empty());
}

TEST_CASE("packet read error records failure_detail", "[connection][handshake]") {
    crypto::provider p = prov();
    auto client = make_client(p);
    const char banner[] = "SSH-2.0-test\r\n";
    std::size_t n = 0;
    auto ec = client.conn.feed(std::as_bytes(std::span{banner, sizeof(banner) - 1}), n);
    REQUIRE_FALSE(ec);
    REQUIRE_FALSE(client.conn.failure());
    std::array<std::byte, 8> bogus{};
    bogus[0] = std::byte{0xff};
    bogus[1] = std::byte{0xff};
    bogus[2] = std::byte{0xff};
    bogus[3] = std::byte{0xff};
    n = 0;
    ec = client.conn.feed(bogus, n);
    REQUIRE(client.conn.failure() == code::packet_too_large);
    REQUIRE(ec == code::packet_too_large);
    REQUIRE_FALSE(client.conn.failure_detail().empty());
}

TEST_CASE("malformed kex reply records failure_detail", "[connection][handshake]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    feed_consume(client, server);
    feed_consume(server, client);
    REQUIRE(client.conn.negotiated() != nullptr);

    const std::byte payload[]{std::byte{static_cast<std::uint8_t>(wire::msg::kex_ecdh_reply)}};
    const auto pkt = plaintext_packet(p, payload);
    std::size_t n = 0;
    auto ec = client.conn.feed(pkt, n);
    REQUIRE(client.conn.failure() == code::invalid_kex_reply);
    REQUIRE(ec == code::invalid_kex_reply);
    REQUIRE_FALSE(client.conn.failure_detail().empty());
}

TEST_CASE("set_host_key copies private material; caller seed still signs after server dies",
          "[core][hostkey]") {
    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);
    {
        auto server = make_server(p);
        REQUIRE_FALSE(server.conn.set_host_key(hm.blob, hm.priv));
        REQUIRE_FALSE(server.conn.set_host_key(hm.blob, hm.priv));
    }
    crypto::signing_key key = p.new_signing_key(hm.priv);
    REQUIRE(static_cast<bool>(key));
    const std::byte msg[4]{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    std::array<std::byte, crypto::max_signature_size> sig{};
    std::size_t n = 0;
    REQUIRE(key.sign(std::span<const std::byte>{msg}, sig, n));
    REQUIRE(n > 0);
}
