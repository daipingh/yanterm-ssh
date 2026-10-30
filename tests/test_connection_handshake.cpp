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
#include "scripted_peer.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <optional>
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
    const std::string_view default_kex = p.supports(crypto::kex_id::mlkem768x25519)
                                             ? "mlkem768x25519-sha256"
                                             : "curve25519-sha256";
    REQUIRE(cap.client_kex_name == default_kex);
    REQUIRE(cap.server_kex_name == default_kex);
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
        }
        // NEWKEYS and EXT_INFO are in this flight. SERVICE_ACCEPT is not: the
        // server emits it only after the client's SERVICE_REQUEST.
        REQUIRE(handshake == events.end());
        REQUIRE_FALSE(client.session_id().empty());
        REQUIRE_FALSE(client.server_sig_algs().empty());

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
    REQUIRE(server_sig_algs == kex::default_host_key_algorithms(p));
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
    REQUIRE(client.conn.failure() == code::invalid_packet_length);
    REQUIRE(ec == code::invalid_packet_length);
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

TEST_CASE("fatal key exchange errors send disconnect to the peer",
          "[connection][handshake][kex]") {
    enum class scenario {
        negotiate_no_common_kex,
        strict_kex_before_kexinit,
        strict_kex_during_initial_kex,
        unexpected_message_during_initial_kex,
        unrecognized_message_during_strict_initial_kex,
        server_invalid_kex_init,
        client_invalid_kex_reply,
        client_resolve_accept_invalid_reply,
        rekey_host_key_changed,
        bad_packet_length_during_initial_kex,
        malformed_ignore_during_initial_kex,
        malformed_debug_during_initial_kex,
    };

    struct case_t {
        std::string_view name;
        scenario kind;
        bool client_fails;
        code expected_failure;
        wire::disconnect_reason expected_reason;
    };

    constexpr auto kex_failed = wire::disconnect_reason::key_exchange_failed;
    constexpr auto protocol_error = wire::disconnect_reason::protocol_error;
    const case_t cases[] = {
        {"negotiate_no_common_kex", scenario::negotiate_no_common_kex, false,
         code::no_common_kex_algorithm, kex_failed},
        {"strict_kex_before_kexinit", scenario::strict_kex_before_kexinit, true,
         code::strict_kex_violation, protocol_error},
        {"strict_kex_during_initial_kex", scenario::strict_kex_during_initial_kex, true,
         code::strict_kex_violation, protocol_error},
        {"unexpected_message_during_initial_kex", scenario::unexpected_message_during_initial_kex,
         true, code::unexpected_message, protocol_error},
        {"unrecognized_message_during_strict_initial_kex",
         scenario::unrecognized_message_during_strict_initial_kex, true, code::strict_kex_violation,
         protocol_error},
        {"server_invalid_kex_init", scenario::server_invalid_kex_init, false,
         code::invalid_kex_reply, kex_failed},
        {"client_invalid_kex_reply", scenario::client_invalid_kex_reply, true,
         code::invalid_kex_reply, kex_failed},
        {"client_resolve_accept_invalid_reply", scenario::client_resolve_accept_invalid_reply, true,
         code::invalid_kex_reply, kex_failed},
        {"bad_packet_length_during_initial_kex", scenario::bad_packet_length_during_initial_kex,
         true, code::invalid_packet_length, protocol_error},
        {"malformed_ignore_during_initial_kex", scenario::malformed_ignore_during_initial_kex,
         true, code::invalid_format, protocol_error},
        {"malformed_debug_during_initial_kex", scenario::malformed_debug_during_initial_kex,
         true, code::invalid_format, protocol_error},
    };

    crypto::provider p = prov();
    auto hm = make_ed25519_host(p);

    for (const auto& c : cases) {
        INFO(c.name);
        core::config client_cfg;
        core::config server_cfg;
        if (c.kind == scenario::negotiate_no_common_kex) {
            client_cfg.preferred_kex = "curve25519-sha256";
            server_cfg.preferred_kex = "diffie-hellman-group14-sha256";
        } else if (c.kind == scenario::malformed_ignore_during_initial_kex
                   || c.kind == scenario::malformed_debug_during_initial_kex) {
            // Strict KEX would reject any IGNORE/DEBUG before decoding it.
            client_cfg.advertise_strict_kex = false;
        }

        auto client = make_client(p, client_cfg);
        auto server = make_server(p, server_cfg);
        configure_server(server, hm);

        auto exchange_banners_only = [&]() {
            const auto cb = collect_output(client.conn);
            const auto sb = collect_output(server.conn);
            client.conn.consume_output(cb.size());
            server.conn.consume_output(sb.size());
            std::error_code ec;
            REQUIRE(feed_all(server.conn, cb, ec) == cb.size());
            REQUIRE_FALSE(ec);
            REQUIRE(feed_all(client.conn, sb, ec) == sb.size());
            REQUIRE_FALSE(ec);
        };

        auto reach_initial_kex_exchange = [&]() {
            exchange_banners_only();
            const auto ck = collect_output(client.conn);
            const auto sk = collect_output(server.conn);
            client.conn.consume_output(ck.size());
            server.conn.consume_output(sk.size());
            std::error_code ec;
            REQUIRE(feed_all(server.conn, ck, ec) == ck.size());
            REQUIRE_FALSE(ec);
            REQUIRE(feed_all(client.conn, sk, ec) == sk.size());
            REQUIRE_FALSE(ec);
            REQUIRE(client.conn.negotiated() != nullptr);
            REQUIRE(server.conn.negotiated() != nullptr);
            client.conn.consume_output(client.conn.pending_output_bytes());
            REQUIRE(client.conn.pending_output_bytes() == 0);
            REQUIRE(server.conn.pending_output_bytes() == 0);
        };

        std::error_code trigger_ec;
        switch (c.kind) {
            case scenario::negotiate_no_common_kex: {
                exchange_banners_only();
                server.conn.consume_output(server.conn.pending_output_bytes());
                const auto ck = collect_output(client.conn);
                client.conn.consume_output(ck.size());
                std::size_t n = 0;
                trigger_ec = server.conn.feed(ck, n);
                break;
            }
            case scenario::strict_kex_before_kexinit: {
                exchange_banners_only();
                client.conn.consume_output(client.conn.pending_output_bytes());
                server.conn.consume_output(server.conn.pending_output_bytes());
                wire::detail::service_msg svc{wire::msg::service_request, "ssh-userauth"};
                wire::writer w;
                svc.encode(w);
                const auto pkt = plaintext_packet(p, w.data());
                std::size_t n = 0;
                trigger_ec = client.conn.feed(pkt, n);
                break;
            }
            case scenario::strict_kex_during_initial_kex: {
                reach_initial_kex_exchange();
                wire::detail::ignore_msg ig{};
                wire::writer w;
                ig.encode(w);
                const auto pkt = plaintext_packet(p, w.data());
                std::size_t n = 0;
                trigger_ec = client.conn.feed(pkt, n);
                break;
            }
            case scenario::unexpected_message_during_initial_kex: {
                reach_initial_kex_exchange();
                wire::detail::service_msg svc{wire::msg::service_accept, "ssh-userauth"};
                wire::writer w;
                svc.encode(w);
                const auto pkt = plaintext_packet(p, w.data());
                std::size_t n = 0;
                trigger_ec = client.conn.feed(pkt, n);
                break;
            }
            case scenario::unrecognized_message_during_strict_initial_kex: {
                reach_initial_kex_exchange();
                const std::byte payload[]{std::byte{200}};
                const auto pkt = plaintext_packet(p, payload);
                std::size_t n = 0;
                trigger_ec = client.conn.feed(pkt, n);
                break;
            }
            case scenario::server_invalid_kex_init: {
                reach_initial_kex_exchange();
                const std::byte payload[]{
                    std::byte{static_cast<std::uint8_t>(wire::msg::kex_ecdh_init)}};
                const auto pkt = plaintext_packet(p, payload);
                std::size_t n = 0;
                trigger_ec = server.conn.feed(pkt, n);
                break;
            }
            case scenario::client_invalid_kex_reply: {
                reach_initial_kex_exchange();
                const std::byte payload[]{
                    std::byte{static_cast<std::uint8_t>(wire::msg::kex_ecdh_reply)}};
                const auto pkt = plaintext_packet(p, payload);
                std::size_t n = 0;
                trigger_ec = client.conn.feed(pkt, n);
                break;
            }
            case scenario::client_resolve_accept_invalid_reply: {
                reach_initial_kex_exchange();
                wire::detail::kex_ecdh_reply reply{};
                reply.host_key = hm.blob;
                wire::writer w;
                reply.encode(w);
                const auto pkt = plaintext_packet(p, w.data());
                std::size_t n = 0;
                REQUIRE_FALSE(client.conn.feed(pkt, n));
                core::host_key_ticket ticket{};
                for (const auto& ev : client.handler.events) {
                    if (const auto* hk =
                            std::get_if<recording_handler::verify_host_key>(&ev)) {
                        ticket = hk->ticket;
                    }
                }
                REQUIRE(ticket != core::host_key_ticket{});
                trigger_ec = client.conn.resolve(ticket, core::host_key_verdict::accept);
                break;
            }
            case scenario::rekey_host_key_changed: {
                handshake_capture cap;
                REQUIRE(run_handshake(client, server, cap));
                client.conn.consume_output(client.conn.pending_output_bytes());
                server.conn.consume_output(server.conn.pending_output_bytes());
                keys::private_key alt_sk;
                REQUIRE_FALSE(
                    keys::private_key::generate(p, crypto::sig_id::ed25519, 0, "alt", alt_sk));
                REQUIRE_FALSE(server.conn.rekey());
                REQUIRE_FALSE(server.conn.set_host_key(alt_sk.pub().blob(), alt_sk.material()));
                feed_consume(server.conn, client.conn);
                feed_consume(client.conn, server.conn);
                const auto srv_reply = collect_output(server.conn);
                server.conn.consume_output(srv_reply.size());
                std::size_t n = 0;
                trigger_ec = client.conn.feed(srv_reply, n);
                break;
            }
            case scenario::bad_packet_length_during_initial_kex: {
                reach_initial_kex_exchange();
                std::array<std::byte, 8> bogus;
                bogus.fill(std::byte{0xff});
                std::size_t n = 0;
                trigger_ec = client.conn.feed(bogus, n);
                break;
            }
            case scenario::malformed_ignore_during_initial_kex:
            case scenario::malformed_debug_during_initial_kex: {
                reach_initial_kex_exchange();
                const auto id = c.kind == scenario::malformed_ignore_during_initial_kex
                                    ? wire::msg::ignore
                                    : wire::msg::debug;
                const std::byte payload[]{std::byte{static_cast<std::uint8_t>(id)}};
                const auto pkt = plaintext_packet(p, payload);
                std::size_t n = 0;
                trigger_ec = client.conn.feed(pkt, n);
                break;
            }
        }

        wired_connection& failing = c.client_fails ? client : server;
        wired_connection& peer = c.client_fails ? server : client;

        REQUIRE(trigger_ec == c.expected_failure);
        REQUIRE(failing.conn.failure() == c.expected_failure);
        REQUIRE(failing.conn.pending_output_bytes() > 0);

        peer.handler.events.clear();
        const auto disconnect_bytes = collect_output(failing.conn);
        std::error_code peer_ec;
        const std::size_t accepted = feed_all(peer.conn, disconnect_bytes, peer_ec);
        failing.conn.consume_output(accepted);
        REQUIRE(accepted == disconnect_bytes.size());
        REQUIRE_FALSE(peer_ec);
        REQUIRE(peer.conn.failure() == code::peer_disconnected);

        const recording_handler::disconnected* got_disc = nullptr;
        for (const auto& ev : peer.handler.events) {
            if (const auto* d = std::get_if<recording_handler::disconnected>(&ev)) {
                got_disc = d;
            }
        }
        REQUIRE(got_disc != nullptr);
        REQUIRE(got_disc->reason == c.expected_reason);
        REQUIRE_FALSE(got_disc->description.empty());
    }
}

// RFC 4253 §11.4: an unrecognized message number is answered with
// UNIMPLEMENTED carrying its sequence number and is otherwise ignored.
TEST_CASE("unrecognized messages are answered with UNIMPLEMENTED", "[connection][transport]") {
    struct case_t {
        std::string_view name;
        core::role role;
        bool service_ready;
        std::uint8_t id;
    };
    const case_t cases[] = {
        {"client before userauth service", core::role::client, false, 62},
        {"server before userauth service", core::role::server, false, 101},
        {"server, unassigned connection number", core::role::server, true, 83},
        {"client, client protocol range", core::role::client, true, 128},
        {"server, local extension range", core::role::server, true, 200},
    };

    for (const auto& c : cases) {
        INFO(c.name);
        peer_session s{c.role};
        if (c.service_ready) {
            s.handshake();
        } else {
            s.exchange_keys();
        }
        s.peer.clear_received();

        const std::uint32_t seq = s.peer.next_send_sequence();
        const std::byte payload[]{std::byte{c.id}, std::byte{0x2a}};
        s.peer.send(payload);
        REQUIRE_FALSE(s.peer.exchange(s.sut));
        REQUIRE_FALSE(s.sut.conn.failure());

        const auto reply = s.peer.take(wire::msg::unimplemented);
        REQUIRE(reply);
        wire::reader r{*reply};
        wire::detail::unimplemented_msg msg;
        REQUIRE(msg.decode(r));
        REQUIRE(r.empty());
        REQUIRE(msg.sequence_number == seq);
    }
}

// A known message in the wrong state, or one that does not decode, is a
// protocol error rather than an unrecognized message.
TEST_CASE("misplaced or malformed upper-layer messages disconnect with PROTOCOL_ERROR",
          "[connection][transport]") {
    enum class stage { keys, service, authenticated };
    struct case_t {
        std::string_view name;
        core::role role;
        stage at;
        std::vector<std::byte> payload;
        code expected;
    };
    auto build = [](wire::msg id, auto&& fill) {
        wire::writer w;
        w.write_byte(static_cast<std::uint8_t>(id));
        fill(w);
        return std::vector<std::byte>(w.data().begin(), w.data().end());
    };
    auto nothing = [](wire::writer&) {};
    const case_t cases[] = {
        {"client receives SERVICE_REQUEST", core::role::client, stage::keys,
         build(wire::msg::service_request, [](wire::writer& w) { w.write_string("ssh-userauth"); }),
         code::unexpected_message},
        {"client receives USERAUTH_REQUEST", core::role::client, stage::service,
         build(wire::msg::userauth_request,
               [](wire::writer& w) {
                   w.write_string("alice");
                   w.write_string("ssh-connection");
                   w.write_string("none");
               }),
         code::unexpected_message},
        {"server receives USERAUTH_SUCCESS", core::role::server, stage::service,
         build(wire::msg::userauth_success, nothing), code::unexpected_message},
        {"client receives USERAUTH_FAILURE with no request pending", core::role::client,
         stage::service,
         build(wire::msg::userauth_failure,
               [](wire::writer& w) {
                   w.write_string("password");
                   w.write_bool(false);
               }),
         code::unexpected_message},
        {"server receives truncated USERAUTH_REQUEST", core::role::server, stage::service,
         build(wire::msg::userauth_request, nothing), code::invalid_format},
        {"CHANNEL_DATA for an unknown channel", core::role::client, stage::authenticated,
         build(wire::msg::channel_data,
               [](wire::writer& w) {
                   w.write_uint32(7);
                   w.write_string("x");
               }),
         code::unexpected_message},
        {"REQUEST_SUCCESS with no global request pending", core::role::server,
         stage::authenticated, build(wire::msg::request_success, nothing),
         code::unexpected_message},
        {"truncated CHANNEL_WINDOW_ADJUST", core::role::client, stage::authenticated,
         build(wire::msg::channel_window_adjust, nothing), code::invalid_format},
    };

    for (const auto& c : cases) {
        INFO(c.name);
        peer_session s{c.role};
        switch (c.at) {
        case stage::keys: s.exchange_keys(); break;
        case stage::service: s.handshake(); break;
        case stage::authenticated: s.authenticate(); break;
        }
        s.peer.clear_received();

        s.peer.send(c.payload);
        REQUIRE(s.peer.exchange(s.sut) == c.expected);
        REQUIRE(s.sut.conn.failure() == c.expected);

        const auto disc = s.peer.take(wire::msg::disconnect);
        REQUIRE(disc);
        wire::reader r{*disc};
        wire::detail::disconnect_msg msg;
        REQUIRE(msg.decode(r));
        REQUIRE(msg.reason == wire::disconnect_reason::protocol_error);
        REQUIRE_FALSE(s.peer.take(wire::msg::unimplemented));
    }
}

// Framing and authentication failures must look the same on the wire;
// distinct replies would be a padding/MAC oracle.
TEST_CASE("binary packet errors all disconnect with one PROTOCOL_ERROR message",
          "[connection][transport]") {
    enum class corrupt { packet_length, padding, gcm_tag };
    struct case_t {
        std::string_view name;
        corrupt kind;
        code expected;
    };
    const case_t cases[] = {
        {"plaintext packet_length above the maximum", corrupt::packet_length, code::invalid_packet_length},
        {"plaintext padding_length below the minimum", corrupt::padding, code::invalid_padding},
        {"aes256-gcm tag mismatch", corrupt::gcm_tag, code::decrypt_failure},
    };

    std::optional<std::string> description;
    for (const auto& c : cases) {
        INFO(c.name);
        peer_session s{core::role::client};

        std::vector<std::byte> bytes;
        if (c.kind == corrupt::gcm_tag) {
            s.exchange_keys();
            s.peer.clear_received();
            const std::byte ignore[]{std::byte{static_cast<std::uint8_t>(wire::msg::ignore)},
                                     std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}};
            s.peer.send(ignore);
            bytes = s.peer.take_pending();
            REQUIRE_FALSE(bytes.empty());
            bytes.back() ^= std::byte{0x01};
        } else {
            // The corrupt packet takes the place of the peer's KEXINIT.
            const auto pending = s.peer.take_pending();
            const auto eol = std::find(pending.begin(), pending.end(), std::byte{'\n'});
            REQUIRE(eol != pending.end());
            bytes.assign(pending.begin(), eol + 1);
            if (c.kind == corrupt::packet_length) {
                bytes.insert(bytes.end(), 4, std::byte{0xff});
            } else {
                // packet_length 12, padding_length 3, 8 payload bytes, 3 padding bytes.
                const std::byte header[]{std::byte{0}, std::byte{0}, std::byte{0}, std::byte{12},
                                         std::byte{3}};
                bytes.insert(bytes.end(), std::begin(header), std::end(header));
                bytes.insert(bytes.end(), 8, std::byte{0x11});
                bytes.insert(bytes.end(), 3, std::byte{0x22});
            }
        }

        std::size_t accepted = 0;
        REQUIRE(s.sut.conn.feed(bytes, accepted) == c.expected);
        REQUIRE(s.sut.conn.failure() == c.expected);

        s.peer.collect(s.sut);
        const auto disc = s.peer.take(wire::msg::disconnect);
        REQUIRE(disc);
        wire::reader r{*disc};
        wire::detail::disconnect_msg msg;
        REQUIRE(msg.decode(r));
        REQUIRE(msg.reason == wire::disconnect_reason::protocol_error);
        if (!description) description.emplace(msg.description);
        REQUIRE(msg.description == *description);
    }
}
