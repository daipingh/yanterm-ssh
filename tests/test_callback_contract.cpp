#include <catch2/catch_test_macros.hpp>
#include "channel_test_helpers.hpp"
#include "drive.hpp"
#include "legacy_loopback_event.hpp"
#include "fixed_random_provider.hpp"
#include "handshake_fixture.hpp"

#include <yanterm-ssh/auth/types.hpp>
#include <yanterm-ssh/channels/requests.hpp>
#include <yanterm-ssh/detail/error.hpp>
#include <yanterm-ssh/wire/message_ids.hpp>
#include <yanterm-ssh/wire/types.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

namespace {

class inline_resolve_handler : public recording_handler {
public:
    explicit inline_resolve_handler(bool resolve_inline) : resolve_inline_{resolve_inline} {}

    void on_global_request(core::connection& c, core::global_request_ticket ticket,
                           const channels::request_view& request) override {
        recording_handler::on_global_request(c, ticket, request);
        if (resolve_inline_ && request.want_reply) {
            const std::byte pay{0x01};
            c.resolve(ticket, true, std::span<const std::byte>{&pay, 1});
        }
    }

    void on_channel_request(core::connection& c, core::channel_request_ticket ticket, void* user,
                            const channels::request_view& request) override {
        recording_handler::on_channel_request(c, ticket, user, request);
        if (resolve_inline_) c.resolve(ticket, true);
    }

private:
    bool resolve_inline_;
};

void bring_up_authed_conn(wired_connection& client, core::connection& server,
                          recording_handler& server_handler,
                          host_material& hm) {
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_loopback(
        client.conn, client.handler, server, server_handler, &client, nullptr,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (is_client) accept_client_host_key(client, ev);
        }));
    REQUIRE_FALSE(client.conn.auth_password("alice", "s3cret"));
    REQUIRE(run_loopback(
        client.conn, client.handler, server, server_handler, &client, nullptr,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (const auto* req = std::get_if<recording_handler::auth_request>(&ev)) {
                if (!is_client) server.resolve(req->ticket, auth::auth_verdict::success());
            }
        }));
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.failure());
}

template <class T>
std::vector<const T*> all_of(const std::vector<recording_handler::recorded_event>& evs) {
    std::vector<const T*> out;
    for (const auto& ev : evs) {
        if (const auto* p = std::get_if<T>(&ev)) out.push_back(p);
    }
    return out;
}

std::size_t count_released(const std::vector<recording_handler::recorded_event>& evs) {
    std::size_t n = 0;
    for (const auto& ev : evs) {
        if (std::holds_alternative<recording_handler::channel_released>(ev)) ++n;
    }
    return n;
}

struct reply_outcomes {
    std::vector<std::byte> server_suffix;
    std::byte global_payload{};
    bool channel_success = false;
};

reply_outcomes server_reply(bool resolve_inline) {
    fixed_random_provider client_random{prov(), 0x12345678};
    fixed_random_provider server_random{prov(), 0x87654321};
    const auto client_p = client_random.get();
    const auto server_p = server_random.get();
    auto hm = make_ed25519_host(server_p);
    auto client = make_client(client_p);
    inline_resolve_handler server_handler{resolve_inline};
    core::connection server{core::role::server, server_p, {}, server_handler};
    bring_up_authed_conn(client, server, server_handler, hm);

    core::channel_ref cid{};
    REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, cid));
    bool opened = false;
    REQUIRE(run_loopback(
        client.conn, client.handler, server, server_handler, &client, nullptr,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (!is_client) {
                if (const auto* o =
                        std::get_if<recording_handler::channel_open_request>(&ev)) {
                    server.resolve(o->ticket, channels::channel_open_verdict::accepted());
                }
            }
            if (is_client) {
                if (std::holds_alternative<recording_handler::channel_opened>(ev)) {
                    opened = true;
                }
            }
        }));
    REQUIRE(opened);

    wire::writer gw;
    channels::encode_tcpip_forward(gw, "127.0.0.1", 0);
    REQUIRE_FALSE(client.conn.send_global_request("tcpip-forward", gw.data(), true));
    REQUIRE_FALSE(client.conn.request_env(cid, "K", "V"));

    const auto mark = collect_output(server);

    const auto resolve_pending = [&]() {
        const auto globals =
            all_of<recording_handler::global_request>(server_handler.events);
        if (!globals.empty()) {
            const std::byte pay{0x01};
            server.resolve(globals[0]->ticket, true, std::span<const std::byte>{&pay, 1});
        }
        const auto reqs = all_of<recording_handler::channel_request>(server_handler.events);
        if (!reqs.empty()) server.resolve(reqs[0]->ticket, true);
    };

    const auto batch = std::vector<std::byte>(client.conn.pending_output0().begin(),
                                              client.conn.pending_output0().end());
    REQUIRE_FALSE(batch.empty());
    client.conn.consume_output(batch.size());

    std::size_t n = 0;
    REQUIRE_FALSE(server.feed(batch, n));
    REQUIRE(n == batch.size());
    if (!resolve_inline) resolve_pending();
    transfer_all(client.conn, server);

    const auto now = collect_output(server);
    REQUIRE(now.size() >= mark.size());
    reply_outcomes out;
    out.server_suffix = std::vector<std::byte>(
        now.begin() + static_cast<std::ptrdiff_t>(mark.size()), now.end());
    transfer_all(server, client.conn);
    for (const auto& ev : client.handler.events) {
        if (const auto* g = std::get_if<recording_handler::global_response>(&ev)) {
            REQUIRE(g->success);
            REQUIRE(g->payload.size() == 1);
            out.global_payload = g->payload[0];
        }
        if (const auto* c = std::get_if<recording_handler::channel_response>(&ev)) {
            out.channel_success = c->success;
        }
    }
    REQUIRE(out.channel_success);
    return out;
}

}  // namespace

TEST_CASE("inbound channel requests settle only at queue head", "[callback]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    for (int i = 0; i < 3; ++i) {
        REQUIRE_FALSE(client.conn.request_env(ids.client_ch, "K", std::to_string(i)));
    }
    const auto out = client.conn.pending_output0();
    REQUIRE_FALSE(out.empty());
    std::vector<std::byte> batch(out.begin(), out.end());
    std::size_t n = 0;
    REQUIRE_FALSE(server.conn.feed(batch, n));
    REQUIRE(n == batch.size());
    client.conn.consume_output(n);

    const auto reqs = all_of<recording_handler::channel_request>(server.handler.events);
    REQUIRE(reqs.size() == 3);
    REQUIRE(reqs[0]->seq == 1);
    REQUIRE(reqs[1]->seq == 2);
    REQUIRE(reqs[2]->seq == 3);
    const core::channel_request_ticket ticket0 = reqs[0]->ticket;
    const core::channel_request_ticket ticket1 = reqs[1]->ticket;
    const core::channel_request_ticket ticket2 = reqs[2]->ticket;

    const auto before = server.conn.pending_output_bytes();
    REQUIRE(server.conn.resolve(ticket1, true) == code::invalid_state);
    REQUIRE(server.conn.resolve(ticket2, true) == code::invalid_state);
    REQUIRE(server.conn.pending_output_bytes() == before);
    REQUIRE_FALSE(server.conn.failure());

    REQUIRE_FALSE(server.conn.resolve(ticket0, true));
    REQUIRE_FALSE(server.conn.resolve(ticket1, true));
    REQUIRE_FALSE(server.conn.resolve(ticket2, true));

    std::vector<recording_handler::recorded_event> cap;
    transfer_all_capture(server, client, cap);
    const auto replies = all_of<recording_handler::channel_response>(cap);
    REQUIRE(replies.size() == 3);
    REQUIRE(replies[0]->success);
    REQUIRE(replies[1]->success);
    REQUIRE(replies[2]->success);

    REQUIRE_FALSE(client.conn.channel_close(ids.client_ch));
    transfer_all(client, server);
    REQUIRE(server.conn.resolve(ticket1, true) == code::invalid_state);
    REQUIRE(server.conn.resolve(ticket2, true) == code::invalid_state);

    const auto stale_ref = ids.server_ch;
    const auto stale_ticket = ticket0;
    REQUIRE(server.conn.resolve(stale_ticket, true) == code::invalid_state);
    REQUIRE(server.conn.request_env(stale_ref, "K", "V") == code::invalid_state);
    const auto ids2 = open_session(client, server);
    REQUIRE_FALSE(client.conn.request_env(ids2.client_ch, "K", "after"));
    transfer_all(client, server);
    const auto fresh = all_of<recording_handler::channel_request>(server.handler.events);
    REQUIRE(fresh.size() == 1);
    REQUIRE_FALSE(server.conn.resolve(fresh[0]->ticket, true));
}

TEST_CASE("global requests use head sequencing and seq zero without reply", "[callback]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);

    wire::writer w1;
    channels::encode_tcpip_forward(w1, "127.0.0.1", 0);
    wire::writer w2;
    channels::encode_tcpip_forward(w2, "127.0.0.2", 0);
    REQUIRE_FALSE(client.conn.send_global_request("tcpip-forward", w1.data(), true));
    REQUIRE_FALSE(client.conn.send_global_request("tcpip-forward", w2.data(), true));
    wire::writer w0;
    channels::encode_tcpip_forward(w0, "127.0.0.3", 0);
    REQUIRE_FALSE(client.conn.send_global_request("tcpip-forward", w0.data(), false));

    std::vector<recording_handler::recorded_event> cap;
    transfer_all_capture(client, server, cap);
    const auto globals = all_of<recording_handler::global_request>(cap);
    REQUIRE(globals.size() == 3);
    REQUIRE_FALSE(globals[2]->want_reply);
    REQUIRE(globals[2]->seq == 0);

    const auto before = server.conn.pending_output_bytes();
    const std::byte pay2{0x02};
    const std::byte pay1{0x01};
    REQUIRE(server.conn.resolve(globals[1]->ticket, true, std::span<const std::byte>{&pay2, 1})
            == code::invalid_state);
    REQUIRE(server.conn.pending_output_bytes() == before);

    REQUIRE_FALSE(server.conn.resolve(globals[0]->ticket, true, std::span<const std::byte>{&pay1, 1}));
    REQUIRE_FALSE(server.conn.resolve(globals[1]->ticket, true, std::span<const std::byte>{&pay2, 1}));
    REQUIRE_FALSE(server.conn.resolve(globals[2]->ticket, true));

    transfer_all_capture(server, client, cap);
    const auto replies = all_of<recording_handler::global_response>(cap);
    REQUIRE(replies.size() == 2);
    REQUIRE(replies[0]->payload[0] == std::byte{0x01});
    REQUIRE(replies[1]->payload[0] == std::byte{0x02});
}

TEST_CASE("dead connection resolve emits no inbound replies", "[callback]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    bring_up_authed(client, server, hm);
    const auto ids = open_session(client, server);

    REQUIRE_FALSE(client.conn.request_env(ids.client_ch, "K", "V"));
    wire::writer gw;
    channels::encode_tcpip_forward(gw, "127.0.0.1", 0);
    REQUIRE_FALSE(client.conn.send_global_request("tcpip-forward", gw.data(), true));

    std::vector<recording_handler::recorded_event> cap;
    transfer_all_capture(client, server, cap);
    const auto reqs = all_of<recording_handler::channel_request>(cap);
    const auto globals = all_of<recording_handler::global_request>(cap);
    REQUIRE(reqs.size() == 1);
    REQUIRE(globals.size() == 1);
    REQUIRE(reqs[0]->want_reply);
    REQUIRE(globals[0]->want_reply);

    REQUIRE_FALSE(server.conn.disconnect(wire::disconnect_reason::by_application, "bye"));
    REQUIRE_FALSE(server.conn.failure());
    const auto before = server.conn.pending_output_bytes();
    REQUIRE(server.conn.resolve(reqs[0]->ticket, false) == code::invalid_state);
    REQUIRE(server.conn.resolve(globals[0]->ticket, false) == code::invalid_state);
    REQUIRE(server.conn.pending_output_bytes() == before);
}

TEST_CASE("on_released fires exactly once on each release path", "[callback]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);

    {
        auto client = make_client(p);
        auto server = make_server(p);
        bring_up_authed(client, server, hm);
        core::channel_ref cid{};
        REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, cid));
        std::vector<recording_handler::recorded_event> cap;
        transfer_all_capture(client, server, cap);
        const auto opens = all_of<recording_handler::channel_open_request>(cap);
        REQUIRE(opens.size() == 1);
        server.conn.resolve(opens[0]->ticket, channels::channel_open_verdict::rejected(
                                  channels::channel_open_reason::connect_failed, "no"));
        append_recorded(server, cap);
        REQUIRE(count_released(cap) == 1);
    }

    {
        auto client = make_client(p);
        auto server = make_server(p);
        bring_up_authed(client, server, hm);
        core::channel_ref ref{};
        REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, ref));
        std::vector<recording_handler::recorded_event> cap;
        transfer_all_capture(client, server, cap);
        const auto opens = all_of<recording_handler::channel_open_request>(cap);
        REQUIRE(opens.size() == 1);
        server.conn.resolve(opens[0]->ticket, channels::channel_open_verdict::rejected(
                                  channels::channel_open_reason::connect_failed, "fail"));
        cap.clear();
        transfer_all_capture(server, client, cap);
        REQUIRE(count_released(cap) == 1);
        REQUIRE(all_of<recording_handler::channel_open_failed>(cap).size() == 1);
        REQUIRE(std::none_of(cap.begin(), cap.end(), [](const auto& ev) {
            return std::holds_alternative<recording_handler::channel_opened>(ev);
        }));
    }

    {
        auto client = make_client(p);
        auto server = make_server(p);
        bring_up_authed(client, server, hm);
        core::channel_ref ref{};
        REQUIRE_FALSE(client.conn.open_channel(channels::channel_open_spec{}, nullptr, ref));
        REQUIRE_FALSE(client.conn.abandon_open(ref));
        std::vector<recording_handler::recorded_event> cap;
        transfer_all_capture(client, server, cap);
        const auto opens = all_of<recording_handler::channel_open_request>(cap);
        REQUIRE(opens.size() == 1);
        server.conn.resolve(opens[0]->ticket, channels::channel_open_verdict::accepted());
        cap.clear();
        for (int i = 0; i < 64; ++i) {
            transfer_all_capture(server, client, cap);
            transfer_all_capture(client, server, cap);
            if (count_released(cap) >= 1) break;
        }
        REQUIRE(count_released(cap) == 1);
        REQUIRE(std::none_of(cap.begin(), cap.end(), [](const auto& ev) {
            return std::holds_alternative<recording_handler::channel_opened>(ev)
                   || std::holds_alternative<recording_handler::channel_open_failed>(ev);
        }));
    }

    {
        auto client = make_client(p);
        auto server = make_server(p);
        bring_up_authed(client, server, hm);
        const auto ids = open_session(client, server);
        REQUIRE_FALSE(client.conn.channel_close(ids.client_ch));
        std::vector<recording_handler::recorded_event> cap;
        transfer_all_capture(client, server, cap);
        REQUIRE(count_released(cap) == 1);
    }
}

TEST_CASE("server wire bytes match for inline and deferred resolve", "[callback]") {
    const auto a = server_reply(true);
    const auto b = server_reply(false);
    REQUIRE(a.global_payload == b.global_payload);
    REQUIRE(a.channel_success == b.channel_success);
    REQUIRE(a.global_payload == std::byte{0x01});
    REQUIRE_FALSE(a.server_suffix.empty());
    REQUIRE_FALSE(b.server_suffix.empty());
    REQUIRE(a.server_suffix == b.server_suffix);
}

// Moves every complete unit from `from` into `to`. Stops when `to` stalls so the
// packet that paused feed stays consumed and the rest remains on `from`.
bool deliver_output(core::connection& from, core::connection& to) {
    bool any = false;
    while (!from.pending_output0().empty()) {
        const auto out = from.pending_output0();
        std::size_t n = 0;
        REQUIRE_FALSE(to.feed(out, n));
        if (n == 0) break;
        from.consume_output(n);
        any = true;
    }
    return any;
}

std::vector<std::byte> output_after(const std::vector<std::byte>& before,
                                   const std::vector<std::byte>& now) {
    REQUIRE(now.size() >= before.size());
    return std::vector<std::byte>(now.begin() + static_cast<std::ptrdiff_t>(before.size()),
                                  now.end());
}

std::vector<std::byte> client_handshake_output(bool inline_accept) {
    fixed_random_provider client_random{prov(), 0x12345678};
    fixed_random_provider server_random{prov(), 0x87654321};
    auto hm = make_ed25519_host(server_random.get());
    recording_handler delayed;
    struct accepting_handler : recording_handler {
        bool accepted = false;
        void on_host_key(core::connection& c, core::host_key_ticket ticket,
                         std::span<const std::byte> blob) override {
            recording_handler::on_host_key(c, ticket, blob);
            REQUIRE_FALSE(c.resolve(ticket, core::host_key_verdict::accept));
            accepted = true;
        }
    } immediate;
    recording_handler& client_handler = inline_accept ? immediate : delayed;
    core::connection client{core::role::client, client_random.get(), {}, client_handler};
    recording_handler server_handler;
    core::connection server{core::role::server, server_random.get(), {}, server_handler};
    configure_server(server, hm);

    bool accepted = false;
    bool client_done = false;
    auto drain_client = [&] {
        while (!client_handler.events.empty()) {
            auto ev = std::move(client_handler.events.front());
            client_handler.events.erase(client_handler.events.begin());
            if (std::holds_alternative<recording_handler::handshake_done>(ev)) {
                client_done = true;
            }
            if (const auto* host = std::get_if<recording_handler::verify_host_key>(&ev)) {
                if (!inline_accept) {
                    REQUIRE_FALSE(client.resolve(host->ticket, core::host_key_verdict::accept));
                }
                accepted = true;
            }
        }
        if (inline_accept && immediate.accepted) accepted = true;
    };

    std::vector<std::byte> measured;
    for (int round = 0; round < 64; ++round) {
        bool progress = false;
        // Bytes from before the host-key accept are delivered, not measured.
        if (!accepted && deliver_output(client, server)) {
            progress = true;
            server_handler.events.clear();
        }
        if (!server.pending_output0().empty()) {
            const auto out = server.pending_output0();
            std::size_t n = 0;
            REQUIRE_FALSE(client.feed(out, n));
            if (n > 0) {
                server.consume_output(n);
                progress = true;
            }
            drain_client();
        }
        if (accepted) {
            // Finish the server's NEWKEYS / EXT_INFO flight without consuming
            // the client bytes produced by accept.
            (void)deliver_output(server, client);
            drain_client();
            measured = collect_output(client);
            // SERVICE_ACCEPT is what completes the handshake; it is not part
            // of the bytes queued by resolve().
            if (!client_done && !measured.empty()) {
                REQUIRE(deliver_output(client, server));
                (void)deliver_output(server, client);
                drain_client();
            }
            break;
        }
        if (!progress) break;
    }
    REQUIRE(client_done);
    REQUIRE_FALSE(client.failure());
    return measured;
}

enum class auth_wire_scenario { password_success, password_failure, pk_ok, kbdint_info };

struct auth_server_handler : recording_handler {
    bool resolve_inline_ = false;
    auth_wire_scenario scenario_ = auth_wire_scenario::password_success;

    auth_server_handler(bool inline_resolve, auth_wire_scenario s)
        : resolve_inline_{inline_resolve}, scenario_{s} {}

    void on_auth_request(core::connection& c, core::auth_ticket ticket,
                         const auth::auth_request_view& request) override {
        recording_handler::on_auth_request(c, ticket, request);
        if (resolve_inline_) apply(c, ticket, request);
    }

    void apply(core::connection& c, core::auth_ticket ticket, const auth::auth_request_view& request) {
        switch (scenario_) {
        case auth_wire_scenario::password_success:
            REQUIRE(request.method == "password");
            REQUIRE_FALSE(c.resolve(ticket, auth::auth_verdict::success()));
            break;
        case auth_wire_scenario::password_failure:
            REQUIRE(request.method == "password");
            REQUIRE_FALSE(c.resolve(ticket, auth::auth_verdict::failure("password")));
            break;
        case auth_wire_scenario::pk_ok:
            REQUIRE(request.method == "publickey");
            REQUIRE_FALSE(request.has_signature);
            REQUIRE_FALSE(c.resolve(ticket, auth::auth_verdict::success()));
            break;
        case auth_wire_scenario::kbdint_info: {
            REQUIRE(request.method == "keyboard-interactive");
            const auth::kbdint_prompt prompts[] = {{"pw", false}};
            REQUIRE_FALSE(
                c.resolve(ticket, auth::auth_verdict::info("n", "i", std::span{prompts})));
            break;
        }
        }
    }
};

struct auth_server_bed {
    auth_server_handler handler;
    core::connection conn;

    auth_server_bed(crypto::provider p, bool inline_resolve, auth_wire_scenario scenario,
                    host_material& hm)
        : handler{inline_resolve, scenario}, conn{core::role::server, p, {}, handler} {
        configure_server(conn, hm);
    }
};

std::vector<std::byte> server_auth_output(bool resolve_inline, auth_wire_scenario scenario) {
    fixed_random_provider client_random{prov(), 0x11112222};
    fixed_random_provider server_random{prov(), 0x33334444};
    auto hm = make_ed25519_host(server_random.get());
    auto client = make_client(client_random.get());
    auth_server_bed server{server_random.get(), resolve_inline, scenario, hm};
    REQUIRE(run_loopback(
        client.conn, client.handler, server.conn, server.handler, &client, nullptr,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (is_client) accept_client_host_key(client, ev);
        }));
    if (scenario == auth_wire_scenario::pk_ok) {
        REQUIRE_FALSE(client.conn.auth_publickey_query("alice", hm.blob, "ssh-ed25519"));
    } else if (scenario == auth_wire_scenario::kbdint_info) {
        REQUIRE_FALSE(client.conn.auth_keyboard_interactive("alice"));
    } else {
        REQUIRE_FALSE(client.conn.auth_password("alice", "s3cret"));
    }
    const auto mark = collect_output(server.conn);
    const auto request = collect_output(client.conn);
    REQUIRE_FALSE(request.empty());
    client.conn.consume_output(request.size());
    std::size_t n = 0;
    REQUIRE_FALSE(server.conn.feed(request, n));
    REQUIRE(n == request.size());
    if (!resolve_inline) {
        const recording_handler::auth_request* pending = nullptr;
        for (const auto& ev : server.handler.events) {
            if (const auto* req = std::get_if<recording_handler::auth_request>(&ev)) {
                pending = req;
            }
        }
        REQUIRE(pending != nullptr);
        server.handler.apply(
            server.conn, pending->ticket,
            auth::auth_request_view{pending->user, pending->service, pending->method,
                                    pending->has_signature, pending->algorithm,
                                    pending->public_blob, pending->password, pending->submethods});
    }
    const auto now = collect_output(server.conn);
    return output_after(mark, now);
}

struct kbdint_wire_client_handler : recording_handler {
    bool resolve_inline_ = false;

    explicit kbdint_wire_client_handler(bool inline_resolve) : resolve_inline_{inline_resolve} {}

    void on_kbdint_request(core::connection& c, core::kbdint_ticket ticket,
                           const auth::info_request_view& request) override {
        recording_handler::on_kbdint_request(c, ticket, request);
        if (resolve_inline_) {
            const std::string_view answers[] = {"s3cret"};
            REQUIRE_FALSE(c.resolve(ticket, answers));
        }
    }
};

std::vector<std::byte> client_kbdint_output(bool inline_kbdint_resolve) {
    fixed_random_provider client_random{prov(), 0x11112222};
    fixed_random_provider server_random{prov(), 0x33334444};
    auto hm = make_ed25519_host(server_random.get());
    kbdint_wire_client_handler client_handler{inline_kbdint_resolve};
    core::connection client{core::role::client, client_random.get(), {}, client_handler};
    auth_server_bed server{server_random.get(), true, auth_wire_scenario::kbdint_info, hm};
    REQUIRE(run_loopback(
        client, client_handler, server.conn, server.handler, nullptr, nullptr,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (is_client) {
                if (const auto* host =
                        std::get_if<recording_handler::verify_host_key>(&ev)) {
                    REQUIRE_FALSE(client.resolve(host->ticket, core::host_key_verdict::accept));
                }
            }
        }));
    REQUIRE_FALSE(client.auth_keyboard_interactive("alice"));
    // USERAUTH_REQUEST is already queued; the info-response flight is what
    // this helper measures.
    REQUIRE(deliver_output(client, server.conn));
    server.handler.events.clear();
    client_handler.events.clear();

    const auto mark = collect_output(client);
    const auto info = collect_output(server.conn);
    REQUIRE_FALSE(info.empty());
    server.conn.consume_output(info.size());
    std::size_t n = 0;
    REQUIRE_FALSE(client.feed(info, n));
    REQUIRE(n == info.size());
    if (!inline_kbdint_resolve) {
        const recording_handler::auth_info_request* pending = nullptr;
        for (const auto& ev : client_handler.events) {
            if (const auto* info_ev =
                    std::get_if<recording_handler::auth_info_request>(&ev)) {
                pending = info_ev;
            }
        }
        REQUIRE(pending != nullptr);
        const std::string_view answers[] = {"s3cret"};
        REQUIRE_FALSE(client.resolve(pending->ticket, answers));
    }
    return output_after(mark, collect_output(client));
}

class reenter_handler : public recording_handler {
public:
    core::connection* client = nullptr;
    core::connection* server = nullptr;
    host_material* hm = nullptr;
    reenter_handler* peer = nullptr;
    core::channel_ref session_ch{};
    bool authed = false;
    bool open_started = false;
    bool session_ready = false;
    bool exercised_io = false;
    bool client_close_sent = false;
    bool exercised_double_close = false;
    std::error_code second_close_ec{};

    void on_handshake_done(core::connection& c) override {
        recording_handler::on_handshake_done(c);
        reenter(c);
    }

    void on_host_key(core::connection& c, core::host_key_ticket ticket,
                     std::span<const std::byte> blob) override {
        recording_handler::on_host_key(c, ticket, blob);
        if (&c == client) c.resolve(ticket, core::host_key_verdict::accept);
        reenter(c);
    }

    void on_auth_request(core::connection& c, core::auth_ticket ticket,
                         const auth::auth_request_view& request) override {
        recording_handler::on_auth_request(c, ticket, request);
        if (&c == server && request.method == "password") {
            c.resolve(ticket, auth::auth_verdict::success());
        }
        reenter(c);
    }

    void on_open_request(core::connection& c, core::open_ticket ticket,
                         const channels::open_request_view& request) override {
        recording_handler::on_open_request(c, ticket, request);
        if (&c == server) {
            c.resolve(ticket, channels::channel_open_verdict::accepted());
            session_ch = core::connection::channel_ref_of(ticket);
            session_ready = true;
        }
        reenter(c);
    }

    void on_global_request(core::connection& c, core::global_request_ticket ticket,
                           const channels::request_view& request) override {
        recording_handler::on_global_request(c, ticket, request);
        if (&c == server && request.want_reply) c.resolve(ticket, true);
        reenter(c);
    }

    void on_channel_request(core::connection& c, core::channel_request_ticket ticket, void* user,
                            const channels::request_view& request) override {
        recording_handler::on_channel_request(c, ticket, user, request);
        if (&c == server && request.want_reply) c.resolve(ticket, true);
        reenter(c);
    }

    void on_auth_result(core::connection& c, const auth::auth_result& result) override {
        recording_handler::on_auth_result(c, result);
        if (&c == client && result.success) authed = true;
        reenter(c);
    }

    void on_open_result(core::connection& c, core::channel_ref ref, void* user,
                        const channels::open_result_view& result) override {
        recording_handler::on_open_result(c, ref, user, result);
        if (&c == client && result.success) {
            session_ch = ref;
            session_ready = true;
        }
        reenter(c);
    }

    void on_released(core::connection& c, core::channel_ref ref, void* user) override {
        recording_handler::on_released(c, ref, user);
        if (&c == client && client_close_sent && !exercised_double_close) {
            second_close_ec = c.channel_close(ref);
            exercised_double_close = true;
        }
        reenter(c);
    }

private:
    void reenter(core::connection& c) {
        if (!client_close_sent) {
            const std::byte ign{0x01};
            (void)c.send_ignore(std::span<const std::byte>{&ign, 1});
        }
        if (!authed && client && server && hm) {
            if (&c == client) {
                (void)client->auth_password("alice", "s3cret");
            }
        }
        if (authed && client && !open_started && &c == client) {
            open_started = true;
            core::channel_ref opened{};
            (void)client->open_channel(channels::channel_open_spec{}, nullptr, opened);
        }
        if (session_ready && !exercised_io) {
            std::size_t accepted = 0;
            const std::byte pay{0x02};
            const std::span<const std::byte> frag{&pay, 1};
            const std::span<const std::span<const std::byte>> frags{&frag, 1};
            (void)c.channel_write(session_ch, frags, accepted);
            (void)c.channel_read(session_ch, 0, std::span<std::byte>{});
            (void)c.send_global_request("tcpip-forward", {}, false);
            exercised_io = true;
        }
        if (&c == client && session_ready && !client_close_sent) {
            REQUIRE_FALSE(c.channel_close(session_ch));
            client_close_sent = true;
            if (peer) peer->client_close_sent = true;
        }
        if (!client_close_sent) (void)c.rekey();
    }
};

TEST_CASE("client handshake wire bytes match inline and deferred host-key resolve", "[callback]") {
    const auto inline_bytes = client_handshake_output(true);
    const auto deferred_bytes = client_handshake_output(false);
    REQUIRE_FALSE(inline_bytes.empty());
    REQUIRE_FALSE(deferred_bytes.empty());
    REQUIRE(inline_bytes == deferred_bytes);
}

TEST_CASE("server auth wire bytes match inline and deferred resolve", "[callback]") {
    for (auto scenario :
         {auth_wire_scenario::password_success, auth_wire_scenario::password_failure,
          auth_wire_scenario::pk_ok, auth_wire_scenario::kbdint_info}) {
        INFO("scenario=" << static_cast<int>(scenario));
        const auto inline_bytes = server_auth_output(true, scenario);
        const auto deferred_bytes = server_auth_output(false, scenario);
        REQUIRE_FALSE(inline_bytes.empty());
        REQUIRE_FALSE(deferred_bytes.empty());
        REQUIRE(inline_bytes == deferred_bytes);
    }
}

TEST_CASE("client kbdint wire bytes match inline and deferred resolve", "[callback]") {
    const auto inline_bytes = client_kbdint_output(true);
    const auto deferred_bytes = client_kbdint_output(false);
    REQUIRE_FALSE(inline_bytes.empty());
    REQUIRE_FALSE(deferred_bytes.empty());
    REQUIRE(inline_bytes == deferred_bytes);
}

TEST_CASE("handler reentry during callbacks completes auth and opens session", "[callback]") {
    fixed_random_provider client_random{prov(), 0xabadbeef};
    fixed_random_provider server_random{prov(), 0x600dcafe};
    auto hm = make_ed25519_host(server_random.get());
    reenter_handler client_handler;
    reenter_handler server_handler;
    core::connection client{core::role::client, client_random.get(), {}, client_handler};
    core::connection server{core::role::server, server_random.get(), {}, server_handler};
    client_handler.client = &client;
    client_handler.server = &server;
    client_handler.hm = &hm;
    client_handler.peer = &server_handler;
    server_handler.client = &client;
    server_handler.server = &server;
    server_handler.hm = &hm;
    server_handler.peer = &client_handler;
    configure_server(server, hm);
    REQUIRE(run_loopback(
        client, client_handler, server, server_handler, nullptr, nullptr,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (!is_client) return;
            if (const auto* auth = std::get_if<recording_handler::auth_response>(&ev)) {
                if (auth->success) client_handler.authed = true;
            }
            if (std::holds_alternative<recording_handler::channel_opened>(ev)) {
                client_handler.session_ready = true;
            }
        },
        512));
    REQUIRE(run_loopback(
        client, client_handler, server, server_handler, nullptr, nullptr,
        [](bool, const recording_handler::recorded_event&) {}, 512));
    REQUIRE(client_handler.authed);
    REQUIRE(client_handler.session_ready);
    REQUIRE(client_handler.exercised_io);
    REQUIRE(server_handler.exercised_io);
    REQUIRE(client_handler.client_close_sent);
    REQUIRE(client_handler.exercised_double_close);
    REQUIRE(client_handler.second_close_ec == code::invalid_state);
    REQUIRE_FALSE(client.failure());
    REQUIRE_FALSE(server.failure());
}
