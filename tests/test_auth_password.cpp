#include <catch2/catch_test_macros.hpp>
#include "drive.hpp"
#include "handshake_fixture.hpp"
#include "scripted_peer.hpp"
#include "secret_scan_resource.hpp"

#include <yanterm-ssh/core/handler.hpp>
#include <yanterm-ssh/wire/detail/messages.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/detail/error.hpp>

#include <algorithm>
#include <cstdint>
#include <initializer_list>
#include <memory_resource>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

using auth::auth_verdict;
using auth::service_userauth;

namespace {

// Observes the password span when its page is returned. The check has to happen
// inside deallocate: after feed() the block is already back with the resource.
class wiped_span_resource final : public std::pmr::memory_resource {
public:
    explicit wiped_span_resource(std::pmr::memory_resource* upstream) : upstream_{upstream} {}

    const char* pwd = nullptr;
    std::size_t len = 0;
    bool saw = false;
    bool wiped = false;

private:
    void* do_allocate(std::size_t n, std::size_t alignment) override {
        return upstream_->allocate(n, alignment);
    }

    void do_deallocate(void* p, std::size_t n, std::size_t alignment) override {
        if (!saw && pwd != nullptr && len > 0) {
            const auto* begin = static_cast<const char*>(p);
            const auto* end = begin + n;
            if (pwd >= begin && pwd + len <= end) {
                saw = true;
                wiped = std::all_of(pwd, pwd + len, [](char c) { return c == '\0'; });
            }
        }
        upstream_->deallocate(p, n, alignment);
    }

    bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override {
        return this == &other;
    }

    std::pmr::memory_resource* upstream_;
};

class password_probe_recording : public recording_handler {
public:
    const char* pwd_ptr = nullptr;
    std::size_t pwd_len = 0;
    wiped_span_resource* probe = nullptr;

    void on_auth_request(core::connection& c, core::auth_ticket ticket,
                         const auth::auth_request_view& request) override {
        pwd_ptr = request.password.data();
        pwd_len = request.password.size();
        if (probe != nullptr) {
            probe->pwd = pwd_ptr;
            probe->len = pwd_len;
        }
        recording_handler::on_auth_request(c, ticket, request);
    }
};

class throwing_password_handler : public recording_handler {
public:
    std::string copied;

    void on_auth_request(core::connection& c, core::auth_ticket ticket,
                         const auth::auth_request_view& request) override {
        copied.assign(request.password.begin(), request.password.end());
        (void)c;
        (void)ticket;
        throw std::runtime_error("auth callback failed");
    }
};

struct probe_server {
    password_probe_recording handler;
    core::connection conn;

    probe_server(crypto::provider p, std::pmr::memory_resource* mr,
                 const core::config& cfg = {})
        : conn{core::role::server, p, cfg, handler, mr} {}
};

struct throwing_server {
    throwing_password_handler handler;
    core::connection conn;

    throwing_server(crypto::provider p, const core::config& cfg = {})
        : conn{core::role::server, p, cfg, handler} {}
};

}  // namespace

TEST_CASE("password callback wipes page bytes after return", "[auth][password][password bytes]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    wiped_span_resource mr{memory::default_page_resource()};
    probe_server server{p, &mr};
    server.handler.probe = &mr;
    configure_server(server.conn, hm);
    handshake_capture cap;
    REQUIRE(run_loopback(
        client.conn, client.handler, server.conn, server.handler, &client, nullptr,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (is_client) accept_client_host_key(client, ev);
        }));

    REQUIRE_FALSE(client.conn.auth_password("alice", "s3cret"));

    REQUIRE(run_loopback(
        client.conn, client.handler, server.conn, server.handler, &client, nullptr,
        [](bool, const recording_handler::recorded_event&) {}));

    REQUIRE(server.handler.pwd_ptr != nullptr);
    REQUIRE(server.handler.pwd_len == 6);
    REQUIRE(mr.saw);
    REQUIRE(mr.wiped);

    auto client2 = make_client(p);
    auto server2 = make_server(p);
    configure_server(server2, hm);
    REQUIRE(run_handshake(client2, server2, cap));
    REQUIRE_FALSE(client2.conn.auth_password("alice", "s3cret"));
    REQUIRE(run_auth_loopback(client2, server2,
                                       [&](bool is_client, const recording_handler::recorded_event& ev) {
                                           if (const auto* req =
                                                   std::get_if<recording_handler::auth_request>(&ev)) {
                                               if (!is_client) {
                                                   REQUIRE(req->password == "s3cret");
                                                   server2.conn.resolve(req->ticket,
                                                                        auth_verdict::success());
                                               }
                                           }
                                       }));
}

TEST_CASE("password callback wipe survives handler throw", "[auth][password][password bytes]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    throwing_server server{p};
    configure_server(server.conn, hm);
    handshake_capture cap;
    REQUIRE(run_loopback(
        client.conn, client.handler, server.conn, server.handler, &client, nullptr,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (is_client) accept_client_host_key(client, ev);
        }));

    REQUIRE_FALSE(client.conn.auth_password("alice", "s3cret"));

    REQUIRE_THROWS_AS(
        run_loopback(
            client.conn, client.handler, server.conn, server.handler, &client, nullptr,
            [&](bool is_client, const recording_handler::recorded_event& ev) {
                if (is_client) accept_client_host_key(client, ev);
            }),
        std::runtime_error);
    REQUIRE(server.handler.copied == "s3cret");
    REQUIRE(server.conn.failure() == code::invalid_state);

    wire::detail::service_msg req;
    req.id = wire::msg::service_request;
    req.service_name = service_userauth;
    wire::writer sw;
    req.encode(sw);
    std::size_t accepted = 0;
    REQUIRE(server.conn.feed(sw.data(), accepted) == code::invalid_state);
}

class inline_resolve_handler : public recording_handler {
public:
    core::auth_ticket ticket{};

    void on_auth_request(core::connection& c, core::auth_ticket t,
                         const auth::auth_request_view& request) override {
        REQUIRE(request.method == "password");
        ticket = t;
        REQUIRE_FALSE(c.resolve(t, auth_verdict::success()));
        REQUIRE(c.pending_output_bytes() > 0);
        REQUIRE(c.resolve(t, auth_verdict::success()) == code::invalid_state);
        REQUIRE_FALSE(c.failure());
    }
};

struct inline_resolve_server {
    inline_resolve_handler handler;
    core::connection conn;

    inline_resolve_server(crypto::provider p, const core::config& cfg = {})
        : conn{core::role::server, p, cfg, handler} {}
};

TEST_CASE("inline auth resolve in callback queues success", "[auth][password]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    inline_resolve_server server{p};
    configure_server(server.conn, hm);
    REQUIRE(run_loopback(
        client.conn, client.handler, server.conn, server.handler, &client, nullptr,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (is_client) accept_client_host_key(client, ev);
        }));

    REQUIRE_FALSE(client.conn.auth_password("alice", "s3cret"));

    bool saw_success = false;
    REQUIRE(run_loopback(
        client.conn, client.handler, server.conn, server.handler, &client, nullptr,
        [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (const auto* resp = std::get_if<recording_handler::auth_response>(&ev)) {
                if (is_client && resp->success) saw_success = true;
            }
        }));

    REQUIRE(saw_success);
    REQUIRE(server.handler.ticket != core::auth_ticket{});
    REQUIRE(server.conn.resolve(server.handler.ticket, auth_verdict::success()) == code::invalid_state);
    REQUIRE_FALSE(server.conn.failure());
    REQUIRE_FALSE(client.conn.failure());
}

TEST_CASE("password success both directions", "[auth][password]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    REQUIRE_FALSE(client.conn.auth_password("alice", "s3cret"));

    bool saw_req = false;
    bool saw_resp = false;
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client,
                                                            const recording_handler::recorded_event& ev) {
        if (const auto* req = std::get_if<recording_handler::auth_request>(&ev)) {
            if (!is_client) {
                REQUIRE(req->user == "alice");
                REQUIRE(req->service == "ssh-connection");
                REQUIRE(req->method == "password");
                REQUIRE(req->password == "s3cret");
                REQUIRE(req->ticket != core::auth_ticket{});
                saw_req = true;
                server.conn.resolve(req->ticket, auth_verdict::success());
            }
        }
        if (const auto* resp = std::get_if<recording_handler::auth_response>(&ev)) {
            if (is_client) {
                REQUIRE(resp->success);
                saw_resp = true;
            }
        }
    }));
    REQUIRE(saw_req);
    REQUIRE(saw_resp);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());

    REQUIRE(client.conn.auth_password("alice", "s3cret") == code::invalid_state);
    REQUIRE(client.conn.auth_none("alice") == code::invalid_state);
}

TEST_CASE("password mismatch is auth failure not session failure", "[auth][password]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    REQUIRE_FALSE(client.conn.auth_password("alice", "wrong"));

    bool saw_resp = false;
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client,
                                                            const recording_handler::recorded_event& ev) {
        if (const auto* req = std::get_if<recording_handler::auth_request>(&ev)) {
            if (!is_client && req->method == "password") {
                server.conn.resolve(req->ticket, auth_verdict::failure("publickey,password"));
            }
        }
        if (const auto* resp = std::get_if<recording_handler::auth_response>(&ev)) {
            if (is_client) {
                REQUIRE_FALSE(resp->success);
                REQUIRE(resp->methods == "publickey,password");
                REQUIRE_FALSE(resp->partial_success);
                saw_resp = true;
            }
        }
    }));
    REQUIRE(saw_resp);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("server send_auth_banner reaches client", "[auth][banner]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    REQUIRE_FALSE(client.conn.auth_none("alice"));

    std::vector<std::string_view> client_auth;
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client,
                                                            const recording_handler::recorded_event& ev) {
        if (const auto* req = std::get_if<recording_handler::auth_request>(&ev)) {
            if (!is_client) {
                REQUIRE_FALSE(server.conn.send_auth_banner("hello"));
                server.conn.resolve(req->ticket, auth_verdict::failure("publickey,password"));
            }
        }
        if (const auto* banner = std::get_if<recording_handler::auth_banner>(&ev)) {
            if (is_client) {
                REQUIRE(banner->text == "hello");
                client_auth.push_back("auth_banner");
            }
        }
        if (const auto* resp = std::get_if<recording_handler::auth_response>(&ev)) {
            if (is_client) {
                REQUIRE_FALSE(resp->success);
                client_auth.push_back("auth_response");
            }
        }
    }));
    REQUIRE(client_auth.size() == 2);
    REQUIRE(client_auth[0] == "auth_banner");
    REQUIRE(client_auth[1] == "auth_response");
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("partial_success keeps session and allows next method", "[auth][password]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    REQUIRE_FALSE(client.conn.auth_none("alice"));

    bool saw_partial = false;
    bool saw_pw_req = false;
    bool saw_ok = false;
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client,
                                                            const recording_handler::recorded_event& ev) {
        if (const auto* req = std::get_if<recording_handler::auth_request>(&ev)) {
            if (!is_client) {
                if (req->method == "none") {
                    server.conn.resolve(req->ticket, auth_verdict::failure("password", true));
                } else if (req->method == "password") {
                    REQUIRE(req->password == "s3cret");
                    saw_pw_req = true;
                    server.conn.resolve(req->ticket, auth_verdict::success());
                }
            }
        }
        if (const auto* resp = std::get_if<recording_handler::auth_response>(&ev)) {
            if (is_client) {
                if (!resp->success) {
                    REQUIRE(resp->partial_success);
                    REQUIRE(resp->methods == "password");
                    saw_partial = true;
                    REQUIRE_FALSE(client.conn.auth_password("alice", "s3cret"));
                } else {
                    saw_ok = true;
                }
            }
        }
    }));
    REQUIRE(saw_partial);
    REQUIRE(saw_pw_req);
    REQUIRE(saw_ok);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("password bytes are not left in event after resolve", "[auth][password]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    REQUIRE_FALSE(client.conn.auth_password("alice", "s3cret"));

    std::string copied;
    bool resolved = false;
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client,
                                                            const recording_handler::recorded_event& ev) {
        if (const auto* req = std::get_if<recording_handler::auth_request>(&ev)) {
            if (!is_client) {
                copied.assign(req->password.begin(), req->password.end());
                REQUIRE(copied == "s3cret");
                server.conn.resolve(req->ticket, auth_verdict::success());
                resolved = true;
            }
        }
    }));
    REQUIRE(copied == "s3cret");
    REQUIRE(resolved);
}

namespace {

std::vector<std::byte> password_request(bool change, std::initializer_list<std::string_view> secrets,
                                        std::span<const std::byte> tail = {}) {
    wire::writer w;
    w.write_byte(static_cast<std::uint8_t>(wire::msg::userauth_request));
    w.write_string("alice");
    w.write_string("ssh-connection");
    w.write_string("password");
    w.write_bool(change);
    for (auto s : secrets) w.write_string(s);
    for (auto b : tail) w.write_byte(static_cast<std::uint8_t>(b));
    return w.take();
}

void feed_bytes(core::connection& conn, std::span<const std::byte> bytes) {
    std::error_code ec;
    const auto n = feed_all(conn, bytes, ec);
    INFO(ec.message());
    REQUIRE(n == bytes.size());
    REQUIRE_FALSE(ec);
}

const recording_handler::auth_request* password_request(const recording_handler& handler) {
    const recording_handler::auth_request* saw = nullptr;
    for (const auto& ev : handler.events) {
        if (const auto* req = std::get_if<recording_handler::auth_request>(&ev)) saw = req;
    }
    return saw;
}

}  // namespace

TEST_CASE("second auth_password while outstanding is invalid_state", "[auth][password]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    REQUIRE_FALSE(client.conn.auth_password("alice", "s3cret"));
    const auto ec = client.conn.auth_password("alice", "other");
    REQUIRE(ec == code::invalid_state);
    REQUIRE_FALSE(client.conn.failure());

    const auto userauth = collect_output(client.conn);
    REQUIRE_FALSE(userauth.empty());
    consume_pending_output(client.conn);
    server.handler.events.clear();
    feed_bytes(server.conn, userauth);

    const auto* req = password_request(server.handler);
    REQUIRE(req != nullptr);
    REQUIRE(req->method == "password");
    REQUIRE(req->user == "alice");
    REQUIRE(req->password == "s3cret");
    REQUIRE_FALSE(client.conn.failure());
}

TEST_CASE("password changereq is unexpected_message", "[auth][password]") {
    peer_session s{core::role::client};
    s.handshake();
    REQUIRE_FALSE(s.sut.conn.auth_password("alice", "s3cret"));
    REQUIRE_FALSE(s.peer.exchange(s.sut));
    REQUIRE(s.peer.take(wire::msg::userauth_request));

    wire::detail::userauth_pk_ok pk;      // 60 号在 password 上下文中是 CHANGEREQ
    pk.algorithm = "ssh-ed25519";
    const std::byte blob[] = {std::byte{1}};
    pk.blob = blob;
    s.peer.send_msg(pk);
    REQUIRE(s.peer.deliver(s.sut) == code::unexpected_message);
}

TEST_CASE("unknown auth method still emits auth_request", "[auth]") {
    peer_session s{core::role::server};
    s.handshake();
    wire::writer uw;
    uw.write_byte(static_cast<std::uint8_t>(wire::msg::userauth_request));
    uw.write_string("alice");
    uw.write_string("ssh-connection");
    uw.write_string("hostbased");
    uw.write_string("trailing-method-data");
    s.peer.send(uw.data());
    REQUIRE_FALSE(s.peer.exchange(s.sut));
    REQUIRE(s.sut.handler.events.size() == 1);
    const auto* req = std::get_if<recording_handler::auth_request>(&s.sut.handler.events[0]);
    REQUIRE(req != nullptr);
    REQUIRE(req->user == "alice");
    REQUIRE(req->method == "hostbased");
    REQUIRE(s.sut.conn.inbound_requests_stalled());
    REQUIRE_FALSE(s.sut.conn.resolve(req->ticket, auth_verdict::failure("password")));
    REQUIRE_FALSE(s.peer.exchange(s.sut));
    REQUIRE(s.peer.take(wire::msg::userauth_failure));
}

TEST_CASE("password change=true is unexpected_message", "[auth][password]") {
    peer_session s{core::role::server};
    s.handshake();
    s.sut.handler.events.clear();
    s.peer.send(password_request(true, {"old-secret", "new-secret"}));
    REQUIRE(s.peer.deliver(s.sut) == code::unexpected_message);
    REQUIRE(s.sut.handler.events.empty());
}

TEST_CASE("resolve(info) on password is invalid_state", "[auth][password]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    REQUIRE_FALSE(client.conn.auth_password("alice", "s3cret"));

    bool saw_req = false;
    (void)run_auth_loopback(client, server, [&](bool is_client,
                                                           const recording_handler::recorded_event& ev) {
        if (const auto* req = std::get_if<recording_handler::auth_request>(&ev)) {
            if (!is_client && req->method == "password") {
                saw_req = true;
                const auth::kbdint_prompt prompts[] = {{"Password:", false}};
                REQUIRE(server.conn.resolve(req->ticket, auth_verdict::info("login", "nope", prompts))
                        == code::invalid_state);
            }
        }
    });
    REQUIRE(saw_req);
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("auth_password write failure fails the session", "[auth][password]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    REQUIRE_FALSE(client.conn.auth_none("alice"));
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client,
                                                            const recording_handler::recorded_event& ev) {
        if (const auto* req = std::get_if<recording_handler::auth_request>(&ev)) {
            if (!is_client) {
                server.conn.resolve(req->ticket, auth_verdict::failure("password"));
            }
        }
    }));
    REQUIRE_FALSE(client.conn.failure());

    const std::string huge(40000, 'p');
    const auto ec = client.conn.auth_password("alice", huge);
    REQUIRE(ec == code::packet_too_large);
    REQUIRE(client.conn.failure() == code::packet_too_large);
    REQUIRE(client.conn.auth_none("alice") == code::invalid_state);
}

TEST_CASE("rejected password fields on the page are wiped", "[auth][password]") {
    struct row {
        const char* name;
        std::vector<std::byte> payload;
        std::vector<std::string_view> secrets;
        std::error_code expect;
    };
    const std::byte trailing[] = {std::byte{0x5a}};
    const std::byte truncated[] = {std::byte{0}, std::byte{0}, std::byte{0}, std::byte{20}, std::byte{0x11}};
    const row rows[] = {
        {"change=true", password_request(true, {"old-secret", "new-secret"}),
         {"old-secret", "new-secret"}, code::unexpected_message},
        {"trailing byte", password_request(false, {"s3cret"}, trailing), {"s3cret"}, code::invalid_format},
        {"truncated new password", password_request(true, {"old-secret"}, truncated),
         {"old-secret"}, code::invalid_format},
    };
    for (const auto& r : rows) {
        DYNAMIC_SECTION(r.name) {
            secret_scan_resource mr;
            for (auto sec : r.secrets) mr.watch(sec);
            {
                peer_session s{core::role::server, scripted_peer::sut_config(), &mr};
                s.handshake();
                s.sut.handler.events.clear();
                s.peer.send(r.payload);
                REQUIRE(s.peer.deliver(s.sut) == r.expect);
                REQUIRE(s.sut.handler.events.empty());
            }
            REQUIRE(mr.returned_blocks() > 0);
            REQUIRE_FALSE(mr.leaked());
        }
    }
}

TEST_CASE("kbdint info response count mismatch wipes located secrets", "[auth][kbdint]") {
    secret_scan_resource mr;
    mr.watch("alpha-secret");
    mr.watch("beta-secret");
    {
        peer_session s{core::role::server, scripted_peer::sut_config(), &mr};
        s.handshake();
        wire::detail::userauth_request_kbdint hello;
        hello.user = "alice";
        s.peer.send_msg(hello);
        REQUIRE_FALSE(s.peer.exchange(s.sut));
        REQUIRE(s.sut.handler.events.size() == 1);
        const auto* req = std::get_if<recording_handler::auth_request>(&s.sut.handler.events[0]);
        REQUIRE(req != nullptr);
        const auth::kbdint_prompt prompts[] = {{"Password:", false}};
        REQUIRE_FALSE(s.sut.conn.resolve(req->ticket, auth_verdict::info("login", "hi", prompts)));
        REQUIRE_FALSE(s.peer.exchange(s.sut));
        REQUIRE(s.peer.take(wire::msg::userauth_info_request));

        const std::string_view responses[] = {"alpha-secret", "beta-secret"};
        wire::detail::userauth_info_response msg;
        msg.responses = responses;
        s.sut.handler.events.clear();
        s.peer.send_msg(msg);
        REQUIRE(s.peer.deliver(s.sut) == code::invalid_format);
        REQUIRE(s.sut.handler.events.empty());
    }
    REQUIRE(mr.returned_blocks() > 0);
    REQUIRE_FALSE(mr.leaked());
}
