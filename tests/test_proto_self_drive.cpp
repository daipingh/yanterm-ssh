#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/channel.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/session.hpp>

#include "facade_fixture.hpp"

#include <auv/error.hpp>
#include <auv/stream.hpp>
#include <corral/corral.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <tuple>
#include <utility>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

namespace {

auto accept_host = [](host_key_view) -> corral::Task<bool> { co_return true; };

auto reject_open = [](inbound_channel_open open) -> corral::Task<void> {
    open.reject(channel_open_reason::administratively_prohibited, "client");
    co_return;
};
auto reject_global = [](inbound_global_request req) -> corral::Task<void> {
    req.reject();
    co_return;
};

corral::Task<void> drain_turns(TestLoop& loop, int n) {
    for (int i = 0; i < n; ++i) {
        corral::Event turn;
        loop.post([&] { turn.trigger(); });
        co_await turn;
    }
}

// What the author wants an application to be able to write: TCP connect (here a
// pipe), handshake and authenticate, then hand back a ready session.
corral::Task<std::tuple<std::error_code, client_session>> connect_ready(client_session cs) {
    if (auto ec = co_await cs.handshake(accept_host)) co_return {ec, client_session{}};
    auto [ec, r] = co_await cs.auth_password("alice", "wrong");
    if (ec) co_return {ec, client_session{}};
    REQUIRE_FALSE(r.success);
    REQUIRE(r.methods == "password,keyboard-interactive");
    std::tie(ec, r) = co_await cs.auth_keyboard_interactive(
        "alice", [](std::string_view, std::string_view, std::span<const kbdint_prompt> prompts)
                     -> corral::Task<std::vector<std::string>> {
            REQUIRE(prompts.size() == 1);
            co_return std::vector<std::string>{"s3cret"};
        });
    if (ec) co_return {ec, client_session{}};
    if (!r.success) co_return {std::make_error_code(std::errc::permission_denied), client_session{}};
    co_return {std::error_code{}, std::move(cs)};
}

// Linear server: no outer run(), no run_with.
corral::Task<void> linear_server(server_session& ss, TestLoop& loop, int delay_before_serve) {
    auto&& awaited_ = co_await ss.handshake();
REQUIRE_FALSE(awaited_);
    auto aec = co_await ss.authenticate([](auth_request req) -> corral::Task<auth_verdict> {
        if (req.method() == "keyboard-interactive") {
            auto [ec, answer] = co_await req.challenge("Password: ", false);
            if (!ec && answer == "s3cret") co_return auth_verdict::success();
        }
        co_return auth_verdict::failure("password,keyboard-interactive");
    });
    REQUIRE_FALSE(aec);
    // e.g. look up the user's home directory before accepting channels.
    co_await drain_turns(loop, delay_before_serve);
    co_await ss.serve(
        [&](inbound_channel_open open) -> corral::Task<void> {
            channel ch = open.accept();
            auv::stream s = auv::stream::borrow(ch);
            char buf[16];
            auto [rec, nread] = co_await s.read([&] { return auv::buffer(buf, sizeof(buf)); });
            REQUIRE_FALSE(rec);
            std::printf("server read %zu: %.*s\n", nread, int(nread), buf);
            auv::buffer echo{buf, nread};
            auto&& awaited_ = co_await s.write(&echo, std::size_t{1});
REQUIRE_FALSE(awaited_);
        },
        reject_global);
}

}  // namespace

TEST_CASE("proto: factory returns a ready session; server is linear", "[proto]") {
    std::printf("sizeof(session_impl)=%zu\n", sizeof(session_impl));
    for (int delay : {0, 50}) {
        auto fp = make_facade_pair();
        bool echoed = false;
        corral::run(fp.loop, [&]() -> corral::Task<void> {
            CORRAL_WITH_NURSERY(n) {
                n.start([&]() -> corral::Task<void> { co_await linear_server(fp.server, fp.loop, delay); });
                auto [ec, cs] = co_await connect_ready(std::move(fp.client));
                REQUIRE_FALSE(ec);
                REQUIRE(cs);
                // The ready session was moved out of the factory; serve() pumps it.
                CORRAL_WITH_NURSERY(c) {
                    co_await c.start([&](corral::TaskStarted<> st) -> corral::Task<void> {
                        co_await cs.serve(reject_open, reject_global, std::move(st));
                    });
                    auto opened = co_await cs.open_session_channel();
                    REQUIRE_FALSE(opened.ec);
                    auv::stream s = auv::stream::borrow(opened.ch);
                    const char msg[] = "hi";
                    auv::buffer wb{msg, 2};
                    auto&& awaited_ = co_await s.write(&wb, std::size_t{1});
REQUIRE_FALSE(awaited_);
                    char got[8];
                    auto [rec, nread] =
                        co_await s.read([&] { return auv::buffer(got, sizeof(got)); });
                    REQUIRE_FALSE(rec);
                    std::printf("client read %zu: %.*s\n", nread, int(nread), got);
                    REQUIRE(nread == 2);
                    echoed = std::memcmp(got, "hi", 2) == 0;
                    co_await cs.disconnect(disconnect_reason::by_application, "done");
                    co_return corral::join;
                };
                co_return corral::join;
            };
        }());
        REQUIRE(echoed);
        REQUIRE(fp.server.disconnected() != nullptr);
    }
}

TEST_CASE("proto: current design rejects opens while server delays serve", "[proto]") {
    auto fp = make_facade_pair();
    std::error_code open_ec;
    corral::run(fp.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &fp.client);
            co_await n.start(&server_session::run, &fp.server);
            n.start([&]() -> corral::Task<void> { co_await linear_server(fp.server, fp.loop, 50); });
            auto&& awaited_ = co_await fp.client.handshake(accept_host);
REQUIRE_FALSE(awaited_);
            auto [ec, r] = co_await fp.client.auth_keyboard_interactive(
                "alice", [](std::string_view, std::string_view, std::span<const kbdint_prompt>)
                             -> corral::Task<std::vector<std::string>> {
                    co_return std::vector<std::string>{"s3cret"};
                });
            REQUIRE(r.success);
            auto opened = co_await fp.client.open_session_channel();
            open_ec = opened.ec;
            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
    REQUIRE(open_ec == errc::request_denied);
}

TEST_CASE("proto: failed auth then DISCONNECT without any pump", "[proto]") {
    auto fp = make_facade_pair();
    corral::run(fp.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto&& awaited_ = co_await fp.server.handshake();
REQUIRE_FALSE(awaited_);
                auto ec = co_await fp.server.authenticate(
                    [](auth_request) -> corral::Task<auth_verdict> {
                        co_return auth_verdict::failure("password");
                    });
                REQUIRE(ec == errc::peer_disconnected);
            });
            auto&& awaited_ = co_await fp.client.handshake(accept_host);
REQUIRE_FALSE(awaited_);
            auto [ec, r] = co_await fp.client.auth_password("alice", "nope");
            REQUIRE_FALSE(ec);
            REQUIRE_FALSE(r.success);
            co_await fp.client.disconnect(disconnect_reason::no_more_auth_methods_available,
                                          "bye");
            co_return corral::join;
        };
    }());
    REQUIRE(fp.server.disconnected() != nullptr);
    REQUIRE(fp.server.disconnected()->reason == disconnect_reason::no_more_auth_methods_available);
}

TEST_CASE("proto: cancelled self-driven handshake leaves a usable session", "[proto]") {
    auto fp = make_facade_pair();
    corral::run(fp.loop, [&]() -> corral::Task<void> {
        // Client times out its first handshake attempt before the server starts.
        auto first = co_await corral::anyOf(fp.client.handshake(accept_host),
                                            drain_turns(fp.loop, 3));
        REQUIRE_FALSE(std::get<0>(first));
        REQUIRE_FALSE(fp.client.failure());
        auto [cec, sec] = co_await corral::allOf(fp.client.handshake(accept_host),
                                                 fp.server.handshake());
        REQUIRE_FALSE(cec);
        REQUIRE_FALSE(sec);
    }());
}
