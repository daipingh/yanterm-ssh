#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/channel.hpp>
#include <yanterm-ssh/wire/types.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/detail/error.hpp>
#include <yanterm-ssh/session.hpp>

#include "facade_fixture.hpp"

#include <corral/corral.h>

#include <string_view>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

namespace {

auto accept_host = [](host_key_view) -> corral::Task<bool> { co_return true; };

auto dummy_open = [](inbound_channel_open open) -> corral::Task<void> {
    open.reject(channel_open_reason::administratively_prohibited, "unexpected open");
    co_return;
};

auto dummy_global = [](inbound_global_request req) -> corral::Task<void> {
    req.reject();
    co_return;
};

corral::Task<void> handshake_and_password(client_session& client, server_session& server) {
    auto [cec, sec] = co_await corral::allOf(client.handshake(accept_host), server.handshake());
    REQUIRE_FALSE(cec);
    REQUIRE_FALSE(sec);

    auto [aec, auth] = co_await corral::allOf(
        client.auth_password("alice", "s3cret"),
        server.authenticate([](auth_request req) -> corral::Task<auth_verdict> {
            if (req.method() == "password" && req.user() == "alice" && req.password() == "s3cret") {
                co_return auth_verdict::success();
            }
            co_return auth_verdict::failure("password");
        }));
    auto [pec, result] = aec;
    REQUIRE_FALSE(pec);
    REQUIRE(result.success);
    REQUIRE_FALSE(auth);
}

corral::Task<void> drain_turns(TestLoop& loop, int n) {
    for (int i = 0; i < n; ++i) {
        corral::Event turn;
        loop.post([&] { turn.trigger(); });
        co_await turn;
    }
}

}  // namespace

TEST_CASE("uninstalled serve rejects inbound opens", "[facade][serve][callback]") {
    auto fp = make_facade_pair();

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &fp.client);
            co_await n.start(&server_session::run, &fp.server);
            co_await handshake_and_password(fp.client, fp.server);

            auto opened = co_await fp.client.open_session_channel();
            REQUIRE(opened.ec == errc::request_denied);
            REQUIRE_FALSE(opened.ch);
            REQUIRE(opened.reason == channel_open_reason::administratively_prohibited);
            REQUIRE(opened.description == "serve not installed");

            auto gec = co_await fp.client.send_global_request("tcpip-forward", {}, true);
            REQUIRE(gec == errc::request_denied);

            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("tcpip-forward global request", "[facade][serve]") {
    auto fp = make_facade_pair();

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &fp.client);
            co_await n.start(&server_session::run, &fp.server);
            co_await handshake_and_password(fp.client, fp.server);

            corral::Event serving;
            n.start([&]() -> corral::Task<void> {
                serving.trigger();
                co_await fp.server.serve(
                    dummy_open, [](inbound_global_request req) -> corral::Task<void> {
                        REQUIRE(req.type() == "tcpip-forward");
                        REQUIRE(req.want_reply());
                        wire::writer bound;
                        bound.write_uint32(1234);
                        req.accept(bound.data());
                        co_return;
                    });
            });
            co_await serving;

            std::uint16_t bound = 0;
            auto fec = co_await fp.client.request_tcpip_forward("127.0.0.1", 0, bound);
            REQUIRE_FALSE(fec);
            REQUIRE(bound == 1234);

            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("streamlocal-forward global request", "[facade][serve]") {
    auto fp = make_facade_pair();

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &fp.client);
            co_await n.start(&server_session::run, &fp.server);
            co_await handshake_and_password(fp.client, fp.server);

            corral::Event serving;
            n.start([&]() -> corral::Task<void> {
                serving.trigger();
                co_await fp.server.serve(
                    dummy_open, [](inbound_global_request req) -> corral::Task<void> {
                        REQUIRE(req.want_reply());
                        std::string_view path;
                        REQUIRE(channels::decode_streamlocal_forward(
                            req.payload(), path));
                        REQUIRE(path == "/tmp/agent.sock");
                        REQUIRE((req.type() == "streamlocal-forward@openssh.com"
                                 || req.type() == "cancel-streamlocal-forward@openssh.com"));
                        req.accept();
                        co_return;
                    });
            });
            co_await serving;

            auto fec = co_await fp.client.request_streamlocal_forward("/tmp/agent.sock");
            REQUIRE_FALSE(fec);

            auto cec = co_await fp.client.cancel_streamlocal_forward("/tmp/agent.sock");
            REQUIRE_FALSE(cec);

            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("tcpip-forward illegal bound payload is invalid_format", "[facade][serve]") {
    auto fp = make_facade_pair();

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &fp.client);
            co_await n.start(&server_session::run, &fp.server);
            co_await handshake_and_password(fp.client, fp.server);

            corral::Event serving;
            n.start([&]() -> corral::Task<void> {
                serving.trigger();
                co_await fp.server.serve(dummy_open, [](inbound_global_request req) -> corral::Task<void> {
                    const std::byte junk[]{std::byte{1}, std::byte{2}, std::byte{3}};
                    req.accept(junk);
                    co_return;
                });
            });
            co_await serving;

            std::uint16_t bound = 0;
            auto fec = co_await fp.client.request_tcpip_forward("127.0.0.1", 0, bound);
            REQUIRE(fec == code::invalid_format);

            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("uninstalled serve_requests denies pty", "[facade][serve]") {
    auto fp = make_facade_pair();

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &fp.client);
            co_await n.start(&server_session::run, &fp.server);
            co_await handshake_and_password(fp.client, fp.server);

            corral::Event serving;
            n.start([&]() -> corral::Task<void> {
                serving.trigger();
                co_await fp.server.serve(
                    [&](inbound_channel_open open) -> corral::Task<void> {
                        channel ch = open.accept();
                        REQUIRE(ch);
                        co_await corral::suspendForever;
                    },
                    dummy_global);
            });
            co_await serving;

            auto opened = co_await fp.client.open_session_channel();
            REQUIRE_FALSE(opened.ec);
            auto pec = co_await opened.ch.request_pty(pty_spec{"xterm", 80, 24});
            REQUIRE(pec == errc::request_denied);

            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("channel serve_requests is serial", "[facade][serve]") {
    auto fp = make_facade_pair();
    int in_flight = 0;
    int max_in_flight = 0;
    int served = 0;
    bool first_done = false;
    bool second_started_early = false;

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &fp.client);
            co_await n.start(&server_session::run, &fp.server);
            co_await handshake_and_password(fp.client, fp.server);

            corral::Event serving;
            n.start([&]() -> corral::Task<void> {
                serving.trigger();
                co_await fp.server.serve(
                    [&](inbound_channel_open open) -> corral::Task<void> {
                        REQUIRE(open.type() == channel_type::session);
                        REQUIRE(open.payload().empty());
                        channel ch = open.accept();
                        REQUIRE(ch);
                        auto reqs = ch.serve_requests(
                            [&](inbound_channel_request req) -> corral::Task<bool> {
                                ++in_flight;
                                max_in_flight = std::max(max_in_flight, in_flight);
                                ++served;
                                if (served == 2 && !first_done) second_started_early = true;
                                corral::Event turn;
                                fp.loop.post([&] { turn.trigger(); });
                                co_await turn;
                                if (served == 1) first_done = true;
                                --in_flight;
                                co_return req.type() == "pty-req" || req.type() == "shell";
                            });
                        co_await std::move(reqs);
                    },
                    dummy_global);
            });
            co_await serving;

            auto opened = co_await fp.client.open_session_channel();
            REQUIRE_FALSE(opened.ec);
            REQUIRE(opened.ch);

            auto [pec, sec] = co_await corral::allOf(
                opened.ch.request_pty(pty_spec{"xterm-256color", 80, 24}),
                opened.ch.request_shell());
            REQUIRE_FALSE(pec);
            REQUIRE_FALSE(sec);
            REQUIRE(served == 2);
            REQUIRE(max_in_flight == 1);
            REQUIRE_FALSE(second_started_early);

            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("serve cancellation restores auto-reject", "[facade][serve]") {
    auto fp = make_facade_pair();

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &fp.client);
            co_await n.start(&server_session::run, &fp.server);
            co_await handshake_and_password(fp.client, fp.server);

            CORRAL_WITH_NURSERY(sn) {
                corral::Event serving;
                sn.start([&]() -> corral::Task<void> {
                    serving.trigger();
                    co_await fp.server.serve(
                        [&](inbound_channel_open open) -> corral::Task<void> {
                            (void)open.accept();
                            co_return;
                        },
                        dummy_global);
                });
                co_await serving;
                co_await drain_turns(fp.loop, 4);
                co_return corral::cancel;
            };

            co_await drain_turns(fp.loop, 4);

            auto opened = co_await fp.client.open_session_channel();
            REQUIRE(opened.ec == errc::request_denied);
            REQUIRE_FALSE(opened.ch);
            REQUIRE(opened.reason == channel_open_reason::administratively_prohibited);

            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}
