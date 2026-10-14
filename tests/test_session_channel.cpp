#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/channel.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/session.hpp>

#include "facade_fixture.hpp"

#include <auv/error.hpp>
#include <auv/stream.hpp>
#include <corral/corral.h>

#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

static_assert(auv::detail::stream_like<channel>);

namespace {

auto accept_host = [](host_key_view) -> corral::Task<bool> { co_return true; };

auto dummy_global = [](inbound_global_request) -> corral::Task<void> { co_return; };

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

TEST_CASE("session channel echo", "[facade][channel]") {
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
                        REQUIRE(open.type() == channel_type::session);
                        channel ch = open.accept();
                        REQUIRE(ch);
                        auv::stream s = auv::stream::borrow(ch);
                        char buf[16];
                        auto [rec, nread] = co_await s.read([&] {
                            return auv::buffer(buf, sizeof(buf));
                        });
                        REQUIRE_FALSE(rec);
                        REQUIRE(nread == 2);
                        REQUIRE(std::memcmp(buf, "hi", 2) == 0);
                        auv::buffer echo{buf, nread};
                        auto wec = co_await s.write(&echo, std::size_t{1});
                        REQUIRE_FALSE(wec);
                    },
                    dummy_global);
            });
            co_await serving;

            auto opened = co_await fp.client.open_session_channel();
            REQUIRE_FALSE(opened.ec);
            REQUIRE(opened.ch);

            auv::stream cs = auv::stream::borrow(opened.ch);
            const char msg[] = "hi";
            auv::buffer wb{msg, 2};
            auto wec = co_await cs.write(&wb, std::size_t{1});
            REQUIRE_FALSE(wec);

            char got[16];
            auto [rec, nread] = co_await cs.read([&] { return auv::buffer(got, sizeof(got)); });
            REQUIRE_FALSE(rec);
            REQUIRE(nread == 2);
            REQUIRE(std::memcmp(got, "hi", 2) == 0);

            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("channel destructor enqueues CLOSE", "[facade][channel]") {
    auto fp = make_facade_pair();
    corral::Event saw_eof;

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
                        auv::stream s = auv::stream::borrow(ch);
                        char buf[8];
                        auto [rec, nread] = co_await s.read([&] {
                            return auv::buffer(buf, sizeof(buf));
                        });
                        REQUIRE(rec == auv::errc::eof);
                        REQUIRE(nread == 0);
                        saw_eof.trigger();
                    },
                    dummy_global);
            });
            co_await serving;

            {
                auto opened = co_await fp.client.open_session_channel();
                REQUIRE_FALSE(opened.ec);
                REQUIRE(opened.ch);
            }

            co_await saw_eof;
            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("channel outlives session handle and drains buffered data", "[facade][channel]") {
    auto fp = make_facade_pair();
    channel surviving;
    constexpr std::string_view payload = "payload-bytes";
    corral::Event serving;
    corral::Event written;

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        auto client_body = [&]() -> corral::Task<void> {
            co_await handshake_and_password(fp.client, fp.server);
            co_await serving;
            auto opened = co_await fp.client.open_session_channel();
            REQUIRE_FALSE(opened.ec);
            surviving = std::move(opened.ch);
            REQUIRE(surviving);
            REQUIRE_FALSE(opened.ch);
            co_await written;
            co_await drain_turns(fp.loop, 6);
        };
        auto server_body = [&]() -> corral::Task<void> {
            CORRAL_WITH_NURSERY(sn) {
                sn.start([&]() -> corral::Task<void> {
                    serving.trigger();
                    co_await fp.server.serve(
                        [&](inbound_channel_open open) -> corral::Task<void> {
                            channel ch = open.accept();
                            auv::stream s = auv::stream::borrow(ch);
                            auv::buffer wb{payload.data(), payload.size()};
                            auto wec = co_await s.write(&wb, std::size_t{1});
                            REQUIRE_FALSE(wec);
                            written.trigger();
                            co_await corral::SuspendForever{};
                        },
                        dummy_global);
                });
                co_await written;
                co_await drain_turns(fp.loop, 6);
                co_return corral::cancel;
            };
        };

        co_await corral::allOf(run_with(fp.client, client_body), run_with(fp.server, server_body));
    }());

    fp.client = {};
    fp.server = {};
    REQUIRE(surviving);

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        auv::stream s = auv::stream::borrow(surviving);
        char buf[32];
        auto [rec, nread] = co_await s.read([&] { return auv::buffer(buf, sizeof(buf)); });
        REQUIRE_FALSE(rec);
        REQUIRE(nread == payload.size());
        REQUIRE(std::string_view(buf, nread) == payload);

        auto [rec2, n2] = co_await s.read([&] { return auv::buffer(buf, sizeof(buf)); });
        REQUIRE((rec2 == auv::errc::eof || rec2 == errc::session_closed));
        REQUIRE(n2 == 0);

        char x = 'x';
        auv::buffer wb{&x, 1};
        auto wec = co_await surviving.write(&wb, std::size_t{1});
        REQUIRE(wec);
        co_return;
    }());
}

TEST_CASE("channel close after peer CLOSE with unread data releases slot", "[facade][channel]") {
    client_options co;
    co.max_channels = 1;
    server_options so;
    so.max_channels = 1;
    auto fp = make_facade_pair(std::move(co), std::move(so));
    constexpr std::string_view payload = "unread";

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &fp.client);
            co_await n.start(&server_session::run, &fp.server);
            co_await handshake_and_password(fp.client, fp.server);

            corral::Event serving;
            corral::Event peer_closed;
            int inbound = 0;
            n.start([&]() -> corral::Task<void> {
                serving.trigger();
                co_await fp.server.serve(
                    [&](inbound_channel_open open) -> corral::Task<void> {
                        channel ch = open.accept();
                        if (++inbound == 1) {
                            auv::buffer wb{payload.data(), payload.size()};
                            auto wec = co_await ch.write(&wb, std::size_t{1});
                            REQUIRE_FALSE(wec);
                            co_await ch.close();
                            peer_closed.trigger();
                            co_await corral::SuspendForever{};
                        }
                        auv::stream s = auv::stream::borrow(ch);
                        char buf[16];
                        auto [rec, nread] = co_await s.read([&] {
                            return auv::buffer(buf, sizeof(buf));
                        });
                        REQUIRE_FALSE(rec);
                        REQUIRE(nread == 2);
                        REQUIRE(std::memcmp(buf, "hi", 2) == 0);
                        auv::buffer echo{buf, nread};
                        auto wec = co_await s.write(&echo, std::size_t{1});
                        REQUIRE_FALSE(wec);
                    },
                    dummy_global);
                co_return;
            });
            co_await serving;

            auto opened = co_await fp.client.open_session_channel();
            REQUIRE_FALSE(opened.ec);
            REQUIRE(opened.ch);

            co_await peer_closed;
            co_await drain_turns(fp.loop, 6);

            co_await opened.ch.close();
            co_await drain_turns(fp.loop, 6);

            auto opened2 = co_await fp.client.open_session_channel();
            REQUIRE_FALSE(opened2.ec);
            REQUIRE(opened2.ch);

            auv::stream cs = auv::stream::borrow(opened2.ch);
            const char msg[] = "hi";
            auv::buffer wb{msg, 2};
            auto wec = co_await cs.write(&wb, std::size_t{1});
            REQUIRE_FALSE(wec);

            char got[16];
            auto [rec, nread] = co_await cs.read([&] { return auv::buffer(got, sizeof(got)); });
            REQUIRE_FALSE(rec);
            REQUIRE(nread == 2);
            REQUIRE(std::memcmp(got, "hi", 2) == 0);

            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("pty-req then shell then data", "[facade][channel][pty]") {
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
                        REQUIRE(open.type() == channel_type::session);
                        channel ch = open.accept();
                        REQUIRE(ch);
                        auto reqs = ch.serve_requests(
                            [](inbound_channel_request req) -> corral::Task<bool> {
                                if (auto pty = req.pty()) {
                                    REQUIRE(pty->term == "xterm-256color");
                                    REQUIRE(pty->width == 80);
                                    REQUIRE(pty->height == 24);
                                    co_return true;
                                }
                                if (req.type() == "shell") co_return true;
                                co_return false;
                            });
                        CORRAL_WITH_NURSERY(cn) {
                            cn.start([&]() -> corral::Task<void> {
                                co_await std::move(reqs);
                            });
                            auv::stream s = auv::stream::borrow(ch);
                            char buf[16];
                            auto [rec, nread] = co_await s.read([&] {
                                return auv::buffer(buf, sizeof(buf));
                            });
                            REQUIRE_FALSE(rec);
                            REQUIRE(nread == 2);
                            REQUIRE(std::memcmp(buf, "hi", 2) == 0);
                            auv::buffer echo{buf, nread};
                            auto wec = co_await s.write(&echo, std::size_t{1});
                            REQUIRE_FALSE(wec);
                            co_return corral::cancel;
                        };
                    },
                    dummy_global);
            });
            co_await serving;

            auto opened = co_await fp.client.open_session_channel();
            REQUIRE_FALSE(opened.ec);
            REQUIRE(opened.ch);

            auto pec = co_await opened.ch.request_pty(pty_spec{"xterm-256color", 80, 24});
            REQUIRE_FALSE(pec);
            auto sec = co_await opened.ch.request_shell();
            REQUIRE_FALSE(sec);

            auv::stream cs = auv::stream::borrow(opened.ch);
            const char msg[] = "hi";
            auv::buffer wb{msg, 2};
            auto wec = co_await cs.write(&wb, std::size_t{1});
            REQUIRE_FALSE(wec);

            char got[16];
            auto [rec, nread] = co_await cs.read([&] { return auv::buffer(got, sizeof(got)); });
            REQUIRE_FALSE(rec);
            REQUIRE(nread == 2);
            REQUIRE(std::memcmp(got, "hi", 2) == 0);

            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("direct-tcpip open payload round-trip", "[facade][channel][tcp]") {
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
                        REQUIRE(open.type() == channel_type::direct_tcpip);
                        REQUIRE(open.host() == "127.0.0.1");
                        REQUIRE(open.port() == 9);
                        REQUIRE(open.originator_host() == "0.0.0.0");
                        REQUIRE(open.originator_port() == 0);
                        wire::writer encoded;
                        channels::encode_direct_tcpip(
                            encoded, "127.0.0.1", 9, "0.0.0.0", 0);
                        const auto want = encoded.take();
                        std::vector<std::byte> got(open.payload().begin(), open.payload().end());
                        REQUIRE(got == want);
                        channel ch = open.accept();
                        REQUIRE(ch);
                        auv::stream s = auv::stream::borrow(ch);
                        char buf[16];
                        auto [rec, nread] = co_await s.read([&] {
                            return auv::buffer(buf, sizeof(buf));
                        });
                        REQUIRE_FALSE(rec);
                        REQUIRE(nread == 2);
                        REQUIRE(std::memcmp(buf, "hi", 2) == 0);
                        auv::buffer echo{buf, nread};
                        auto wec = co_await s.write(&echo, std::size_t{1});
                        REQUIRE_FALSE(wec);
                    },
                    dummy_global);
            });
            co_await serving;

            auto opened = co_await fp.client.open_direct_tcpip("127.0.0.1", 9, "0.0.0.0", 0);
            REQUIRE_FALSE(opened.ec);
            REQUIRE(opened.ch);

            auv::stream cs = auv::stream::borrow(opened.ch);
            const char msg[] = "hi";
            auv::buffer wb{msg, 2};
            auto wec = co_await cs.write(&wb, std::size_t{1});
            REQUIRE_FALSE(wec);

            char got[16];
            auto [rec, nread] = co_await cs.read([&] { return auv::buffer(got, sizeof(got)); });
            REQUIRE_FALSE(rec);
            REQUIRE(nread == 2);
            REQUIRE(std::memcmp(got, "hi", 2) == 0);

            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("x11-req extra round-trips through serve_requests", "[facade][channel][x11]") {
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
                        REQUIRE(open.type() == channel_type::session);
                        channel ch = open.accept();
                        REQUIRE(ch);
                        co_await ch.serve_requests(
                            [](inbound_channel_request req) -> corral::Task<bool> {
                                auto x11 = req.x11();
                                REQUIRE(x11);
                                REQUIRE(x11->single_connection);
                                REQUIRE(x11->protocol == "MIT-MAGIC-COOKIE-1");
                                REQUIRE(x11->cookie == "aabbccdd");
                                REQUIRE(x11->screen == 1);
                                co_return true;
                            });
                    },
                    dummy_global);
            });
            co_await serving;

            auto opened = co_await fp.client.open_session_channel();
            REQUIRE_FALSE(opened.ec);
            auto xec = co_await opened.ch.request_x11(
                x11_req_spec{true, "MIT-MAGIC-COOKIE-1", "aabbccdd", 1});
            REQUIRE_FALSE(xec);

            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("forwarded-streamlocal open payload round-trip", "[facade][channel]") {
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
                        REQUIRE(open.type() == channel_type::forwarded_streamlocal);
                        REQUIRE(open.socket_path() == "/tmp/fwd.sock");
                        wire::writer encoded;
                        channels::encode_forwarded_streamlocal(encoded,
                                                                             "/tmp/fwd.sock");
                        const auto want = encoded.take();
                        std::vector<std::byte> got(open.payload().begin(), open.payload().end());
                        REQUIRE(got == want);
                        channel ch = open.accept();
                        REQUIRE(ch);
                        co_await corral::SuspendForever{};
                    },
                    dummy_global);
            });
            co_await serving;

            auto opened = co_await fp.client.open_forwarded_streamlocal("/tmp/fwd.sock");
            REQUIRE_FALSE(opened.ec);
            REQUIRE(opened.ch);

            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("pipelined pty then shell both complete", "[facade][channel]") {
    auto fp = make_facade_pair();
    int served = 0;

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
                        channel ch = open.accept();
                        REQUIRE(ch);
                        auto reqs = ch.serve_requests(
                            [&](inbound_channel_request req) -> corral::Task<bool> {
                                ++served;
                                if (auto pty = req.pty()) {
                                    REQUIRE(pty->term == "xterm-256color");
                                    REQUIRE(pty->width == 80);
                                    REQUIRE(pty->height == 24);
                                    corral::Event turn;
                                    fp.loop.post([&] { turn.trigger(); });
                                    co_await turn;
                                    co_return true;
                                }
                                if (req.type() == "shell") co_return true;
                                co_return false;
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

            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("same-batch channel request then CLOSE does not latch", "[facade][channel]") {
    auto fp = make_facade_pair();
    int served = 0;

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
                        channel ch = open.accept();
                        REQUIRE(ch);
                        auto reqs = ch.serve_requests(
                            [&](inbound_channel_request req) -> corral::Task<bool> {
                                ++served;
                                REQUIRE(req.type() == "window-change");
                                co_return true;
                            });
                        co_await std::move(reqs);
                    },
                    dummy_global);
            });
            co_await serving;

            auto opened = co_await fp.client.open_session_channel();
            REQUIRE_FALSE(opened.ec);
            REQUIRE(opened.ch);

            auto wec = co_await opened.ch.request_window_change(window_size{80, 24});
            REQUIRE_FALSE(wec);
            co_await opened.ch.close();

            corral::Event turn;
            fp.loop.post([&] { turn.trigger(); });
            co_await turn;

            REQUIRE_FALSE(fp.server.failure());
            REQUIRE_FALSE(fp.client.failure());
            REQUIRE(served == 1);

            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}
