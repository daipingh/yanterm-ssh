#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/channel.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/session.hpp>

#include "counting_resource.hpp"
#include "facade_fixture.hpp"

#include <auv/error.hpp>
#include <auv/stream.hpp>
#include <corral/corral.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

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

corral::Task<void> echo_once(channel& ch, std::string_view msg) {
    auv::stream s = auv::stream::borrow(ch);
    auv::buffer wb{msg.data(), msg.size()};
    auto wec = co_await s.write(&wb, std::size_t{1});
    REQUIRE_FALSE(wec);
    char got[32];
    auto [rec, nread] = co_await s.read([&] { return auv::buffer(got, sizeof(got)); });
    REQUIRE_FALSE(rec);
    REQUIRE(nread == msg.size());
    REQUIRE(std::string_view(got, nread) == msg);
}

}  // namespace

TEST_CASE("cancelling channel.read keeps data", "[facade][cancel]") {
    auto fp = make_facade_pair();
    constexpr std::string_view payload = "0123456789abcdef";
    corral::Event read_cancelled;

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
                        co_await read_cancelled;
                        auv::buffer wb{payload.data(), payload.size()};
                        auto wec = co_await ch.write(&wb, std::size_t{1});
                        REQUIRE_FALSE(wec);
                    },
                    dummy_global);
            });
            co_await serving;

            auto opened = co_await fp.client.open_session_channel();
            REQUIRE_FALSE(opened.ec);
            REQUIRE(opened.ch);

            char buf[32];
            auv::stream cs = auv::stream::borrow(opened.ch);
            auto [got, ign] = co_await corral::anyOf(
                cs.read([&] { return auv::buffer(buf, sizeof(buf)); }), corral::noop());
            REQUIRE_FALSE(got.has_value());
            (void)ign;
            read_cancelled.trigger();

            auto [rec, nread] = co_await cs.read([&] { return auv::buffer(buf, sizeof(buf)); });
            REQUIRE_FALSE(rec);
            REQUIRE(nread == payload.size());
            REQUIRE(std::string_view(buf, nread) == payload);

            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("cancelled channel reply waiter does not steal next reply", "[facade][cancel]") {
    auto fp = make_facade_pair();
    corral::Event first_in_flight;
    corral::Event cancel_first;
    corral::Event allow_server_replies;
    std::optional<std::error_code> second_ec;

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
                        co_await ch.serve_requests([&](inbound_channel_request req) -> corral::Task<bool> {
                            co_await allow_server_replies;
                            if (req.type() == "env") {
                                if (auto env = req.env()) {
                                    if (env->first == "ONE") co_return false;
                                    if (env->first == "TWO") co_return true;
                                }
                            }
                            co_return false;
                        });
                    },
                    dummy_global);
            });
            co_await serving;

            auto opened = co_await fp.client.open_session_channel();
            REQUIRE_FALSE(opened.ec);
            REQUIRE(opened.ch);

            n.start([&]() -> corral::Task<void> {
                first_in_flight.trigger();
                co_await corral::anyOf(opened.ch.request_env("ONE", "1"), cancel_first);
            });
            n.start([&]() -> corral::Task<void> {
                co_await first_in_flight;
                second_ec = co_await opened.ch.request_env("TWO", "2");
            });
            co_await first_in_flight;
            cancel_first.trigger();
            allow_server_replies.trigger();
            for (int i = 0; i < 64 && !second_ec.has_value(); ++i) {
                co_await drain_turns(fp.loop, 1);
            }
            REQUIRE(second_ec.has_value());
            REQUIRE(*second_ec == std::error_code{});

            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("cancelling open_session_channel abandons", "[facade][cancel]") {
    counting_resource client_res;
    TestLoop loop;
    auto [a, b] = memory_pipe::make(loop);
    auto p = prov();
    server_options so;
    so.host_keys.push_back(parse_host_key_file(p, "id_ed25519"));
    client_session client{auv::stream::own(std::move(a)), p, {}, &client_res};
    server_session server{auv::stream::own(std::move(b)), p, std::move(so)};

    corral::Event got_open;
    corral::Event allow_accept;
    bool saw_close = false;

    corral::run(loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &client);
            co_await n.start(&server_session::run, &server);
            co_await handshake_and_password(client, server);
            const std::size_t baseline_blocks = client_res.outstanding_blocks();

            corral::Event serving;
            n.start([&]() -> corral::Task<void> {
                serving.trigger();
                co_await server.serve(
                    [&](inbound_channel_open open) -> corral::Task<void> {
                        REQUIRE(open.type() == channel_type::session);
                        got_open.trigger();
                        co_await allow_accept;
                        channel ch = open.accept();
                        REQUIRE(ch);
                        auv::stream s = auv::stream::borrow(ch);
                        char buf[8];
                        auto [rec, nread] =
                            co_await s.read([&] { return auv::buffer(buf, sizeof(buf)); });
                        REQUIRE(rec == auv::errc::eof);
                        REQUIRE(nread == 0);
                        saw_close = true;
                    },
                    dummy_global);
            });
            co_await serving;

            CORRAL_WITH_NURSERY(open_n) {
                open_n.start([&]() -> corral::Task<void> {
                    auto opened = co_await client.open_session_channel();
                    (void)opened;
                    co_return;
                });
                co_await got_open;
                co_return corral::cancel;
            };

            allow_accept.trigger();
            for (int i = 0; i < 64 && !saw_close; ++i) {
                co_await drain_turns(loop, 1);
            }
            REQUIRE(saw_close);
            co_await drain_turns(loop, 16);
            REQUIRE(client_res.outstanding_blocks() == baseline_blocks);

            co_await client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("session close while opening drops the channel state", "[facade][cancel]") {
    TestLoop loop;
    auto [a, b] = memory_pipe::make(loop);
    auto p = prov();
    server_options so;
    so.host_keys.push_back(parse_host_key_file(p, "id_ed25519"));
    client_session client{auv::stream::own(std::move(a)), p, {}};
    server_session server{auv::stream::own(std::move(b)), p, std::move(so)};

    corral::Event got_open;
    corral::Event allow_accept;

    corral::run(loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &client);
            co_await n.start(&server_session::run, &server);
            co_await handshake_and_password(client, server);

            corral::Event serving;
            n.start([&]() -> corral::Task<void> {
                serving.trigger();
                co_await server.serve(
                    [&](inbound_channel_open open) -> corral::Task<void> {
                        got_open.trigger();
                        co_await allow_accept;
                        (void)open;
                        co_return;
                    },
                    dummy_global);
            });
            co_await serving;

            channel_open_result opened;
            CORRAL_WITH_NURSERY(open_n) {
                open_n.start([&]() -> corral::Task<void> {
                    opened = co_await client.open_session_channel();
                    co_return;
                });
                co_await got_open;
                co_await client.disconnect(disconnect_reason::by_application, "done");
                co_return corral::cancel;
            };
            REQUIRE(opened.ec == errc::session_closed);
            REQUIRE_FALSE(opened.ch);
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("write waits for output watermark", "[facade][backpressure]") {
    TestLoop loop;
    auto [a, b] = memory_pipe::make(loop);
    auto stall_server = b.stall_reads();
    crypto::openssl_backend backend;
    auto p = crypto::provider::wrap(backend);
    client_options co;
    co.max_output_bytes = 1024;
    server_options so;
    so.host_keys.push_back(parse_host_key_file(p, "id_ed25519"));
    client_session client{auv::stream::own(std::move(a)), p, std::move(co)};
    server_session server{auv::stream::own(std::move(b)), p, std::move(so)};

    std::vector<char> payload(64u * 1024u, 'x');
    bool write_done = false;
    std::error_code write_ec;

    corral::run(loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &client);
            co_await n.start(&server_session::run, &server);
            co_await handshake_and_password(client, server);

            corral::Event serving;
            n.start([&]() -> corral::Task<void> {
                serving.trigger();
                co_await server.serve(
                    [&](inbound_channel_open open) -> corral::Task<void> {
                        channel ch = open.accept();
                        REQUIRE(ch);
                        co_await corral::SuspendForever{};
                    },
                    dummy_global);
            });
            co_await serving;

            auto opened = co_await client.open_session_channel();
            REQUIRE_FALSE(opened.ec);
            REQUIRE(opened.ch);

            stall_server = true;
            n.start([&]() -> corral::Task<void> {
                auv::buffer wb{payload.data(), payload.size()};
                write_ec = co_await opened.ch.write(&wb, std::size_t{1});
                write_done = true;
            });
            co_await drain_turns(loop, 16);
            REQUIRE_FALSE(write_done);

            stall_server = false;
            for (int i = 0; i < 64 && !write_done; ++i) {
                corral::Event turn;
                loop.post([&] { turn.trigger(); });
                co_await turn;
            }
            REQUIRE(write_done);
            REQUIRE_FALSE(write_ec);

            co_await client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("rekey while echoing", "[facade][rekey]") {
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
                        auv::stream s = auv::stream::borrow(ch);
                        for (;;) {
                            char buf[32];
                            auto [rec, nread] = co_await s.read([&] {
                                return auv::buffer(buf, sizeof(buf));
                            });
                            if (rec) break;
                            auv::buffer echo{buf, nread};
                            auto wec = co_await s.write(&echo, std::size_t{1});
                            REQUIRE_FALSE(wec);
                        }
                    },
                    dummy_global);
            });
            co_await serving;

            auto opened = co_await fp.client.open_session_channel();
            REQUIRE_FALSE(opened.ec);
            REQUIRE(opened.ch);

            co_await echo_once(opened.ch, "one");
            std::vector<std::byte> sid(fp.client.session_id().begin(),
                                       fp.client.session_id().end());
            auto rec = co_await fp.client.rekey();
            REQUIRE_FALSE(rec);
            REQUIRE(fp.client.negotiated() != nullptr);
            REQUIRE(std::equal(sid.begin(), sid.end(), fp.client.session_id().begin(),
                               fp.client.session_id().end()));
            co_await echo_once(opened.ch, "two");

            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("send_keepalive", "[facade][keepalive]") {
    auto fp = make_facade_pair();
    bool saw_keepalive = false;

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &fp.client);
            co_await n.start(&server_session::run, &fp.server);
            co_await handshake_and_password(fp.client, fp.server);

            corral::Event serving;
            n.start([&]() -> corral::Task<void> {
                serving.trigger();
                co_await fp.server.serve(
                    [](inbound_channel_open open) -> corral::Task<void> {
                        open.reject(channel_open_reason::administratively_prohibited,
                                    "none");
                        co_return;
                    },
                    [&](inbound_global_request req) -> corral::Task<void> {
                        if (req.type() == "keepalive@openssh.com") {
                            saw_keepalive = true;
                            req.accept();
                            co_return;
                        }
                        req.reject();
                    });
            });
            co_await serving;

            auto kec = co_await fp.client.send_keepalive();
            REQUIRE_FALSE(kec);
            REQUIRE(saw_keepalive);

            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}
