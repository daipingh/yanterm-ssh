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

// Handshake and authentication drive themselves: no nursery and no serve().
corral::Task<client_session> authenticated_client(client_session cs) {
    auto hs = co_await cs.handshake(accept_host);
    if (hs) co_return client_session{};
    auto [aec, result] = co_await cs.auth_password("alice", "s3cret");
    if (aec || !result.success) co_return client_session{};
    co_return std::move(cs);
}

}  // namespace

TEST_CASE("channel and global calls before serve return invalid_state", "[facade][serve]") {
    auto fp = make_facade_pair();

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        co_await handshake_and_password(fp.client, fp.server);

        auto opened = co_await fp.client.open_session_channel();
        REQUIRE(opened.ec == code::invalid_state);
        REQUIRE_FALSE(opened.ch);

        auto gec = co_await fp.client.send_global_request("tcpip-forward", {}, true);
        REQUIRE(gec == code::invalid_state);

        auto rec = co_await fp.client.rekey();
        REQUIRE(rec == code::invalid_state);
        auto kec = co_await fp.client.send_keepalive();
        REQUIRE(kec == code::invalid_state);
    }());
}

TEST_CASE("serve before authentication returns invalid_state", "[facade][serve]") {
    auto fp = make_facade_pair();

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        auto [cec, sec] = co_await corral::allOf(fp.client.handshake(accept_host), fp.server.handshake());
        REQUIRE_FALSE(cec);
        REQUIRE_FALSE(sec);

        auto client_serve = co_await fp.client.serve(reject_inbound, reject_inbound);
        REQUIRE(client_serve == code::invalid_state);
        auto server_serve = co_await fp.server.serve(dummy_open, dummy_global);
        REQUIRE(server_serve == code::invalid_state);
        REQUIRE_FALSE(fp.client.failure());
        REQUIRE_FALSE(fp.server.failure());
    }());
}

TEST_CASE("tcpip-forward global request", "[facade][serve]") {
    auto fp = make_facade_pair();

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        co_await handshake_and_password(fp.client, fp.server);
        co_await fp.client.serve(reject_inbound, reject_inbound, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {

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
        });
    }());
}

TEST_CASE("streamlocal-forward global request", "[facade][serve]") {
    auto fp = make_facade_pair();

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        co_await handshake_and_password(fp.client, fp.server);
        co_await fp.client.serve(reject_inbound, reject_inbound, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {

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
        });
    }());
}

TEST_CASE("tcpip-forward illegal bound payload is invalid_format", "[facade][serve]") {
    auto fp = make_facade_pair();

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        co_await handshake_and_password(fp.client, fp.server);
        co_await fp.client.serve(reject_inbound, reject_inbound, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {

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
        });
    }());
}

TEST_CASE("uninstalled serve_requests denies pty", "[facade][serve]") {
    auto fp = make_facade_pair();

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        co_await handshake_and_password(fp.client, fp.server);
        co_await fp.client.serve(reject_inbound, reject_inbound, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {

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
        });
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
        co_await handshake_and_password(fp.client, fp.server);
        co_await fp.client.serve(reject_inbound, reject_inbound, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {

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
        });
    }());
}

TEST_CASE("cancelling serve sends no DISCONNECT and latches session_closed", "[facade][serve]") {
    auto fp = make_facade_pair();

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        co_await handshake_and_password(fp.client, fp.server);

        co_await corral::allOf(
            [&]() -> corral::Task<void> {
                CORRAL_WITH_NURSERY(n) {
                    n.start([&]() -> corral::Task<void> {
                        (void)co_await fp.client.serve(
                            reject_inbound, reject_inbound, [&]() -> corral::Task<void> {
                                co_await corral::suspendForever;
                            });
                    });
                    co_await drain_turns(fp.loop, 4);
                    co_return corral::cancel;
                };
                REQUIRE(fp.client.failure() == code::session_closed);
                REQUIRE(fp.client.disconnected() == nullptr);
                co_await drain_turns(fp.loop, 8);
                REQUIRE(fp.server.disconnected() == nullptr);
                co_await fp.server.disconnect(disconnect_reason::by_application, "cleanup");
            }(),
            fp.server.serve(dummy_open, dummy_global));
    }());

    REQUIRE(fp.client.failure() == code::session_closed);
    REQUIRE(fp.server.disconnected() == nullptr);
}

TEST_CASE("factory returns a ready client session that serve opens", "[facade][serve]") {
    auto fp = make_facade_pair();
    client_session ready;

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        co_await corral::allOf(
            [&]() -> corral::Task<void> {
                auto hs = co_await fp.server.handshake();
                REQUIRE_FALSE(hs);
                auto aec = co_await fp.server.authenticate(
                    [](auth_request req) -> corral::Task<auth_verdict> {
                        if (req.method() == "password" && req.user() == "alice" &&
                            req.password() == "s3cret") {
                            co_return auth_verdict::success();
                        }
                        co_return auth_verdict::failure("password");
                    });
                REQUIRE_FALSE(aec);
                (void)co_await fp.server.serve(
                    [&](inbound_channel_open open) -> corral::Task<void> {
                        channel ch = open.accept();
                        REQUIRE(ch);
                        co_await fp.server.until_closed();
                    },
                    dummy_global);
            }(),
            [&]() -> corral::Task<void> {
                ready = co_await authenticated_client(std::move(fp.client));
                REQUIRE(ready);
                auto ec = co_await ready.serve(
                    reject_inbound, reject_inbound, [&]() -> corral::Task<void> {
                        auto opened = co_await ready.open_session_channel();
                        REQUIRE_FALSE(opened.ec);
                        REQUIRE(opened.ch);
                    });
                REQUIRE_FALSE(ec);
            }());
    }());

    REQUIRE(ready);
    REQUIRE_FALSE(fp.client);
}

TEST_CASE("serve body return disconnects by_application", "[facade][serve]") {
    auto fp = make_facade_pair();
    std::error_code client_ec;
    std::error_code server_ec;

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        co_await handshake_and_password(fp.client, fp.server);
        auto done = co_await corral::allOf(
            fp.server.serve(dummy_open, dummy_global),
            fp.client.serve(reject_inbound, reject_inbound,
                            [&]() -> corral::Task<void> { co_return; }));
        server_ec = std::get<0>(done);
        client_ec = std::get<1>(done);
    }());

    REQUIRE_FALSE(client_ec);
    REQUIRE_FALSE(server_ec);
    REQUIRE(fp.server.disconnected() != nullptr);
    REQUIRE(fp.server.disconnected()->reason == disconnect_reason::by_application);
}

TEST_CASE("peer protocol_error lets the serve body continue", "[facade][serve]") {
    auto fp = make_facade_pair();
    bool continued = false;
    std::error_code client_ec;
    std::error_code server_ec;
    const disconnect_info* disc = nullptr;

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        co_await handshake_and_password(fp.client, fp.server);
        co_await corral::allOf(
            [&]() -> corral::Task<void> {
                server_ec = co_await fp.server.serve(
                    dummy_open, dummy_global, [&]() -> corral::Task<void> {
                        co_await fp.server.disconnect(disconnect_reason::protocol_error, "boom");
                    });
            }(),
            [&]() -> corral::Task<void> {
                client_ec = co_await fp.client.serve(
                    reject_inbound, reject_inbound, [&]() -> corral::Task<void> {
                        co_await fp.client.until_closed();
                        continued = true;
                    });
            }());
        const auto failure_before = fp.client.failure();
        disc = fp.client.disconnected();
        REQUIRE(disc != nullptr);
        const auto reason = disc->reason;
        co_await fp.client.until_closed();
        REQUIRE(fp.client.failure() == failure_before);
        REQUIRE(fp.client.disconnected() == disc);
        REQUIRE(fp.client.disconnected()->reason == reason);
        auto again = co_await fp.client.serve(reject_inbound, reject_inbound);
        REQUIRE(again == code::peer_disconnected);
    }());

    REQUIRE(continued);
    REQUIRE(client_ec == code::peer_disconnected);
    REQUIRE_FALSE(server_ec);
    REQUIRE(disc != nullptr);
    REQUIRE(disc->reason == disconnect_reason::protocol_error);
}

TEST_CASE("serve body that disconnects itself is not cancelled", "[facade][serve]") {
    auto fp = make_facade_pair();
    bool after_disconnect = false;
    std::error_code client_ec;
    std::error_code server_ec;

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        co_await handshake_and_password(fp.client, fp.server);
        co_await corral::allOf(
            [&]() -> corral::Task<void> {
                server_ec = co_await fp.server.serve(dummy_open, dummy_global);
            }(),
            [&]() -> corral::Task<void> {
                client_ec = co_await fp.client.serve(
                    reject_inbound, reject_inbound, [&]() -> corral::Task<void> {
                        co_await fp.client.disconnect(disconnect_reason::by_application, "bye");
                        after_disconnect = true;
                    });
            }());
    }());

    REQUIRE(after_disconnect);
    REQUIRE_FALSE(client_ec);
    REQUIRE_FALSE(server_ec);
    REQUIRE(fp.server.disconnected() != nullptr);
    REQUIRE(fp.server.disconnected()->reason == disconnect_reason::by_application);
}

TEST_CASE("server delay before serve does not deny the client open", "[facade][serve]") {
    auto fp = make_facade_pair();
    std::error_code open_ec;

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        co_await handshake_and_password(fp.client, fp.server);
        co_await corral::allOf(
            [&]() -> corral::Task<void> {
                co_await drain_turns(fp.loop, 8);
                (void)co_await fp.server.serve(
                    [&](inbound_channel_open open) -> corral::Task<void> {
                        channel ch = open.accept();
                        REQUIRE(ch);
                        co_await fp.server.until_closed();
                    },
                    dummy_global);
            }(),
            fp.client.serve(reject_inbound, reject_inbound, [&]() -> corral::Task<void> {
                auto opened = co_await fp.client.open_session_channel();
                open_ec = opened.ec;
                REQUIRE_FALSE(opened.ec);
                REQUIRE(opened.ch);
            }));
    }());

    REQUIRE_FALSE(open_ec);
}

TEST_CASE("cancelling serve unblocks a disconnect waiting on the write pump",
          "[facade][serve]") {
    TestLoop loop;
    auto [client_end, server_end] = memory_pipe::make(loop);
    auto stall_server_reads = server_end.stall_reads();
    auto p = prov();
    server_options so;
    so.host_keys.push_back(parse_host_key_file(p, "id_ed25519"));
    client_session cs{auv::stream::own(std::move(client_end)), p, client_options{}};
    server_session ss{auv::stream::own(std::move(server_end)), p, std::move(so)};
    bool disconnect_returned = false;

    corral::run(loop, [&]() -> corral::Task<void> {
        auto [cec, sec] = co_await corral::allOf(
            cs.handshake([](host_key_view) -> corral::Task<bool> { co_return true; }),
            ss.handshake());
        REQUIRE_FALSE(cec);
        REQUIRE_FALSE(sec);
        auto authed = co_await corral::allOf(
            cs.auth_password("alice", "s3cret"),
            ss.authenticate([](auth_request) -> corral::Task<auth_verdict> {
                co_return auth_verdict::success();
            }));
        auto [pec, result] = std::get<0>(authed);
        REQUIRE_FALSE(pec);
        REQUIRE(result.success);
        REQUIRE_FALSE(std::get<1>(authed));

        // With the peer not reading, the client's DISCONNECT cannot be
        // flushed, so disconnect() is still waiting when serve is cancelled.
        stall_server_reads = true;
        corral::Event pumps_up;
        co_await corral::allOf(
            ss.serve(reject_inbound, reject_inbound),
            [&]() -> corral::Task<void> {
                CORRAL_WITH_NURSERY(live) {
                    live.start([&]() -> corral::Task<void> {
                        co_await pumps_up;
                        co_await cs.disconnect(disconnect_reason::by_application, "bye");
                        disconnect_returned = true;
                    });
                    CORRAL_WITH_NURSERY(n) {
                        n.start([&]() -> corral::Task<void> {
                            (void)co_await cs.serve(
                                reject_inbound, reject_inbound, [&]() -> corral::Task<void> {
                                    pumps_up.trigger();
                                    co_await corral::suspendForever;
                                });
                        });
                        co_await pumps_up;
                        co_await drain_turns(loop, 2);
                        co_return corral::cancel;
                    };
                    co_return corral::join;
                };
                stall_server_reads = false;
                co_await ss.disconnect(disconnect_reason::by_application, "cleanup");
            }());
    }());

    REQUIRE(disconnect_returned);
    REQUIRE(cs.failure() == code::session_closed);
}

TEST_CASE("authenticate writes USERAUTH_SUCCESS before serve", "[facade][auth]") {
    auto fp = make_facade_pair();
    bool client_auth_done = false;

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        co_await corral::allOf(
            [&]() -> corral::Task<void> {
                auto hs = co_await fp.server.handshake();
                REQUIRE_FALSE(hs);
                auto aec = co_await fp.server.authenticate(
                    [](auth_request req) -> corral::Task<auth_verdict> {
                        if (req.method() == "password" && req.user() == "alice" &&
                            req.password() == "s3cret") {
                            co_return auth_verdict::success();
                        }
                        co_return auth_verdict::failure("password");
                    });
                REQUIRE_FALSE(aec);
                co_await drain_turns(fp.loop, 8);
                REQUIRE(client_auth_done);
                (void)co_await fp.server.serve(dummy_open, dummy_global);
            }(),
            [&]() -> corral::Task<void> {
                auto hs = co_await fp.client.handshake(accept_host);
                REQUIRE_FALSE(hs);
                auto auth = co_await fp.client.auth_password("alice", "s3cret");
                auto [aec, result] = auth;
                REQUIRE_FALSE(aec);
                REQUIRE(result.success);
                client_auth_done = true;
                auto sec = co_await fp.client.serve(
                    reject_inbound, reject_inbound, [&]() -> corral::Task<void> { co_return; });
                REQUIRE_FALSE(sec);
            }());
    }());

    REQUIRE(client_auth_done);
}
