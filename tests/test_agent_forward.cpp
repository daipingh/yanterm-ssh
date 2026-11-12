#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/agent.hpp>
#include <yanterm-ssh/core/detail/auth_signature.hpp>
#include <yanterm-ssh/crypto/algorithms.hpp>
#include <yanterm-ssh/detail/error.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/keys/public_key.hpp>

#include "facade_fixture.hpp"
#include "memory_pipe.hpp"

#include <corral/corral.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

namespace {

auto accept_host = [](host_key_view) -> corral::Task<bool> { co_return true; };

auto reject_open = [](inbound_channel_open open) -> corral::Task<void> {
    open.reject(channel_open_reason::administratively_prohibited, "app");
    co_return;
};

auto reject_global = [](inbound_global_request req) -> corral::Task<void> {
    req.reject();
    co_return;
};

std::vector<std::byte> frame_of(std::span<const std::byte> payload) {
    std::vector<std::byte> out(4 + payload.size());
    const auto n = static_cast<std::uint32_t>(payload.size());
    out[0] = static_cast<std::byte>(n >> 24);
    out[1] = static_cast<std::byte>(n >> 16);
    out[2] = static_cast<std::byte>(n >> 8);
    out[3] = static_cast<std::byte>(n);
    std::memcpy(out.data() + 4, payload.data(), payload.size());
    return out;
}

corral::Task<std::tuple<std::error_code, std::size_t>> read_some(memory_pipe::end& peer,
                                                                     std::span<char> dst) {
    auv::buffer buf{dst.data(), dst.size()};
    co_return co_await peer.read([](void* p) { return *static_cast<auv::buffer*>(p); }, &buf);
}

corral::Task<std::error_code> write_bytes(memory_pipe::end& peer, std::span<const std::byte> bytes) {
    std::vector<char> copy(bytes.size());
    if (!bytes.empty()) std::memcpy(copy.data(), bytes.data(), bytes.size());
    auv::buffer buf{copy.data(), copy.size()};
    const std::size_t nbufs = 1;
    co_return co_await peer.write(&buf, nbufs);
}

corral::Task<std::vector<std::byte>> read_frame(memory_pipe::end& peer) {
    std::byte hdr[4];
    std::size_t got = 0;
    while (got < 4) {
        auto [ec, n] = co_await read_some(peer, {reinterpret_cast<char*>(hdr + got), 4 - got});
        if (ec) co_return std::vector<std::byte>{};
        got += n;
    }
    const auto len = (std::to_integer<std::uint32_t>(hdr[0]) << 24)
                     | (std::to_integer<std::uint32_t>(hdr[1]) << 16)
                     | (std::to_integer<std::uint32_t>(hdr[2]) << 8)
                     | std::to_integer<std::uint32_t>(hdr[3]);
    std::vector<std::byte> body(len);
    got = 0;
    while (got < len) {
        auto [ec, n] =
            co_await read_some(peer, {reinterpret_cast<char*>(body.data() + got), len - got});
        if (ec) co_return std::vector<std::byte>{};
        got += n;
    }
    co_return body;
}

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

struct user_key {
    std::array<std::byte, crypto::max_generated_key_storage> storage{};
    crypto::private_key_material priv{};
    keys::public_key pk;

    [[nodiscard]] std::span<const std::byte> blob() const { return pk.blob(); }
};

void generate_user_key(crypto::provider p, user_key& k) {
    REQUIRE(p.generate_keypair(crypto::sig_id::ed25519, 0, k.priv, k.storage));
    crypto::public_key_material pub{crypto::sig_id::ed25519, k.priv.public_key, {}};
    REQUIRE_FALSE(keys::public_key::from_material(pub, k.pk));
}

}  // namespace

TEST_CASE("bind_agent_session sends the three materials or nothing", "[agent][bind]") {
    auto fp = make_facade_pair();
    auto [local, peer] = memory_pipe::make(fp.loop);
    basic_agent_client<memory_pipe::end> agent{std::move(local)};

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        bool saw_bytes = false;
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                char buf[8];
                auto [ec, nread] = co_await read_some(peer, {buf, sizeof buf});
                if (!ec && nread > 0) saw_bytes = true;
                co_return;
            });
            const auto ec = co_await bind_agent_session(agent, fp.client, false);
            REQUIRE(ec == code::invalid_state);
            co_return corral::cancel;
        };
        REQUIRE_FALSE(saw_bytes);

        auto [cec, sec] =
            co_await corral::allOf(fp.client.handshake(accept_host), fp.server.handshake());
        REQUIRE_FALSE(cec);
        REQUIRE_FALSE(sec);
        REQUIRE(fp.client.supports_hostbound_publickey());
        REQUIRE_FALSE(fp.client.initial_host_key().empty());
        REQUIRE_FALSE(fp.client.initial_kex_signature().empty());
        REQUIRE_FALSE(fp.client.session_id().empty());

        for (const bool forwarding : {false, true}) {
            CORRAL_WITH_NURSERY(n) {
                n.start([&]() -> corral::Task<void> {
                    const auto body = co_await read_frame(peer);
                    REQUIRE_FALSE(body.empty());
                    std::span<const std::byte> host;
                    std::span<const std::byte> sid;
                    std::span<const std::byte> sig;
                    bool flag = !forwarding;
                    REQUIRE(agent::decode_session_bind(body, host, sid, sig, flag));
                    REQUIRE(std::equal(host.begin(), host.end(), fp.client.initial_host_key().begin(),
                                       fp.client.initial_host_key().end()));
                    REQUIRE(std::equal(sid.begin(), sid.end(), fp.client.session_id().begin(),
                                       fp.client.session_id().end()));
                    REQUIRE(std::equal(sig.begin(), sig.end(), fp.client.initial_kex_signature().begin(),
                                       fp.client.initial_kex_signature().end()));
                    REQUIRE(flag == forwarding);
                    wire::writer ok;
                    agent::encode_success(ok);
                    const auto ec = co_await write_bytes(peer, frame_of(ok.data()));
                    REQUIRE_FALSE(ec);
                });
                const auto ec = co_await bind_agent_session(agent, fp.client, forwarding);
                REQUIRE_FALSE(ec);
                co_return corral::join;
            };
        }
        REQUIRE_FALSE(agent.failure());
    }());
}

TEST_CASE("auth_publickey_from_agent skips unusable keys and does not bind", "[agent][auth]") {
    auto fp = make_facade_pair();
    auto [local, peer] = memory_pipe::make(fp.loop);
    basic_agent_client<memory_pipe::end> agent{std::move(local)};
    auto p = prov();
    user_key first;
    user_key second;
    generate_user_key(p, first);
    generate_user_key(p, second);
    const std::array<std::byte, 4> garbage{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    int queries = 0;
    int signed_ok = 0;
    bool saw_bind = false;

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        auto [cec, sec] =
            co_await corral::allOf(fp.client.handshake(accept_host), fp.server.handshake());
        REQUIRE_FALSE(cec);
        REQUIRE_FALSE(sec);

        std::error_code helper_ec = code::invalid_state;
        auth_result helper_result;
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                const auto auth_ec = co_await fp.server.authenticate(
                    [&](auth_request req) -> corral::Task<auth_verdict> {
                        REQUIRE(auth::is_publickey_method(req.method()));
                        if (!req.has_signature()) {
                            ++queries;
                            co_return auth_verdict::success();
                        }
                        ++signed_ok;
                        co_return auth_verdict::success();
                    });
                REQUIRE_FALSE(auth_ec);
            });
            n.start([&]() -> corral::Task<void> {
                for (;;) {
                    const auto body = co_await read_frame(peer);
                    if (body.empty()) co_return;
                    if (body[0] == static_cast<std::byte>(agent::msg::extension)) {
                        saw_bind = true;
                        co_return;
                    }
                    wire::writer reply;
                    if (body[0] == static_cast<std::byte>(agent::msg::request_identities)) {
                        const agent::identity_view ids[] = {
                            {garbage, "nope"},
                            {first.blob(), "one"},
                            {second.blob(), "two"},
                        };
                        agent::encode_identities_answer(reply, ids);
                    } else if (body[0] == static_cast<std::byte>(agent::msg::sign_request)) {
                        std::span<const std::byte> key;
                        std::span<const std::byte> data;
                        std::uint32_t flags = 0;
                        REQUIRE(agent::decode_sign_request(body, key, data, flags));
                        if (std::equal(key.begin(), key.end(), first.blob().begin(), first.blob().end())) {
                            agent::encode_failure(reply);
                        } else {
                            REQUIRE(std::equal(key.begin(), key.end(), second.blob().begin(),
                                               second.blob().end()));
                            wire::writer sig;
                            REQUIRE_FALSE(core::detail::sign_publickey_data(
                                p, second.priv, "ssh-ed25519", crypto::sig_id::ed25519, data, sig));
                            agent::encode_sign_response(reply, sig.data());
                        }
                    } else {
                        agent::encode_failure(reply);
                    }
                    const auto ec = co_await write_bytes(peer, frame_of(reply.data()));
                    REQUIRE_FALSE(ec);
                }
            });
            std::tie(helper_ec, helper_result) =
                co_await auth_publickey_from_agent(fp.client, "alice", agent);
            co_return corral::cancel;
        };
        REQUIRE_FALSE(helper_ec);
        REQUIRE(helper_result.success);
        REQUIRE(queries == 2);
        REQUIRE(signed_ok == 1);
        REQUIRE_FALSE(saw_bind);
        REQUIRE_FALSE(agent.failure());
    }());
}

TEST_CASE("auth_publickey_from_agent stops after the agent loses sync", "[agent][auth]") {
    auto fp = make_facade_pair();
    auto [local, peer] = memory_pipe::make(fp.loop);
    basic_agent_client<memory_pipe::end> agent{std::move(local)};
    auto p = prov();
    user_key key;
    generate_user_key(p, key);
    int queries = 0;

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        auto [cec, sec] =
            co_await corral::allOf(fp.client.handshake(accept_host), fp.server.handshake());
        REQUIRE_FALSE(cec);
        REQUIRE_FALSE(sec);

        std::error_code helper_ec;
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                (void)co_await fp.server.authenticate([&](auth_request req) -> corral::Task<auth_verdict> {
                    if (!req.has_signature()) ++queries;
                    co_return auth_verdict::success();
                });
            });
            n.start([&]() -> corral::Task<void> {
                const auto listed = co_await read_frame(peer);
                REQUIRE(listed[0] == static_cast<std::byte>(agent::msg::request_identities));
                wire::writer ids;
                const agent::identity_view views[] = {{key.blob(), "one"}, {key.blob(), "two"}};
                agent::encode_identities_answer(ids, views);
                const auto ids_ec = co_await write_bytes(peer, frame_of(ids.data()));
                REQUIRE_FALSE(ids_ec);
                const auto sign = co_await read_frame(peer);
                REQUIRE(sign[0] == static_cast<std::byte>(agent::msg::sign_request));
                wire::writer wrong;
                agent::encode_success(wrong);
                const auto wrong_ec = co_await write_bytes(peer, frame_of(wrong.data()));
                REQUIRE_FALSE(wrong_ec);
                co_await corral::suspendForever;
            });
            auth_result result;
            std::tie(helper_ec, result) = co_await auth_publickey_from_agent(fp.client, "alice", agent);
            co_return corral::cancel;
        };
        REQUIRE(helper_ec == agent.failure());
        REQUIRE(helper_ec);
        REQUIRE(queries == 1);
    }());
}

TEST_CASE("auth_publickey_from_agent returns request_denied when nothing can be tried", "[agent][auth]") {
    TestLoop loop;
    auto [local, peer] = memory_pipe::make(loop);
    basic_agent_client<memory_pipe::end> agent{std::move(local)};
    auto ends = memory_pipe::make(loop);
    client_session client{auv::stream::own(std::move(ends.first)), prov(), client_options{}};

    corral::run(loop, [&]() -> corral::Task<void> {
        std::error_code helper_ec;
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                const auto body = co_await read_frame(peer);
                REQUIRE(body[0] == static_cast<std::byte>(agent::msg::request_identities));
                wire::writer ids;
                const std::array<std::byte, 3> garbage{std::byte{1}, std::byte{2}, std::byte{3}};
                const agent::identity_view views[] = {{garbage, "nope"}};
                agent::encode_identities_answer(ids, views);
                const auto ec = co_await write_bytes(peer, frame_of(ids.data()));
                REQUIRE_FALSE(ec);
            });
            auth_result result;
            std::tie(helper_ec, result) = co_await auth_publickey_from_agent(client, "alice", agent);
            co_return corral::join;
        };
        REQUIRE(helper_ec == code::request_denied);
        REQUIRE_FALSE(agent.failure());
    }());
}

TEST_CASE("an unsolicited agent channel is rejected before the application sees it", "[agent][forward]") {
    auto fp = make_facade_pair();
    int seen = 0;
    corral::run(fp.loop, [&]() -> corral::Task<void> {
        co_await handshake_and_password(fp.client, fp.server);
        co_await corral::allOf(
            fp.client.serve(
                [&](inbound_channel_open open) -> corral::Task<void> {
                    if (open.type() == channel_type::auth_agent) ++seen;
                    open.reject(channel_open_reason::connect_failed, "app");
                    co_return;
                },
                reject_global),
            fp.server.serve(reject_open, reject_global, [&]() -> corral::Task<void> {
                auto opened = co_await fp.server.open_auth_agent();
                REQUIRE(opened.ec == code::request_denied);
                REQUIRE(opened.reason == channel_open_reason::administratively_prohibited);
                REQUIRE(opened.description.empty());
                co_await fp.server.disconnect(disconnect_reason::by_application, "bye");
            }));
    }());
    REQUIRE(seen == 0);
}

TEST_CASE("a requested agent channel is delivered after rekey", "[agent][forward]") {
    auto fp = make_facade_pair();
    int seen = 0;
    std::string wire_name;
    corral::run(fp.loop, [&]() -> corral::Task<void> {
        co_await handshake_and_password(fp.client, fp.server);
        REQUIRE(fp.client.supports_agent_forward());
        corral::Event requested;
        co_await corral::allOf(
            fp.server.serve(
                [&](inbound_channel_open open) -> corral::Task<void> {
                    REQUIRE(open.type() == channel_type::session);
                    channel ch = open.accept();
                    co_await ch.serve_requests([&](inbound_channel_request req) -> corral::Task<bool> {
                        co_return req.type() == "agent-req";
                    });
                },
                reject_global,
                [&]() -> corral::Task<void> {
                    co_await requested;
                    auto opened = co_await fp.server.open_auth_agent();
                    REQUIRE_FALSE(opened.ec);
                    REQUIRE(opened.ch);
                    co_await fp.server.disconnect(disconnect_reason::by_application, "bye");
                }),
            fp.client.serve(
                [&](inbound_channel_open open) -> corral::Task<void> {
                    ++seen;
                    wire_name.assign(open.request_type().begin(), open.request_type().end());
                    REQUIRE(open.type() == channel_type::auth_agent);
                    channel ch = open.accept();
                    co_await ch.close();
                },
                reject_global,
                [&]() -> corral::Task<void> {
                    auto opened = co_await fp.client.open_session_channel();
                    REQUIRE_FALSE(opened.ec);
                    const auto req_ec = co_await opened.ch.request_auth_agent();
                    REQUIRE_FALSE(req_ec);
                    const auto rekey_ec = co_await fp.client.rekey();
                    REQUIRE_FALSE(rekey_ec);
                    requested.trigger();
                    co_await fp.client.until_closed();
                }));
    }());
    REQUIRE(seen == 1);
    REQUIRE(wire_name == "agent-connect");
}

TEST_CASE("a legacy agent channel is bridged when agent-forward was not advertised",
          "[agent][forward]") {
    server_options so;
    so.advertise_ext_info = false;
    auto fp = make_facade_pair({}, std::move(so));
    auto [local, peer] = memory_pipe::make(fp.loop);
    basic_agent_client<memory_pipe::end> agent{std::move(local)};
    std::string request_name;
    std::string wire_name;
    corral::run(fp.loop, [&]() -> corral::Task<void> {
        co_await handshake_and_password(fp.client, fp.server);
        REQUIRE_FALSE(fp.client.supports_agent_forward());
        corral::Event requested;
        corral::Event bridge_up;
        corral::Event bridge_done;
        std::error_code bridge_ec = code::invalid_state;
        co_await corral::allOf(
            fp.server.serve(
                [&](inbound_channel_open open) -> corral::Task<void> {
                    channel ch = open.accept();
                    co_await ch.serve_requests([&](inbound_channel_request req) -> corral::Task<bool> {
                        request_name.assign(req.type().begin(), req.type().end());
                        co_return true;
                    });
                },
                reject_global,
                [&]() -> corral::Task<void> {
                    co_await requested;
                    auto opened = co_await fp.server.open_auth_agent();
                    REQUIRE_FALSE(opened.ec);
                    co_await bridge_up;
                    char ping[] = {'z'};
                    auv::buffer out{ping, 1};
                    const std::size_t nbufs = 1;
                    const auto write_ec = co_await opened.ch.write(&out, nbufs);
                    REQUIRE_FALSE(write_ec);
                    const auto shutdown_ec = co_await opened.ch.shutdown();
                    REQUIRE_FALSE(shutdown_ec);
                    co_await bridge_done;
                    co_await fp.server.disconnect(disconnect_reason::by_application, "bye");
                }),
            fp.client.serve(
                [&](inbound_channel_open open) -> corral::Task<void> {
                    wire_name.assign(open.request_type().begin(), open.request_type().end());
                    REQUIRE(open.type() == channel_type::auth_agent);
                    channel ch = open.accept();
                    CORRAL_WITH_NURSERY(n) {
                        n.start([&]() -> corral::Task<void> {
                            bridge_ec = co_await forward_agent_channel(ch, agent);
                        });
                        corral::Event turn;
                        fp.loop.post([&] { turn.trigger(); });
                        co_await turn;
                        bridge_up.trigger();
                        co_return corral::join;
                    };
                    bridge_done.trigger();
                },
                reject_global,
                [&]() -> corral::Task<void> {
                    auto opened = co_await fp.client.open_session_channel();
                    REQUIRE_FALSE(opened.ec);
                    const auto req_ec = co_await opened.ch.request_auth_agent();
                    REQUIRE_FALSE(req_ec);
                    requested.trigger();
                    co_await bridge_up;
                    char buf[4];
                    auto [ec, nread] = co_await read_some(peer, {buf, sizeof buf});
                    REQUIRE_FALSE(ec);
                    REQUIRE(nread == 1);
                    REQUIRE(buf[0] == 'z');
                    const auto shutdown_ec = co_await peer.shutdown();
                    REQUIRE_FALSE(shutdown_ec);
                    co_await bridge_done;
                    REQUIRE_FALSE(bridge_ec);
                    co_await fp.client.until_closed();
                }));
    }());
    REQUIRE(request_name == "auth-agent-req@openssh.com");
    REQUIRE(wire_name == "auth-agent@openssh.com");
}

TEST_CASE("the agent bridge copies bytes and then refuses protocol calls", "[agent][forward]") {
    auto fp = make_facade_pair();
    auto [local, peer] = memory_pipe::make(fp.loop);
    basic_agent_client<memory_pipe::end> agent{std::move(local)};

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        co_await handshake_and_password(fp.client, fp.server);
        corral::Event requested;
        corral::Event bridge_up;
        corral::Event bridge_done;
        std::error_code bridge_ec = code::invalid_state;
        co_await corral::allOf(
            fp.server.serve(
                [&](inbound_channel_open open) -> corral::Task<void> {
                    channel ch = open.accept();
                    co_await ch.serve_requests([&](inbound_channel_request req) -> corral::Task<bool> {
                        co_return req.type() == "agent-req";
                    });
                },
                reject_global,
                [&]() -> corral::Task<void> {
                    co_await requested;
                    auto opened = co_await fp.server.open_auth_agent();
                    REQUIRE_FALSE(opened.ec);
                    co_await bridge_up;
                    char ping[] = {'p', 'i', 'n', 'g'};
                    auv::buffer out{ping, sizeof ping};
                    const std::size_t nbufs = 1;
                    const auto write_ec = co_await opened.ch.write(&out, nbufs);
                    REQUIRE_FALSE(write_ec);
                    const auto shutdown_ec = co_await opened.ch.shutdown();
                    REQUIRE_FALSE(shutdown_ec);
                    std::string got;
                    for (;;) {
                        char buf[8];
                        auto [ec, n] = co_await opened.ch.read(auv::buffer{buf, sizeof buf});
                        if (ec == auv::errc::eof) break;
                        REQUIRE_FALSE(ec);
                        got.append(buf, n);
                    }
                    REQUIRE(got == "pong");
                    co_await bridge_done;
                    co_await fp.server.disconnect(disconnect_reason::by_application, "bye");
                }),
            fp.client.serve(
                [&](inbound_channel_open open) -> corral::Task<void> {
                    REQUIRE(open.type() == channel_type::auth_agent);
                    channel ch = open.accept();
                    CORRAL_WITH_NURSERY(n) {
                        n.start([&]() -> corral::Task<void> {
                            bridge_ec = co_await forward_agent_channel(ch, agent);
                        });
                        corral::Event turn;
                        fp.loop.post([&] { turn.trigger(); });
                        co_await turn;
                        bridge_up.trigger();
                        co_return corral::join;
                    };
                    bridge_done.trigger();
                },
                reject_global,
                [&]() -> corral::Task<void> {
                    auto opened = co_await fp.client.open_session_channel();
                    REQUIRE_FALSE(opened.ec);
                    const auto req_ec = co_await opened.ch.request_auth_agent();
                    REQUIRE_FALSE(req_ec);
                    requested.trigger();
                    co_await bridge_up;
                    auto [during_ec, during_ids] = co_await agent.list_identities();
                    REQUIRE(during_ec == code::invalid_state);
                    REQUIRE_FALSE(agent.failure());
                    REQUIRE(during_ids.empty());

                    char buf[8];
                    auto [ec, nread] = co_await read_some(peer, {buf, sizeof buf});
                    REQUIRE_FALSE(ec);
                    REQUIRE(nread == 4);
                    REQUIRE(std::string_view(buf, nread) == "ping");
                    char pong[] = {'p', 'o', 'n', 'g'};
                    std::vector<std::byte> pong_bytes(4);
                    std::memcpy(pong_bytes.data(), pong, 4);
                    const auto write_ec = co_await write_bytes(peer, pong_bytes);
                    REQUIRE_FALSE(write_ec);
                    const auto shutdown_ec = co_await peer.shutdown();
                    REQUIRE_FALSE(shutdown_ec);
                    co_await bridge_done;
                    auto [after_ec, after_ids] = co_await agent.list_identities();
                    REQUIRE(after_ec == code::invalid_state);
                    REQUIRE(agent.failure() == code::invalid_state);
                    REQUIRE(after_ids.empty());
                    REQUIRE_FALSE(bridge_ec);
                    co_await fp.client.until_closed();
                }));
    }());
}

TEST_CASE("a queued agent request keeps its reply when bridging is refused", "[agent][forward]") {
    auto fp = make_facade_pair();
    auto [local, peer] = memory_pipe::make(fp.loop);
    basic_agent_client<memory_pipe::end> agent{std::move(local)};

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        co_await handshake_and_password(fp.client, fp.server);
        corral::Event requested;
        channel agent_ch;
        corral::Event got_agent;
        co_await corral::allOf(
            fp.server.serve(
                [&](inbound_channel_open open) -> corral::Task<void> {
                    channel ch = open.accept();
                    co_await ch.serve_requests([&](inbound_channel_request req) -> corral::Task<bool> {
                        co_return req.type() == "agent-req";
                    });
                },
                reject_global,
                [&]() -> corral::Task<void> {
                    co_await requested;
                    auto opened = co_await fp.server.open_auth_agent();
                    REQUIRE_FALSE(opened.ec);
                    co_await fp.server.until_closed();
                }),
            fp.client.serve(
                [&](inbound_channel_open open) -> corral::Task<void> {
                    REQUIRE(open.type() == channel_type::auth_agent);
                    agent_ch = open.accept();
                    got_agent.trigger();
                    co_await fp.client.until_closed();
                },
                reject_global, [&]() -> corral::Task<void> {
                    auto opened = co_await fp.client.open_session_channel();
                    REQUIRE_FALSE(opened.ec);
                    const auto req_ec = co_await opened.ch.request_auth_agent();
                    REQUIRE_FALSE(req_ec);
                    requested.trigger();
                    co_await got_agent;

                    std::error_code list_ec = code::invalid_state;
                    std::vector<agent::identity> ids;
                    CORRAL_WITH_NURSERY(n) {
                        n.start([&]() -> corral::Task<void> {
                            auto listed = co_await agent.list_identities();
                            list_ec = listed.ec;
                            ids = std::move(listed.identities);
                        });
                        const auto request = co_await read_frame(peer);
                        REQUIRE(request[0] == static_cast<std::byte>(agent::msg::request_identities));
                        const auto bridge_ec = co_await forward_agent_channel(agent_ch, agent);
                        REQUIRE(bridge_ec == code::invalid_state);
                        REQUIRE_FALSE(agent.failure());
                        wire::writer answer;
                        const std::array<std::byte, 3> blob{std::byte{7}, std::byte{8}, std::byte{9}};
                        const agent::identity_view views[] = {{blob, "kept"}};
                        agent::encode_identities_answer(answer, views);
                        const auto ec = co_await write_bytes(peer, frame_of(answer.data()));
                        REQUIRE_FALSE(ec);
                        co_return corral::join;
                    };
                    REQUIRE_FALSE(list_ec);
                    REQUIRE(ids.size() == 1);
                    REQUIRE(ids[0].comment == "kept");
                    REQUIRE_FALSE(agent.failure());
                    co_await fp.client.disconnect(disconnect_reason::by_application, "bye");
                }));
    }());
}
