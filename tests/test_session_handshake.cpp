#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/session.hpp>

#include "facade_fixture.hpp"

#include <corral/corral.h>

#include <algorithm>
#include <vector>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

TEST_CASE("client and server handshake on memory pipe", "[facade][handshake]") {
    auto fp = make_facade_pair();

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &fp.client);
            co_await n.start(&server_session::run, &fp.server);
            auto [cec, sec] = co_await corral::allOf(
                fp.client.handshake([](host_key_view k) -> corral::Task<bool> {
                    REQUIRE_FALSE(k.fingerprint().empty());
                    co_return true;
                }),
                fp.server.handshake());
            REQUIRE_FALSE(cec);
            REQUIRE_FALSE(sec);
            REQUIRE(fp.client.peer_identification().starts_with("SSH-2.0-"));
            REQUIRE(fp.server.peer_identification().starts_with("SSH-2.0-"));
            REQUIRE_FALSE(fp.client.session_id().empty());
            REQUIRE(std::equal(fp.client.session_id().begin(), fp.client.session_id().end(),
                               fp.server.session_id().begin(), fp.server.session_id().end()));
            REQUIRE(fp.client.negotiated() != nullptr);
            REQUIRE(fp.server.negotiated() != nullptr);
            REQUIRE(fp.client.negotiated()->kex_name == fp.server.negotiated()->kex_name);
            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("rejecting the host key fails the client", "[facade][handshake]") {
    auto fp = make_facade_pair();
    REQUIRE(fp.client.failure_detail().empty());

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &fp.client);
            co_await n.start(&server_session::run, &fp.server);
            auto [cec, sec] = co_await corral::allOf(
                fp.client.handshake([](host_key_view) -> corral::Task<bool> { co_return false; }),
                fp.server.handshake());
            REQUIRE(cec == errc::host_key_rejected);
            REQUIRE(fp.client.failure() == errc::host_key_rejected);
            REQUIRE(fp.client.failure_detail().empty());
            const auto first = fp.client.failure();
            const auto first_detail = fp.client.failure_detail();
            REQUIRE(fp.client.failure_detail().data() == first_detail.data());
            auto again = co_await fp.client.handshake(
                [](host_key_view) -> corral::Task<bool> { co_return true; });
            REQUIRE(again == errc::host_key_rejected);
            REQUIRE(fp.client.failure() == first);
            REQUIRE(fp.client.failure_detail().data() == first_detail.data());
            REQUIRE(fp.client.failure_detail() == first_detail);
            (void)sec;
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("server offers ed25519 and rsa host keys", "[facade][handshake][hostkey]") {
    auto p = prov();
    client_options co;
    co.preferred_host_key = "rsa-sha2-256,ssh-ed25519";
    server_options so;
    so.host_keys.push_back(parse_host_key_file(p, "id_ed25519"));
    so.host_keys.push_back(parse_host_key_file(p, "id_rsa"));
    auto rsa = parse_host_key_file(p, "id_rsa");
    const auto want = std::vector<std::byte>(rsa.pub().blob().begin(), rsa.pub().blob().end());

    auto fp = make_facade_pair(std::move(co), std::move(so));
    std::vector<std::byte> seen;

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &fp.client);
            co_await n.start(&server_session::run, &fp.server);
            auto [cec, sec] = co_await corral::allOf(
                fp.client.handshake([&](host_key_view k) -> corral::Task<bool> {
                    seen.assign(k.key().blob().begin(), k.key().blob().end());
                    co_return true;
                }),
                fp.server.handshake());
            REQUIRE_FALSE(cec);
            REQUIRE_FALSE(sec);
            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());

    REQUIRE(seen == want);
}

TEST_CASE("cancelled host-key verifier does not poison handshake", "[facade][handshake]") {
    auto fp = make_facade_pair();

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &fp.client);
            co_await n.start(&server_session::run, &fp.server);
            n.start([&]() -> corral::Task<void> {
                (void)co_await fp.server.handshake();
                co_return;
            });

            corral::Event entered;
            co_await corral::anyOf(
                fp.client.handshake([&](host_key_view) -> corral::Task<bool> {
                    entered.trigger();
                    co_await corral::suspendForever;
                    co_return false;
                }),
                [&]() -> corral::Task<void> {
                    co_await entered;
                    corral::Event turn;
                    fp.loop.post([&] { turn.trigger(); });
                    co_await turn;
                }());

            auto cec = co_await fp.client.handshake(
                [](host_key_view) -> corral::Task<bool> { co_return true; });
            REQUIRE_FALSE(cec);
            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}
