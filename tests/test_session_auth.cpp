#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/session.hpp>

#include "facade_fixture.hpp"

#include <corral/corral.h>

#include <span>
#include <string>
#include <string_view>
#include <vector>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

namespace {

auto accept_host = [](host_key_view) -> corral::Task<bool> { co_return true; };

}  // namespace

TEST_CASE("password auth succeeds", "[facade][auth]") {
    auto fp = make_facade_pair();

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &fp.client);
            co_await n.start(&server_session::run, &fp.server);
            auto [cec, sec] = co_await corral::allOf(fp.client.handshake(accept_host),
                                                     fp.server.handshake());
            REQUIRE_FALSE(cec);
            REQUIRE_FALSE(sec);

            auto [aec, auth] = co_await corral::allOf(
                fp.client.auth_password("alice", "s3cret"),
                fp.server.authenticate([](auth_request req) -> corral::Task<auth_verdict> {
                    if (req.method() == "password" && req.user() == "alice"
                        && req.password() == "s3cret") {
                        co_return auth_verdict::success();
                    }
                    co_return auth_verdict::failure("password");
                }));
            auto [pec, result] = aec;
            REQUIRE_FALSE(pec);
            REQUIRE(result.success);
            REQUIRE_FALSE(auth);
            REQUIRE_FALSE(fp.client.failure());
            REQUIRE_FALSE(fp.server.failure());
            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("password auth rejected is auth_result not latch", "[facade][auth]") {
    auto fp = make_facade_pair();

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &fp.client);
            co_await n.start(&server_session::run, &fp.server);
            auto [cec, sec] = co_await corral::allOf(fp.client.handshake(accept_host),
                                                     fp.server.handshake());
            REQUIRE_FALSE(cec);
            REQUIRE_FALSE(sec);

            n.start([&]() -> corral::Task<void> {
                (void)co_await fp.server.authenticate(
                    [](auth_request req) -> corral::Task<auth_verdict> {
                        (void)req;
                        co_return auth_verdict::failure("password");
                    });
                co_return;
            });
            auto [pec, result] = co_await fp.client.auth_password("alice", "wrong");
            REQUIRE_FALSE(pec);
            REQUIRE_FALSE(result.success);
            REQUIRE(result.methods == "password");
            REQUIRE_FALSE(fp.client.failure());
            REQUIRE_FALSE(fp.server.failure());
            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("publickey auth succeeds", "[facade][auth]") {
    auto user_key = parse_host_key_file(prov(), "id_ed25519");
    auto fp = make_facade_pair();

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &fp.client);
            co_await n.start(&server_session::run, &fp.server);
            auto [cec, sec] = co_await corral::allOf(fp.client.handshake(accept_host),
                                                     fp.server.handshake());
            REQUIRE_FALSE(cec);
            REQUIRE_FALSE(sec);

            auto [aec, auth] = co_await corral::allOf(
                fp.client.auth_publickey("alice", user_key),
                fp.server.authenticate([](auth_request req) -> corral::Task<auth_verdict> {
                    if (req.method() == "publickey" && req.has_signature()) {
                        co_return auth_verdict::success();
                    }
                    co_return auth_verdict::failure("publickey");
                }));
            auto [pec, result] = aec;
            REQUIRE_FALSE(pec);
            REQUIRE(result.success);
            REQUIRE_FALSE(auth);
            REQUIRE_FALSE(fp.client.failure());
            REQUIRE_FALSE(fp.server.failure());
            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("kbdint one round", "[facade][auth]") {
    SECTION("client answers and server succeeds") {
        auto fp = make_facade_pair();

        corral::run(fp.loop, [&]() -> corral::Task<void> {
            CORRAL_WITH_NURSERY(n) {
                co_await n.start(&client_session::run, &fp.client);
                co_await n.start(&server_session::run, &fp.server);
                auto [cec, sec] = co_await corral::allOf(fp.client.handshake(accept_host),
                                                         fp.server.handshake());
                REQUIRE_FALSE(cec);
                REQUIRE_FALSE(sec);

                auto [aec, auth] = co_await corral::allOf(
                    fp.client.auth_keyboard_interactive(
                        "alice",
                        [](std::string_view, std::string_view,
                           std::span<const kbdint_prompt> prompts) -> corral::Task<std::vector<std::string>> {
                            REQUIRE(prompts.size() == 1);
                            REQUIRE(prompts[0].prompt == "Password:");
                            REQUIRE_FALSE(prompts[0].echo);
                            co_return std::vector<std::string>{"secret"};
                        }),
                    fp.server.authenticate(
                        [](auth_request req) -> corral::Task<auth_verdict> {
                            if (req.method() != "keyboard-interactive") {
                                co_return auth_verdict::failure("keyboard-interactive");
                            }
                            auto [ec, pw] = co_await req.challenge("Password:", false);
                            if (ec || pw != "secret") {
                                co_return auth_verdict::failure("password");
                            }
                            co_return auth_verdict::success();
                        }));
                auto [pec, result] = aec;
                REQUIRE_FALSE(pec);
                REQUIRE(result.success);
                REQUIRE_FALSE(auth);
                REQUIRE_FALSE(fp.client.failure());
                REQUIRE_FALSE(fp.server.failure());
                co_await fp.client.disconnect(disconnect_reason::by_application, "done");
                co_return corral::cancel;
            };
        }());
    }

    SECTION("challenge completes under noncancellable when session dies") {
        auto fp = make_facade_pair();
        std::error_code challenge_ec;

        corral::run(fp.loop, [&]() -> corral::Task<void> {
            CORRAL_WITH_NURSERY(n) {
                co_await n.start(&client_session::run, &fp.client);
                co_await n.start(&server_session::run, &fp.server);
                auto [cec, sec] = co_await corral::allOf(fp.client.handshake(accept_host),
                                                         fp.server.handshake());
                REQUIRE_FALSE(cec);
                REQUIRE_FALSE(sec);

                corral::Event entered;
                n.start([&]() -> corral::Task<void> {
                    (void)co_await fp.client.auth_keyboard_interactive(
                        "alice",
                        [&](std::string_view, std::string_view,
                            std::span<const kbdint_prompt>) -> corral::Task<std::vector<std::string>> {
                            entered.trigger();
                            co_await corral::suspendForever;
                            co_return std::vector<std::string>{};
                        });
                    co_return;
                });
                n.start([&]() -> corral::Task<void> {
                    co_await entered;
                    corral::Event turn;
                    fp.loop.post([&] { turn.trigger(); });
                    co_await turn;
                    co_await fp.client.disconnect(disconnect_reason::by_application, "kill");
                    co_return;
                });

                auto auth_ec = co_await fp.server.authenticate(
                    [&](auth_request req) -> corral::Task<auth_verdict> {
                        auto [ec, pw] =
                            co_await corral::noncancellable(req.challenge("Password:", false));
                        challenge_ec = ec;
                        (void)pw;
                        co_return auth_verdict::failure("password");
                    });
                (void)auth_ec;
                co_return corral::cancel;
            };
        }());

        REQUIRE(challenge_ec);
    }
}

TEST_CASE("server auth_banner reaches client on_banner", "[facade][auth][banner]") {
    SECTION("configured text is delivered before auth_result") {
        client_options co;
        std::string seen_text;
        std::string seen_lang;
        bool banner_before_result = false;
        co.on_banner = [&](std::string_view text, std::string_view language) {
            seen_text.assign(text.begin(), text.end());
            seen_lang.assign(language.begin(), language.end());
        };
        server_options so;
        so.auth_banner = "Authorized use only.\n";
        so.auth_banner_language = "en";
        auto fp = make_facade_pair(std::move(co), std::move(so));

        corral::run(fp.loop, [&]() -> corral::Task<void> {
            CORRAL_WITH_NURSERY(n) {
                co_await n.start(&client_session::run, &fp.client);
                co_await n.start(&server_session::run, &fp.server);
                auto [cec, sec] = co_await corral::allOf(fp.client.handshake(accept_host),
                                                         fp.server.handshake());
                REQUIRE_FALSE(cec);
                REQUIRE_FALSE(sec);

                auto [aec, auth] = co_await corral::allOf(
                    fp.client.auth_password("alice", "s3cret"),
                    fp.server.authenticate(
                        [](auth_request req) -> corral::Task<auth_verdict> {
                            if (req.method() == "password" && req.password() == "s3cret") {
                                co_return auth_verdict::success();
                            }
                            co_return auth_verdict::failure("password");
                        }));
                auto [pec, result] = aec;
                REQUIRE_FALSE(pec);
                REQUIRE(result.success);
                banner_before_result = (seen_text == "Authorized use only.\n");
                REQUIRE(banner_before_result);
                REQUIRE(seen_lang == "en");
                REQUIRE_FALSE(auth);
                co_await fp.client.disconnect(disconnect_reason::by_application, "done");
                co_return corral::cancel;
            };
        }());
    }

    SECTION("empty banner does not invoke on_banner") {
        client_options co;
        bool called = false;
        co.on_banner = [&](std::string_view, std::string_view) { called = true; };
        auto fp = make_facade_pair(std::move(co));

        corral::run(fp.loop, [&]() -> corral::Task<void> {
            CORRAL_WITH_NURSERY(n) {
                co_await n.start(&client_session::run, &fp.client);
                co_await n.start(&server_session::run, &fp.server);
                auto [cec, sec] = co_await corral::allOf(fp.client.handshake(accept_host),
                                                         fp.server.handshake());
                REQUIRE_FALSE(cec);
                REQUIRE_FALSE(sec);

                auto [aec, auth] = co_await corral::allOf(
                    fp.client.auth_password("alice", "s3cret"),
                    fp.server.authenticate(
                        [](auth_request req) -> corral::Task<auth_verdict> {
                            if (req.method() == "password" && req.password() == "s3cret") {
                                co_return auth_verdict::success();
                            }
                            co_return auth_verdict::failure("password");
                        }));
                auto [pec, result] = aec;
                REQUIRE_FALSE(pec);
                REQUIRE(result.success);
                REQUIRE_FALSE(called);
                REQUIRE_FALSE(auth);
                co_await fp.client.disconnect(disconnect_reason::by_application, "done");
                co_return corral::cancel;
            };
        }());
    }
}
