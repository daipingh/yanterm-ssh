#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/core/types.hpp>
#include <yanterm-ssh/crypto/algorithms.hpp>
#include <yanterm-ssh/crypto/provider.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/keys/private_key.hpp>
#include <yanterm-ssh/session.hpp>
#include <yanterm-ssh/wire/types.hpp>

#include "facade_fixture.hpp"

#include <corral/corral.h>

#include <array>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <vector>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

namespace {

auto accept_host = [](host_key_view) -> corral::Task<bool> { co_return true; };

using signer_result = std::tuple<std::error_code, std::vector<std::byte>>;

// SSH signature blob (RFC 4253 section 6.6) made in process from a fixture key,
// standing in for what an ssh-agent or token would return.
std::vector<std::byte> ssh_signature(const keys::private_key& key, crypto::sig_id sig,
                                     std::string_view name, std::span<const std::byte> data) {
    auto material = key.material();
    material.algorithm = sig;
    auto sk = prov().new_signing_key(material);
    REQUIRE(sk);
    std::array<std::byte, crypto::max_signature_size> raw{};
    std::size_t len = 0;
    REQUIRE(sk.sign(data, raw, len));
    wire::writer w;
    w.write_string(name);
    w.write_string(std::span<const std::byte>{raw}.first(len));
    return {w.data().begin(), w.data().end()};
}

auto accept_signed_publickey_or_password = [](auth_request req) -> corral::Task<auth_verdict> {
    if (req.method() == "publickey" && req.has_signature()) co_return auth_verdict::success();
    if (req.method() == "password" && req.password() == "s3cret") {
        co_return auth_verdict::success();
    }
    co_return auth_verdict::failure("publickey,password");
};

server_options rsa_sha2_512_only_server() {
    server_options so;
    so.host_keys.push_back(parse_host_key_file(prov(), "id_rsa"));
    so.preferred_host_key = "rsa-sha2-512";
    so.accepted_publickey_algorithms = "rsa-sha2-512";
    return so;
}

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

TEST_CASE("publickey query reports pk_ok without authenticating", "[facade][auth][pkok]") {
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

            n.start([&]() -> corral::Task<void> {
                (void)co_await fp.server.authenticate(
                    [](auth_request req) -> corral::Task<auth_verdict> {
                        if (req.method() == "publickey") co_return auth_verdict::success();
                        co_return auth_verdict::failure("publickey");
                    });
            });
            auto [qec, query] = co_await fp.client.auth_publickey_query("alice", user_key.pub());
            REQUIRE_FALSE(qec);
            REQUIRE(query.pk_ok);
            REQUIRE_FALSE(query.success);

            auto [pec, result] = co_await fp.client.auth_publickey("alice", user_key);
            REQUIRE_FALSE(pec);
            REQUIRE(result.success);
            REQUIRE_FALSE(fp.client.failure());
            REQUIRE_FALSE(fp.server.failure());
            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("publickey query rejected returns methods", "[facade][auth][pkok]") {
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

            n.start([&]() -> corral::Task<void> {
                (void)co_await fp.server.authenticate(accept_signed_publickey_or_password);
            });
            auto [qec, query] = co_await fp.client.auth_publickey_query("alice", user_key.pub());
            REQUIRE_FALSE(qec);
            REQUIRE_FALSE(query.pk_ok);
            REQUIRE_FALSE(query.success);
            REQUIRE(query.methods == "publickey,password");
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

TEST_CASE("external signer publickey auth succeeds", "[facade][auth][signer]") {
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

            const auto pub_blob = user_key.pub().blob();
            auto signer = [&](const core::publickey_sign_request& req,
                              std::span<const std::byte> data) -> corral::Task<signer_result> {
                REQUIRE(std::vector<std::byte>(req.public_blob.begin(), req.public_blob.end())
                        == std::vector<std::byte>(pub_blob.begin(), pub_blob.end()));
                co_return signer_result{std::error_code{},
                                        ssh_signature(user_key, req.sig, req.algorithm, data)};
            };
            auto [aec, auth] = co_await corral::allOf(
                fp.client.auth_publickey("alice", user_key.pub(), signer),
                fp.server.authenticate(accept_signed_publickey_or_password));
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

TEST_CASE("external signer signing wrong data fails auth", "[facade][auth][signer]") {
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

            n.start([&]() -> corral::Task<void> {
                (void)co_await fp.server.authenticate(accept_signed_publickey_or_password);
            });
            auto signer = [&](const core::publickey_sign_request& req,
                              std::span<const std::byte> data) -> corral::Task<signer_result> {
                std::vector<std::byte> tampered(data.begin(), data.end());
                tampered.back() ^= std::byte{0x01};
                co_return signer_result{std::error_code{},
                                        ssh_signature(user_key, req.sig, req.algorithm, tampered)};
            };
            auto [pec, result] = co_await fp.client.auth_publickey("alice", user_key.pub(), signer);
            REQUIRE_FALSE(pec);
            REQUIRE_FALSE(result.success);
            REQUIRE_FALSE(fp.client.failure());
            REQUIRE_FALSE(fp.server.failure());
            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("external signer downgraded to ssh-rsa is error", "[facade][auth][signer]") {
    auto user_key = parse_host_key_file(prov(), "id_rsa");
    auto fp = make_facade_pair({}, rsa_sha2_512_only_server());

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &fp.client);
            co_await n.start(&server_session::run, &fp.server);
            auto [cec, sec] = co_await corral::allOf(fp.client.handshake(accept_host),
                                                     fp.server.handshake());
            REQUIRE_FALSE(cec);
            REQUIRE_FALSE(sec);

            n.start([&]() -> corral::Task<void> {
                (void)co_await fp.server.authenticate(accept_signed_publickey_or_password);
            });
            // An agent that ignores the SHA-2 flags signs with SHA-1 as ssh-rsa.
            auto signer = [&](const core::publickey_sign_request&,
                              std::span<const std::byte> data) -> corral::Task<signer_result> {
                co_return signer_result{
                    std::error_code{},
                    ssh_signature(user_key, crypto::sig_id::rsa_pkcs1_sha1, "ssh-rsa", data)};
            };
            auto [kec, kresult] = co_await fp.client.auth_publickey("alice", user_key.pub(), signer);
            REQUIRE(kec == code::sign_failure);
            REQUIRE_FALSE(fp.client.failure());

            auto [pec, presult] = co_await fp.client.auth_password("alice", "s3cret");
            REQUIRE_FALSE(pec);
            REQUIRE(presult.success);
            REQUIRE_FALSE(fp.client.failure());
            REQUIRE_FALSE(fp.server.failure());
            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("external signer error propagates unchanged", "[facade][auth][signer]") {
    auto user_key = parse_host_key_file(prov(), "id_ed25519");
    auto fp = make_facade_pair();
    const auto signer_error = std::make_error_code(std::errc::permission_denied);

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &fp.client);
            co_await n.start(&server_session::run, &fp.server);
            auto [cec, sec] = co_await corral::allOf(fp.client.handshake(accept_host),
                                                     fp.server.handshake());
            REQUIRE_FALSE(cec);
            REQUIRE_FALSE(sec);

            n.start([&]() -> corral::Task<void> {
                (void)co_await fp.server.authenticate(accept_signed_publickey_or_password);
            });
            auto signer = [&](const core::publickey_sign_request&,
                              std::span<const std::byte>) -> corral::Task<signer_result> {
                co_return signer_result{signer_error, {}};
            };
            auto [kec, kresult] = co_await fp.client.auth_publickey("alice", user_key.pub(), signer);
            REQUIRE(kec == signer_error);
            REQUIRE_FALSE(fp.client.failure());

            auto [pec, presult] = co_await fp.client.auth_password("alice", "s3cret");
            REQUIRE_FALSE(pec);
            REQUIRE(presult.success);
            REQUIRE_FALSE(fp.client.failure());
            REQUIRE_FALSE(fp.server.failure());
            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}

TEST_CASE("external signer gets rsa-sha2-512 when only it is advertised", "[facade][auth][signer]") {
    auto user_key = parse_host_key_file(prov(), "id_rsa");
    auto fp = make_facade_pair({}, rsa_sha2_512_only_server());
    std::string requested;

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &fp.client);
            co_await n.start(&server_session::run, &fp.server);
            auto [cec, sec] = co_await corral::allOf(fp.client.handshake(accept_host),
                                                     fp.server.handshake());
            REQUIRE_FALSE(cec);
            REQUIRE_FALSE(sec);

            auto signer = [&](const core::publickey_sign_request& req,
                              std::span<const std::byte> data) -> corral::Task<signer_result> {
                requested.assign(req.algorithm.begin(), req.algorithm.end());
                co_return signer_result{std::error_code{},
                                        ssh_signature(user_key, req.sig, req.algorithm, data)};
            };
            auto [aec, auth] = co_await corral::allOf(
                fp.client.auth_publickey("alice", user_key.pub(), signer),
                fp.server.authenticate(accept_signed_publickey_or_password));
            auto [pec, result] = aec;
            REQUIRE_FALSE(pec);
            REQUIRE(result.success);
            REQUIRE_FALSE(auth);
            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
    REQUIRE(requested == "rsa-sha2-512");
}
