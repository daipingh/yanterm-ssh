#include <catch2/catch_test_macros.hpp>
#include "handshake_fixture.hpp"

#include <yanterm-ssh/auth/types.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/detail/error.hpp>

#include <span>
#include <string_view>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

using auth::auth_verdict;
using auth::kbdint_prompt;

TEST_CASE("kbdint one round success", "[auth][kbdint]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    REQUIRE_FALSE(client.conn.auth_keyboard_interactive("alice"));

    bool saw_req = false;
    bool saw_info_req = false;
    bool saw_info_resp = false;
    bool saw_ok = false;
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client, const recording_handler::recorded_event& ev) {
        if (!is_client && std::holds_alternative<recording_handler::auth_request>(ev)) {
            REQUIRE(std::get<recording_handler::auth_request>(ev).user == "alice");
            REQUIRE(std::get<recording_handler::auth_request>(ev).service == "ssh-connection");
            REQUIRE(std::get<recording_handler::auth_request>(ev).method == "keyboard-interactive");
            saw_req = true;
            const kbdint_prompt prompts[] = {{"Password:", false}};
            server.conn.resolve(std::get<recording_handler::auth_request>(ev).ticket, auth_verdict::info("login", "hi", prompts));
        }
        if (is_client && std::holds_alternative<recording_handler::auth_info_request>(ev)) {
            REQUIRE(std::get<recording_handler::auth_info_request>(ev).ticket != core::kbdint_ticket{});
            REQUIRE(std::get<recording_handler::auth_info_request>(ev).name == "login");
            REQUIRE(std::get<recording_handler::auth_info_request>(ev).instruction == "hi");
            REQUIRE(std::get<recording_handler::auth_info_request>(ev).prompts.size() == 1);
            REQUIRE(std::get<recording_handler::auth_info_request>(ev).prompts.data() != nullptr);
            REQUIRE(std::get<recording_handler::auth_info_request>(ev).prompts[0].prompt == "Password:");
            REQUIRE_FALSE(std::get<recording_handler::auth_info_request>(ev).prompts[0].echo);
            saw_info_req = true;
            const std::string_view answers[] = {"s3cret"};
            REQUIRE_FALSE(client.conn.resolve(std::get<recording_handler::auth_info_request>(ev).ticket, answers));
        }
        if (!is_client && std::holds_alternative<recording_handler::auth_info_response>(ev)) {
            const auto& info_resp = std::get<recording_handler::auth_info_response>(ev);
            REQUIRE(info_resp.responses.size() == 1);
            REQUIRE(info_resp.responses[0] == "s3cret");
            saw_info_resp = true;
            server.conn.resolve(info_resp.ticket, auth_verdict::success());
        }
        if (is_client && std::holds_alternative<recording_handler::auth_response>(ev)) {
            REQUIRE(std::get<recording_handler::auth_response>(ev).success);
            saw_ok = true;
        }
    }));
    REQUIRE(saw_req);
    REQUIRE(saw_info_req);
    REQUIRE(saw_info_resp);
    REQUIRE(saw_ok);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("kbdint two rounds", "[auth][kbdint]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    REQUIRE_FALSE(client.conn.auth_keyboard_interactive("alice"));

    core::auth_ticket server_id{};
    int info_rounds = 0;
    int answer_rounds = 0;
    bool saw_ok = false;
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client, const recording_handler::recorded_event& ev) {
        if (!is_client && std::holds_alternative<recording_handler::auth_request>(ev)) {
            REQUIRE(std::get<recording_handler::auth_request>(ev).method == "keyboard-interactive");
            server_id = std::get<recording_handler::auth_request>(ev).ticket;
            const kbdint_prompt prompts[] = {{"Username:", true}};
            server.conn.resolve(std::get<recording_handler::auth_request>(ev).ticket, auth_verdict::info("login", "step1", prompts));
        }
        if (is_client && std::holds_alternative<recording_handler::auth_info_request>(ev)) {
            REQUIRE(std::get<recording_handler::auth_info_request>(ev).ticket != core::kbdint_ticket{});
            ++info_rounds;
            if (info_rounds == 1) {
                REQUIRE(std::get<recording_handler::auth_info_request>(ev).name == "login");
                REQUIRE(std::get<recording_handler::auth_info_request>(ev).instruction == "step1");
                REQUIRE(std::get<recording_handler::auth_info_request>(ev).prompts.size() == 1);
                REQUIRE(std::get<recording_handler::auth_info_request>(ev).prompts[0].prompt == "Username:");
                REQUIRE(std::get<recording_handler::auth_info_request>(ev).prompts[0].echo);
                const std::string_view answers[] = {"alice"};
                REQUIRE_FALSE(client.conn.resolve(std::get<recording_handler::auth_info_request>(ev).ticket, answers));
            } else {
                REQUIRE(std::get<recording_handler::auth_info_request>(ev).instruction == "step2");
                REQUIRE(std::get<recording_handler::auth_info_request>(ev).prompts.size() == 1);
                REQUIRE(std::get<recording_handler::auth_info_request>(ev).prompts[0].prompt == "Password:");
                REQUIRE_FALSE(std::get<recording_handler::auth_info_request>(ev).prompts[0].echo);
                const std::string_view answers[] = {"s3cret"};
                REQUIRE_FALSE(client.conn.resolve(std::get<recording_handler::auth_info_request>(ev).ticket, answers));
            }
        }
        if (!is_client && std::holds_alternative<recording_handler::auth_info_response>(ev)) {
            const auto& info_resp = std::get<recording_handler::auth_info_response>(ev);
            ++answer_rounds;
            if (answer_rounds == 1) {
                REQUIRE(info_resp.responses.size() == 1);
                REQUIRE(info_resp.responses[0] == "alice");
                const kbdint_prompt prompts[] = {{"Password:", false}};
                server.conn.resolve(info_resp.ticket, auth_verdict::info("login", "step2", prompts));
            } else {
                REQUIRE(info_resp.responses.size() == 1);
                REQUIRE(info_resp.responses[0] == "s3cret");
                server.conn.resolve(info_resp.ticket, auth_verdict::success());
            }
        }
        if (is_client && std::holds_alternative<recording_handler::auth_response>(ev)) {
            REQUIRE(std::get<recording_handler::auth_response>(ev).success);
            saw_ok = true;
        }
    }));
    REQUIRE(info_rounds == 2);
    REQUIRE(answer_rounds == 2);
    REQUIRE(saw_ok);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("kbdint response count mismatch is invalid_state", "[auth][kbdint]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    REQUIRE_FALSE(client.conn.auth_keyboard_interactive("alice"));

    bool saw_mismatch = false;
    bool saw_info_resp = false;
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client, const recording_handler::recorded_event& ev) {
        if (!is_client && std::holds_alternative<recording_handler::auth_request>(ev)) {
            const kbdint_prompt prompts[] = {{"Password:", false}};
            server.conn.resolve(std::get<recording_handler::auth_request>(ev).ticket, auth_verdict::info("login", "hi", prompts));
        }
        if (is_client && std::holds_alternative<recording_handler::auth_info_request>(ev)) {
            REQUIRE(std::get<recording_handler::auth_info_request>(ev).prompts.size() == 1);
            const auto before = client.conn.pending_output_bytes();
            const auto ec = client.conn.resolve(std::get<recording_handler::auth_info_request>(ev).ticket, std::span<const std::string_view>{});
            REQUIRE(ec == code::invalid_state);
            REQUIRE(client.conn.pending_output_bytes() == before);
            REQUIRE_FALSE(client.conn.failure());
            REQUIRE_FALSE(server.conn.failure());
            saw_mismatch = true;
        }
        if (!is_client && std::holds_alternative<recording_handler::auth_info_response>(ev)) {
            saw_info_resp = true;
        }
    }));
    REQUIRE(saw_mismatch);
    REQUIRE_FALSE(saw_info_resp);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

// RFC 4253 §7.1: no INFO_RESPONSE between KEXINIT and NEWKEYS, so resolve
// during rekey succeeds and the response is held until the new keys.
TEST_CASE("kbdint resolve during rekey is sent after NEWKEYS", "[auth][kbdint][rekey]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    REQUIRE_FALSE(client.conn.auth_keyboard_interactive("alice"));

    bool saw_info_resp = false;
    bool saw_ok = false;
    int client_rekey_done = 0;
    int server_rekey_done = 0;
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client, const recording_handler::recorded_event& ev) {
        if (std::holds_alternative<recording_handler::rekey_done>(ev)) {
            ++(is_client ? client_rekey_done : server_rekey_done);
        }
        if (!is_client && std::holds_alternative<recording_handler::auth_request>(ev)) {
            const kbdint_prompt prompts[] = {{"Password:", false}};
            server.conn.resolve(std::get<recording_handler::auth_request>(ev).ticket, auth_verdict::info("login", "hi", prompts));
        }
        if (is_client && std::holds_alternative<recording_handler::auth_info_request>(ev)) {
            REQUIRE_FALSE(client.conn.rekey());
            const auto before = client.conn.pending_output_bytes();
            const std::string_view answers[] = {"s3cret"};
            REQUIRE_FALSE(client.conn.resolve(std::get<recording_handler::auth_info_request>(ev).ticket, answers));
            REQUIRE(client.conn.pending_output_bytes() == before);
        }
        if (!is_client && std::holds_alternative<recording_handler::auth_info_response>(ev)) {
            // Flushed from on_rekey_done, so the sender has already finished this rekey.
            REQUIRE(client_rekey_done == 1);
            const auto& info_resp = std::get<recording_handler::auth_info_response>(ev);
            REQUIRE(info_resp.responses.size() == 1);
            REQUIRE(info_resp.responses[0] == "s3cret");
            saw_info_resp = true;
            server.conn.resolve(info_resp.ticket, auth_verdict::success());
        }
        if (is_client && std::holds_alternative<recording_handler::auth_response>(ev)) {
            REQUIRE(std::get<recording_handler::auth_response>(ev).success);
            saw_ok = true;
        }
    }));
    REQUIRE(saw_info_resp);
    REQUIRE(saw_ok);
    REQUIRE(client_rekey_done == 1);
    REQUIRE(server_rekey_done == 1);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("kbdint failure after info", "[auth][kbdint]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    REQUIRE_FALSE(client.conn.auth_keyboard_interactive("alice"));

    bool saw_info_resp = false;
    bool saw_fail = false;
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client, const recording_handler::recorded_event& ev) {
        if (!is_client && std::holds_alternative<recording_handler::auth_request>(ev)) {
            const kbdint_prompt prompts[] = {{"Password:", false}};
            server.conn.resolve(std::get<recording_handler::auth_request>(ev).ticket, auth_verdict::info("login", "hi", prompts));
        }
        if (is_client && std::holds_alternative<recording_handler::auth_info_request>(ev)) {
            REQUIRE(std::get<recording_handler::auth_info_request>(ev).ticket != core::kbdint_ticket{});
            const std::string_view answers[] = {"wrong"};
            REQUIRE_FALSE(client.conn.resolve(std::get<recording_handler::auth_info_request>(ev).ticket, answers));
        }
        if (!is_client && std::holds_alternative<recording_handler::auth_info_response>(ev)) {
            const auto& info_resp = std::get<recording_handler::auth_info_response>(ev);
            REQUIRE(info_resp.responses[0] == "wrong");
            saw_info_resp = true;
            server.conn.resolve(info_resp.ticket, auth_verdict::failure("publickey,password"));
        }
        if (is_client && std::holds_alternative<recording_handler::auth_response>(ev)) {
            REQUIRE_FALSE(std::get<recording_handler::auth_response>(ev).success);
            REQUIRE(std::get<recording_handler::auth_response>(ev).methods == "publickey,password");
            REQUIRE_FALSE(std::get<recording_handler::auth_response>(ev).partial_success);
            saw_fail = true;
        }
    }));
    REQUIRE(saw_info_resp);
    REQUIRE(saw_fail);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("kbdint response bytes are not left in event after resolve", "[auth][kbdint]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    REQUIRE_FALSE(client.conn.auth_keyboard_interactive("alice"));

    std::string copied;
    bool resolved = false;
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client, const recording_handler::recorded_event& ev) {
        if (!is_client && std::holds_alternative<recording_handler::auth_request>(ev)) {
            const kbdint_prompt prompts[] = {{"Password:", false}};
            server.conn.resolve(std::get<recording_handler::auth_request>(ev).ticket, auth_verdict::info("login", "hi", prompts));
        }
        if (is_client && std::holds_alternative<recording_handler::auth_info_request>(ev)) {
            const std::string_view answers[] = {"s3cret"};
            REQUIRE_FALSE(client.conn.resolve(std::get<recording_handler::auth_info_request>(ev).ticket, answers));
        }
        if (!is_client && std::holds_alternative<recording_handler::auth_info_response>(ev)) {
            const auto& info_resp = std::get<recording_handler::auth_info_response>(ev);
            REQUIRE(info_resp.responses.size() == 1);
            copied.assign(info_resp.responses[0].begin(), info_resp.responses[0].end());
            REQUIRE(copied == "s3cret");
            server.conn.resolve(info_resp.ticket, auth_verdict::success());
            resolved = true;
        }
    }));
    REQUIRE(copied == "s3cret");
    REQUIRE(resolved);
}

TEST_CASE("later password auth_request does not leak kbdint submethods", "[auth][kbdint]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    const std::string_view subs[] = {"pam"};
    REQUIRE_FALSE(client.conn.auth_keyboard_interactive("alice", {}, subs));

    bool saw_kbdint = false;
    bool saw_password = false;
    bool saw_ok = false;
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client, const recording_handler::recorded_event& ev) {
        if (!is_client && std::holds_alternative<recording_handler::auth_request>(ev)) {
            if (std::get<recording_handler::auth_request>(ev).method == "keyboard-interactive") {
                REQUIRE(std::get<recording_handler::auth_request>(ev).submethods == "pam");
                saw_kbdint = true;
                server.conn.resolve(std::get<recording_handler::auth_request>(ev).ticket, auth_verdict::failure("password"));
            } else if (std::get<recording_handler::auth_request>(ev).method == "password") {
                REQUIRE(std::get<recording_handler::auth_request>(ev).submethods.empty());
                REQUIRE(std::get<recording_handler::auth_request>(ev).password == "s3cret");
                saw_password = true;
                server.conn.resolve(std::get<recording_handler::auth_request>(ev).ticket, auth_verdict::success());
            }
        }
        if (is_client && std::holds_alternative<recording_handler::auth_response>(ev)) {
            if (!std::get<recording_handler::auth_response>(ev).success) {
                REQUIRE_FALSE(client.conn.auth_password("alice", "s3cret"));
            } else {
                saw_ok = true;
            }
        }
    }));
    REQUIRE(saw_kbdint);
    REQUIRE(saw_password);
    REQUIRE(saw_ok);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("client resolve(auth_verdict) is invalid_state", "[auth][kbdint]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    REQUIRE_FALSE(client.conn.auth_keyboard_interactive("alice"));

    bool saw_info = false;
    (void)run_auth_loopback(client, server,
                                      [&](bool is_client, const recording_handler::recorded_event& ev) {
                                          if (!is_client && std::holds_alternative<recording_handler::auth_request>(ev)) {
                                              const kbdint_prompt prompts[] = {{"Password:", false}};
                                              server.conn.resolve(
                                                  std::get<recording_handler::auth_request>(ev).ticket,
                                                  auth_verdict::info("login", "hi", prompts));
                                          }
                                          if (is_client && std::holds_alternative<recording_handler::auth_info_request>(ev)) {
                                              saw_info = true;
                                              REQUIRE(client.conn.resolve(core::auth_ticket{},
                                                                          auth_verdict::success())
                                                      == code::invalid_state);
                                          }
                                      });
    REQUIRE(saw_info);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}
