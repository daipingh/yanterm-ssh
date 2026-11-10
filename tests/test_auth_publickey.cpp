#include <catch2/catch_test_macros.hpp>
#include "handshake_fixture.hpp"
#include "scripted_peer.hpp"

#include <yanterm-ssh/core/detail/host_key.hpp>
#include <yanterm-ssh/wire/detail/messages.hpp>
#include <yanterm-ssh/crypto/algorithms.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/detail/error.hpp>
#include <yanterm-ssh/keys/public_key.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

using auth::auth_verdict;
using auth::service_userauth;

namespace {

struct user_key {
    std::array<std::byte, crypto::max_generated_key_storage> storage{};
    crypto::private_key_material priv{};
    keys::public_key pk;

    [[nodiscard]] std::span<const std::byte> blob() const { return pk.blob(); }
};

void generate_user_key(crypto::provider p, crypto::sig_id id, std::uint32_t bits, user_key& k) {
    REQUIRE(p.generate_keypair(id, bits, k.priv, k.storage));
    crypto::public_key_material pub{};
    pub.algorithm = id;
    if (id == crypto::sig_id::ed25519) {
        pub.a = k.priv.public_key;
    } else {
        pub.a = k.priv.n;
        pub.b = k.priv.e;
    }
    REQUIRE_FALSE(keys::public_key::from_material(pub, k.pk));
}

}  // namespace

TEST_CASE("ed25519 publickey auth succeeds", "[auth][publickey]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    user_key uk;
    generate_user_key(p, crypto::sig_id::ed25519, 0, uk);

    REQUIRE_FALSE(client.conn.auth_publickey("alice", uk.blob(), uk.priv));

    bool saw_req = false;
    bool saw_resp = false;
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client, const recording_handler::recorded_event& ev) {
        if (!is_client && std::holds_alternative<recording_handler::auth_request>(ev)) {
            REQUIRE(std::get<recording_handler::auth_request>(ev).user == "alice");
            REQUIRE(std::get<recording_handler::auth_request>(ev).service == "ssh-connection");
            REQUIRE(std::get<recording_handler::auth_request>(ev).method == auth::method_hostbound_publickey);
            REQUIRE(std::get<recording_handler::auth_request>(ev).has_signature);
            REQUIRE(std::get<recording_handler::auth_request>(ev).algorithm == "ssh-ed25519");
            REQUIRE(std::vector<std::byte>(std::get<recording_handler::auth_request>(ev).public_blob.begin(), std::get<recording_handler::auth_request>(ev).public_blob.end())
                    == std::vector<std::byte>(uk.blob().begin(), uk.blob().end()));
            saw_req = true;
            server.conn.resolve(std::get<recording_handler::auth_request>(ev).ticket, auth_verdict::success());
        }
        if (is_client && std::holds_alternative<recording_handler::auth_response>(ev)) {
            REQUIRE(std::get<recording_handler::auth_response>(ev).success);
            REQUIRE_FALSE(std::get<recording_handler::auth_response>(ev).pk_ok);
            saw_resp = true;
        }
    }));
    REQUIRE(saw_req);
    REQUIRE(saw_resp);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("bad signature is failure without auth_request", "[auth][publickey]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    user_key blob_key;
    user_key sign_key;
    generate_user_key(p, crypto::sig_id::ed25519, 0, blob_key);
    generate_user_key(p, crypto::sig_id::ed25519, 0, sign_key);

    REQUIRE_FALSE(client.conn.auth_publickey("alice", blob_key.blob(), sign_key.priv));

    bool saw_signed_req = false;
    bool saw_resp = false;
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client, const recording_handler::recorded_event& ev) {
        if (!is_client && std::holds_alternative<recording_handler::auth_request>(ev)) {
            if (std::get<recording_handler::auth_request>(ev).has_signature) saw_signed_req = true;
        }
        if (is_client && std::holds_alternative<recording_handler::auth_response>(ev)) {
            REQUIRE_FALSE(std::get<recording_handler::auth_response>(ev).success);
            REQUIRE_FALSE(std::get<recording_handler::auth_response>(ev).pk_ok);
            REQUIRE(std::get<recording_handler::auth_response>(ev).methods == "publickey");
            saw_resp = true;
        }
    }));
    REQUIRE_FALSE(saw_signed_req);
    REQUIRE(saw_resp);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("unsigned probe PK_OK then signed success", "[auth][publickey][pkok]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    user_key uk;
    generate_user_key(p, crypto::sig_id::ed25519, 0, uk);

    REQUIRE_FALSE(client.conn.auth_publickey_query("alice", uk.blob()));

    bool saw_query = false;
    bool saw_pk_ok = false;
    bool saw_signed = false;
    bool saw_ok = false;
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client, const recording_handler::recorded_event& ev) {
        if (!is_client && std::holds_alternative<recording_handler::auth_request>(ev)) {
            if (!std::get<recording_handler::auth_request>(ev).has_signature) {
                REQUIRE(std::get<recording_handler::auth_request>(ev).method == auth::method_hostbound_publickey);
                REQUIRE(std::get<recording_handler::auth_request>(ev).algorithm == "ssh-ed25519");
                REQUIRE(std::vector<std::byte>(std::get<recording_handler::auth_request>(ev).public_blob.begin(),
                                               std::get<recording_handler::auth_request>(ev).public_blob.end())
                        == std::vector<std::byte>(uk.blob().begin(), uk.blob().end()));
                saw_query = true;
                server.conn.resolve(std::get<recording_handler::auth_request>(ev).ticket, auth_verdict::success());
            } else {
                REQUIRE(std::get<recording_handler::auth_request>(ev).method == auth::method_hostbound_publickey);
                REQUIRE(std::get<recording_handler::auth_request>(ev).algorithm == "ssh-ed25519");
                saw_signed = true;
                server.conn.resolve(std::get<recording_handler::auth_request>(ev).ticket, auth_verdict::success());
            }
        }
        if (is_client && std::holds_alternative<recording_handler::auth_response>(ev)) {
            if (std::get<recording_handler::auth_response>(ev).pk_ok) {
                REQUIRE_FALSE(std::get<recording_handler::auth_response>(ev).success);
                REQUIRE_FALSE(std::get<recording_handler::auth_response>(ev).partial_success);
                REQUIRE(std::get<recording_handler::auth_response>(ev).methods.empty());
                saw_pk_ok = true;
                REQUIRE_FALSE(client.conn.auth_publickey("alice", uk.blob(), uk.priv));
            } else {
                REQUIRE(std::get<recording_handler::auth_response>(ev).success);
                saw_ok = true;
            }
        }
    }));
    REQUIRE(saw_query);
    REQUIRE(saw_pk_ok);
    REQUIRE(saw_signed);
    REQUIRE(saw_ok);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("unsigned probe rejected", "[auth][publickey][pkok]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    user_key uk;
    generate_user_key(p, crypto::sig_id::ed25519, 0, uk);

    REQUIRE_FALSE(client.conn.auth_publickey_query("alice", uk.blob()));

    bool saw_resp = false;
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client, const recording_handler::recorded_event& ev) {
        if (!is_client && std::holds_alternative<recording_handler::auth_request>(ev)) {
            REQUIRE_FALSE(std::get<recording_handler::auth_request>(ev).has_signature);
            server.conn.resolve(std::get<recording_handler::auth_request>(ev).ticket, auth_verdict::failure("password"));
        }
        if (is_client && std::holds_alternative<recording_handler::auth_response>(ev)) {
            REQUIRE_FALSE(std::get<recording_handler::auth_response>(ev).success);
            REQUIRE_FALSE(std::get<recording_handler::auth_response>(ev).pk_ok);
            REQUIRE(std::get<recording_handler::auth_response>(ev).methods == "password");
            saw_resp = true;
        }
    }));
    REQUIRE(saw_resp);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("rsa-sha2-256 userauth uses server-sig-algs", "[auth][publickey][rsa]") {
    auto p = prov();
    user_key host;
    generate_user_key(p, crypto::sig_id::rsa_pkcs1_sha256, 2048, host);
    std::vector<std::byte> host_blob(host.blob().begin(), host.blob().end());
    auto client = make_client(p);
    auto server = make_server(p);
    REQUIRE_FALSE(server.conn.set_host_key(host_blob, host.priv));
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    user_key uk;
    generate_user_key(p, crypto::sig_id::rsa_pkcs1_sha256, 2048, uk);
    core::detail::host_key_view blob_view;
    REQUIRE_FALSE(core::detail::parse_host_key(uk.blob(), blob_view));
    REQUIRE(blob_view.algorithm_name == "ssh-rsa");

    REQUIRE_FALSE(client.conn.auth_publickey("alice", uk.blob(), uk.priv));

    bool saw_req = false;
    bool saw_resp = false;
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client, const recording_handler::recorded_event& ev) {
        if (!is_client && std::holds_alternative<recording_handler::auth_request>(ev)) {
            REQUIRE(std::get<recording_handler::auth_request>(ev).method == auth::method_hostbound_publickey);
            REQUIRE(std::get<recording_handler::auth_request>(ev).has_signature);
            REQUIRE(std::get<recording_handler::auth_request>(ev).algorithm == "rsa-sha2-256");
            core::detail::host_key_view req_blob;
            REQUIRE_FALSE(core::detail::parse_host_key(std::get<recording_handler::auth_request>(ev).public_blob, req_blob));
            REQUIRE(req_blob.algorithm_name == "ssh-rsa");
            saw_req = true;
            server.conn.resolve(std::get<recording_handler::auth_request>(ev).ticket, auth_verdict::success());
        }
        if (is_client && std::holds_alternative<recording_handler::auth_response>(ev)) {
            REQUIRE(std::get<recording_handler::auth_response>(ev).success);
            saw_resp = true;
        }
    }));
    REQUIRE(saw_req);
    REQUIRE(saw_resp);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("rsa publickey query uses rsa-sha2-256", "[auth][publickey][rsa][pkok]") {
    auto p = prov();
    user_key host;
    generate_user_key(p, crypto::sig_id::rsa_pkcs1_sha256, 2048, host);
    std::vector<std::byte> host_blob(host.blob().begin(), host.blob().end());
    auto client = make_client(p);
    auto server = make_server(p);
    REQUIRE_FALSE(server.conn.set_host_key(host_blob, host.priv));
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    user_key uk;
    generate_user_key(p, crypto::sig_id::rsa_pkcs1_sha256, 2048, uk);
    REQUIRE_FALSE(client.conn.auth_publickey_query("alice", uk.blob()));

    bool saw_query = false;
    bool saw_pk_ok = false;
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client, const recording_handler::recorded_event& ev) {
        if (!is_client && std::holds_alternative<recording_handler::auth_request>(ev)) {
            const auto& req = std::get<recording_handler::auth_request>(ev);
            REQUIRE(req.method == auth::method_hostbound_publickey);
            REQUIRE_FALSE(req.has_signature);
            REQUIRE(req.algorithm == "rsa-sha2-256");
            saw_query = true;
            server.conn.resolve(req.ticket, auth_verdict::success());
        }
        if (is_client && std::holds_alternative<recording_handler::auth_response>(ev)) {
            REQUIRE(std::get<recording_handler::auth_response>(ev).pk_ok);
            saw_pk_ok = true;
        }
    }));
    REQUIRE(saw_query);
    REQUIRE(saw_pk_ok);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("rsa key without rsa-sha2 in server-sig-algs is unsupported_algorithm", "[auth][publickey][rsa]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    core::config server_cfg;
    server_cfg.accepted_publickey_algorithms = "ssh-ed25519";
    auto server = make_server(p, server_cfg);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));

    user_key rsa;
    generate_user_key(p, crypto::sig_id::rsa_pkcs1_sha256, 2048, rsa);
    const auto ec = client.conn.auth_publickey("alice", rsa.blob(), rsa.priv);
    REQUIRE(ec == code::unsupported_algorithm);
    REQUIRE_FALSE(client.conn.failure());

    user_key ed;
    generate_user_key(p, crypto::sig_id::ed25519, 0, ed);
    REQUIRE_FALSE(client.conn.auth_publickey("alice", ed.blob(), ed.priv));

    bool saw_ok = false;
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client, const recording_handler::recorded_event& ev) {
        if (!is_client && std::holds_alternative<recording_handler::auth_request>(ev)) {
            REQUIRE(std::get<recording_handler::auth_request>(ev).method == auth::method_hostbound_publickey);
            server.conn.resolve(std::get<recording_handler::auth_request>(ev).ticket, auth_verdict::success());
        }
        if (is_client && std::holds_alternative<recording_handler::auth_response>(ev)) {
            REQUIRE(std::get<recording_handler::auth_response>(ev).success);
            saw_ok = true;
        }
    }));
    REQUIRE(saw_ok);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("empty-methods USERAUTH_FAILURE is not pk_ok", "[auth][publickey][pkok]") {
    user_key uk;
    generate_user_key(prov(), crypto::sig_id::ed25519, 0, uk);
    peer_session s{core::role::client};
    s.handshake();
    REQUIRE_FALSE(s.sut.conn.auth_publickey_query("alice", uk.blob()));
    REQUIRE_FALSE(s.peer.exchange(s.sut));
    REQUIRE(s.peer.take(wire::msg::userauth_request));

    wire::detail::userauth_failure fail;
    fail.out_methods = {};
    fail.partial_success = false;
    s.peer.send_msg(fail);
    REQUIRE_FALSE(s.peer.exchange(s.sut));
    REQUIRE(s.sut.handler.events.size() == 1);
    const auto* rec = std::get_if<recording_handler::auth_response>(&s.sut.handler.events[0]);
    REQUIRE(rec != nullptr);
    REQUIRE_FALSE(rec->success);
    REQUIRE_FALSE(rec->pk_ok);
    REQUIRE(rec->methods.empty());
    REQUIRE_FALSE(s.sut.conn.auth_none("alice"));        // 回到可发起下一次请求的状态
}

TEST_CASE("signed publickey treats PK_OK as unexpected_message", "[auth][publickey]") {
    auto p = prov();
    std::array<std::byte, crypto::max_generated_key_storage> storage{};
    crypto::private_key_material priv{};
    REQUIRE(p.generate_keypair(crypto::sig_id::ed25519, 0, priv, storage));
    crypto::public_key_material pub{crypto::sig_id::ed25519, priv.public_key, {}};
    keys::public_key pk;
    REQUIRE_FALSE(keys::public_key::from_material(pub, pk));

    peer_session s{core::role::client};
    s.handshake();
    REQUIRE_FALSE(s.sut.conn.auth_publickey("alice", pk.blob(), priv));
    REQUIRE_FALSE(s.peer.exchange(s.sut));
    REQUIRE(s.peer.take(wire::msg::userauth_request));

    wire::detail::userauth_pk_ok pkok;
    pkok.algorithm = "ssh-ed25519";
    pkok.blob = pk.blob();
    s.peer.send_msg(pkok);
    REQUIRE(s.peer.deliver(s.sut) == code::unexpected_message);
}

TEST_CASE("ed25519-only server accepts rsa-sha2 user key by default", "[auth][publickey][rsa]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    auto client = make_client(p);
    auto server = make_server(p);
    configure_server(server, hm);
    handshake_capture cap;
    REQUIRE(run_handshake(client, server, cap));
    REQUIRE(client.conn.server_sig_algs() == kex::default_host_key_algorithms(p));

    user_key rsa;
    generate_user_key(p, crypto::sig_id::rsa_pkcs1_sha256, 2048, rsa);

    REQUIRE_FALSE(client.conn.auth_publickey_query("alice", rsa.blob()));
    bool saw_query = false;
    bool saw_pk_ok = false;
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client, const recording_handler::recorded_event& ev) {
        if (!is_client && std::holds_alternative<recording_handler::auth_request>(ev)) {
            const auto& req = std::get<recording_handler::auth_request>(ev);
            REQUIRE_FALSE(req.has_signature);
            REQUIRE(req.algorithm == "rsa-sha2-256");
            saw_query = true;
            server.conn.resolve(req.ticket, auth_verdict::success());
        }
        if (is_client && std::holds_alternative<recording_handler::auth_response>(ev)) {
            REQUIRE(std::get<recording_handler::auth_response>(ev).pk_ok);
            saw_pk_ok = true;
        }
    }));
    REQUIRE(saw_query);
    REQUIRE(saw_pk_ok);

    client.handler.events.clear();
    server.handler.events.clear();
    REQUIRE_FALSE(client.conn.auth_publickey("alice", rsa.blob(), rsa.priv));
    bool saw_signed = false;
    bool saw_ok = false;
    REQUIRE(run_auth_loopback(client, server, [&](bool is_client, const recording_handler::recorded_event& ev) {
        if (!is_client && std::holds_alternative<recording_handler::auth_request>(ev)) {
            const auto& req = std::get<recording_handler::auth_request>(ev);
            REQUIRE(req.has_signature);
            REQUIRE(req.algorithm == "rsa-sha2-256");
            saw_signed = true;
            server.conn.resolve(req.ticket, auth_verdict::success());
        }
        if (is_client && std::holds_alternative<recording_handler::auth_response>(ev)) {
            REQUIRE(std::get<recording_handler::auth_response>(ev).success);
            saw_ok = true;
        }
    }));
    REQUIRE(saw_signed);
    REQUIRE(saw_ok);
    REQUIRE_FALSE(client.conn.failure());
    REQUIRE_FALSE(server.conn.failure());
}

TEST_CASE("default server rejects ssh-rsa publickey before on_auth_request",
          "[auth][publickey]") {
    // Plan task 2 (a): empty accepted_publickey_algorithms → default excludes ssh-rsa.
    auto cfg = scripted_peer::sut_config();
    REQUIRE(cfg.accepted_publickey_algorithms.empty());
    peer_session s{core::role::server, cfg};
    s.handshake();

    user_key rsa;
    generate_user_key(s.p, crypto::sig_id::rsa_pkcs1_sha256, 2048, rsa);

    for (bool has_sig : {false, true}) {
        CAPTURE(has_sig);
        wire::detail::userauth_request_publickey msg;
        msg.user = "alice";
        msg.service = "ssh-connection";
        msg.has_signature = has_sig;
        msg.algorithm = "ssh-rsa";
        msg.blob = rsa.blob();
        const std::array<std::byte, 4> dummy_sig{};
        if (has_sig) msg.signature = dummy_sig;

        s.peer.send_msg(msg);
        REQUIRE_FALSE(s.peer.exchange(s.sut));
        REQUIRE(s.sut.handler.events.empty());  // on_auth_request == 0
        REQUIRE(s.peer.take(wire::msg::userauth_failure));
        REQUIRE_FALSE(s.peer.take(wire::msg::userauth_pk_ok));
        REQUIRE_FALSE(s.peer.take(wire::msg::userauth_success));
    }
}

TEST_CASE("server rejects publickey request outside accepted_publickey_algorithms before on_auth_request",
          "[auth][publickey]") {
    auto cfg = scripted_peer::sut_config();
    cfg.accepted_publickey_algorithms = "ssh-ed25519";
    peer_session s{core::role::server, cfg};
    s.handshake();

    user_key rsa;
    generate_user_key(s.p, crypto::sig_id::rsa_pkcs1_sha512, 2048, rsa);

    for (bool has_sig : {false, true}) {
        CAPTURE(has_sig);
        wire::detail::userauth_request_publickey msg;
        msg.user = "alice";
        msg.service = "ssh-connection";
        msg.has_signature = has_sig;
        msg.algorithm = "rsa-sha2-512";
        msg.blob = rsa.blob();
        const std::array<std::byte, 4> dummy_sig{};
        if (has_sig) msg.signature = dummy_sig;

        s.peer.send_msg(msg);
        REQUIRE_FALSE(s.peer.exchange(s.sut));
        REQUIRE(s.sut.handler.events.empty());
        REQUIRE(s.peer.take(wire::msg::userauth_failure));
        REQUIRE_FALSE(s.peer.take(wire::msg::userauth_pk_ok));
        REQUIRE_FALSE(s.peer.take(wire::msg::userauth_success));
    }

    user_key ed;
    generate_user_key(s.p, crypto::sig_id::ed25519, 0, ed);
    wire::detail::userauth_request_publickey query;
    query.user = "alice";
    query.service = "ssh-connection";
    query.has_signature = false;
    query.algorithm = "ssh-ed25519";
    query.blob = ed.blob();
    s.peer.send_msg(query);
    REQUIRE_FALSE(s.peer.exchange(s.sut));
    REQUIRE(s.sut.handler.events.size() == 1);
    const auto* req = std::get_if<recording_handler::auth_request>(&s.sut.handler.events[0]);
    REQUIRE(req != nullptr);
    REQUIRE(req->algorithm == "ssh-ed25519");
    REQUIRE_FALSE(s.sut.conn.resolve(req->ticket, auth_verdict::success()));
    REQUIRE_FALSE(s.peer.exchange(s.sut));
    REQUIRE(s.peer.take(wire::msg::userauth_pk_ok));
}

TEST_CASE("explicit accepted_publickey_algorithms can opt into ssh-rsa and rsa-sha2-512",
          "[auth][publickey][rsa]") {
    auto p = prov();
    auto hm = make_ed25519_host(p);
    user_key rsa;
    generate_user_key(p, crypto::sig_id::rsa_pkcs1_sha256, 2048, rsa);

    {
        core::config server_cfg;
        server_cfg.accepted_publickey_algorithms = "ssh-rsa,rsa-sha2-512";
        auto client = make_client(p);
        auto server = make_server(p, server_cfg);
        configure_server(server, hm);
        handshake_capture cap;
        REQUIRE(run_handshake(client, server, cap));
        REQUIRE(client.conn.server_sig_algs() == "ssh-rsa,rsa-sha2-512");

        REQUIRE_FALSE(client.conn.auth_publickey("alice", rsa.blob(), rsa.priv));
        bool saw_req = false;
        bool saw_ok = false;
        REQUIRE(run_auth_loopback(client, server, [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (!is_client && std::holds_alternative<recording_handler::auth_request>(ev)) {
                const auto& req = std::get<recording_handler::auth_request>(ev);
                REQUIRE(req.has_signature);
                REQUIRE(req.algorithm == "rsa-sha2-512");
                saw_req = true;
                server.conn.resolve(req.ticket, auth_verdict::success());
            }
            if (is_client && std::holds_alternative<recording_handler::auth_response>(ev)) {
                REQUIRE(std::get<recording_handler::auth_response>(ev).success);
                saw_ok = true;
            }
        }));
        REQUIRE(saw_req);
        REQUIRE(saw_ok);
        REQUIRE_FALSE(client.conn.failure());
        REQUIRE_FALSE(server.conn.failure());

        auto peer_cfg = scripted_peer::sut_config();
        peer_cfg.accepted_publickey_algorithms = "ssh-rsa,rsa-sha2-512";
        peer_session s{core::role::server, peer_cfg};
        s.handshake();
        wire::detail::userauth_request_publickey query;
        query.user = "alice";
        query.service = "ssh-connection";
        query.has_signature = false;
        query.algorithm = "ssh-rsa";
        query.blob = rsa.blob();
        s.peer.send_msg(query);
        REQUIRE_FALSE(s.peer.exchange(s.sut));
        REQUIRE(s.sut.handler.events.size() == 1);
        const auto* req = std::get_if<recording_handler::auth_request>(&s.sut.handler.events[0]);
        REQUIRE(req != nullptr);
        REQUIRE(req->algorithm == "ssh-rsa");
        REQUIRE_FALSE(s.sut.conn.resolve(req->ticket, auth_verdict::success()));
        REQUIRE_FALSE(s.peer.exchange(s.sut));
        REQUIRE(s.peer.take(wire::msg::userauth_pk_ok));
    }

    {
        core::config client_cfg;
        client_cfg.preferred_host_key = "ssh-ed25519,ssh-rsa";
        core::config server_cfg;
        server_cfg.accepted_publickey_algorithms = "ssh-rsa";
        auto client = make_client(p, client_cfg);
        auto server = make_server(p, server_cfg);
        configure_server(server, hm);
        handshake_capture cap;
        REQUIRE(run_handshake(client, server, cap));
        REQUIRE(client.conn.server_sig_algs() == "ssh-rsa");

        REQUIRE_FALSE(client.conn.auth_publickey("alice", rsa.blob(), rsa.priv));
        bool saw_req = false;
        bool saw_ok = false;
        REQUIRE(run_auth_loopback(client, server, [&](bool is_client, const recording_handler::recorded_event& ev) {
            if (!is_client && std::holds_alternative<recording_handler::auth_request>(ev)) {
                const auto& req = std::get<recording_handler::auth_request>(ev);
                REQUIRE(req.has_signature);
                REQUIRE(req.algorithm == "ssh-rsa");
                saw_req = true;
                server.conn.resolve(req.ticket, auth_verdict::success());
            }
            if (is_client && std::holds_alternative<recording_handler::auth_response>(ev)) {
                REQUIRE(std::get<recording_handler::auth_response>(ev).success);
                saw_ok = true;
            }
        }));
        REQUIRE(saw_req);
        REQUIRE(saw_ok);
        REQUIRE_FALSE(client.conn.failure());
        REQUIRE_FALSE(server.conn.failure());
    }
}

namespace {

void send_hostbound_ext(scripted_peer& peer, std::string_view version) {
    const auto value = std::as_bytes(std::span{version.data(), version.size()});
    const wire::detail::ext_info::entry entries[] = {{"publickey-hostbound@openssh.com", value}};
    wire::detail::ext_info msg;
    msg.entries = entries;
    peer.send_msg(msg);
}

struct held_publickey : public wire::detail::userauth_request_publickey {
    std::vector<std::byte> raw;

    explicit held_publickey(std::vector<std::byte> bytes) : raw(std::move(bytes)) {
        wire::reader reader{raw};
        REQUIRE(decode(reader));
        REQUIRE(reader.empty());
    }

    held_publickey(const held_publickey&) = delete;
    held_publickey& operator=(const held_publickey&) = delete;
    held_publickey(held_publickey&&) = delete;
    held_publickey& operator=(held_publickey&&) = delete;
};

held_publickey take_publickey(scripted_peer& peer) {
    auto raw = peer.take(wire::msg::userauth_request);
    REQUIRE(raw);
    return held_publickey{std::move(*raw)};
}

}  // namespace

TEST_CASE("publickey requests follow the host-bound capability already received", "[auth][publickey][hostbound]") {
    user_key uk;
    generate_user_key(prov(), crypto::sig_id::ed25519, 0, uk);

    SECTION("no extension keeps the plain method") {
        peer_session s{core::role::client};
        s.handshake();
        REQUIRE_FALSE(s.sut.conn.supports_hostbound_publickey());
        REQUIRE_FALSE(s.sut.conn.auth_publickey_query("alice", uk.blob()));
        REQUIRE_FALSE(s.peer.exchange(s.sut));
        const auto query = take_publickey(s.peer);
        REQUIRE(query.method == auth::method_publickey);
        REQUIRE_FALSE(query.has_signature);
        REQUIRE(query.server_host_key.empty());

        wire::detail::userauth_failure fail;
        const std::string_view methods[] = {"publickey"};
        fail.out_methods = methods;
        s.peer.send_msg(fail);
        REQUIRE_FALSE(s.peer.exchange(s.sut));
        REQUIRE_FALSE(s.peer.take(wire::msg::userauth_request));

        REQUIRE_FALSE(s.sut.conn.auth_publickey("alice", uk.blob(), uk.priv));
        REQUIRE_FALSE(s.peer.exchange(s.sut));
        const auto signed_req = take_publickey(s.peer);
        REQUIRE(signed_req.method == auth::method_publickey);
        REQUIRE(signed_req.has_signature);
        REQUIRE(signed_req.server_host_key.empty());
        s.peer.send_msg(fail);
        REQUIRE_FALSE(s.peer.exchange(s.sut));
        REQUIRE_FALSE(s.peer.take(wire::msg::userauth_request));
    }

    SECTION("version 0 uses host-bound for the query and the signed request") {
        peer_session s{core::role::client};
        s.handshake();
        send_hostbound_ext(s.peer, "0");
        REQUIRE_FALSE(s.peer.exchange(s.sut));
        REQUIRE(s.sut.conn.supports_hostbound_publickey());
        const auto host = s.sut.conn.initial_host_key();
        REQUIRE_FALSE(host.empty());

        core::publickey_sign_request prepared;
        wire::writer signed_data;
        REQUIRE_FALSE(s.sut.conn.auth_publickey_sign_request("alice", uk.blob(), prepared, signed_data));
        wire::reader signed_reader{signed_data.data()};
        std::span<const std::byte> sid;
        std::uint8_t id = 0;
        std::string_view user;
        std::string_view service;
        std::string_view method;
        REQUIRE(signed_reader.read_string(sid));
        REQUIRE(signed_reader.read_byte(id));
        REQUIRE(signed_reader.read_string(user));
        REQUIRE(signed_reader.read_string(service));
        REQUIRE(signed_reader.read_string(method));
        REQUIRE(method == auth::method_hostbound_publickey);

        REQUIRE_FALSE(s.sut.conn.auth_publickey_query("alice", uk.blob()));
        REQUIRE_FALSE(s.peer.exchange(s.sut));
        const auto query = take_publickey(s.peer);
        REQUIRE(query.method == auth::method_hostbound_publickey);
        REQUIRE_FALSE(query.has_signature);
        REQUIRE(std::equal(query.server_host_key.begin(), query.server_host_key.end(), host.begin(),
                           host.end()));

        wire::detail::userauth_pk_ok pk_ok;
        pk_ok.algorithm = "ssh-ed25519";
        pk_ok.blob = uk.blob();
        s.peer.send_msg(pk_ok);
        REQUIRE_FALSE(s.peer.exchange(s.sut));

        REQUIRE_FALSE(s.sut.conn.auth_publickey("alice", uk.blob(), uk.priv));
        REQUIRE_FALSE(s.peer.exchange(s.sut));
        const auto signed_req = take_publickey(s.peer);
        REQUIRE(signed_req.method == auth::method_hostbound_publickey);
        REQUIRE(signed_req.has_signature);
        REQUIRE(std::equal(signed_req.server_host_key.begin(), signed_req.server_host_key.end(),
                           host.begin(), host.end()));
        wire::detail::userauth_failure fail;
        const std::string_view methods[] = {"publickey"};
        fail.out_methods = methods;
        s.peer.send_msg(fail);
        REQUIRE_FALSE(s.peer.exchange(s.sut));
        REQUIRE_FALSE(s.peer.take(wire::msg::userauth_request));
        REQUIRE_FALSE(s.sut.conn.failure());
    }

    SECTION("another version does not select host-bound") {
        peer_session s{core::role::client};
        s.handshake();
        send_hostbound_ext(s.peer, "1");
        REQUIRE_FALSE(s.peer.exchange(s.sut));
        REQUIRE_FALSE(s.sut.conn.supports_hostbound_publickey());
        REQUIRE_FALSE(s.sut.conn.auth_publickey_query("alice", uk.blob()));
        REQUIRE_FALSE(s.peer.exchange(s.sut));
        const auto query = take_publickey(s.peer);
        REQUIRE(query.method == auth::method_publickey);
        REQUIRE(query.server_host_key.empty());
    }
}

TEST_CASE("a later host-bound announcement replaces the capability and omission does not",
          "[auth][publickey][hostbound]") {
    peer_session s{core::role::client};
    s.handshake();
    REQUIRE_FALSE(s.sut.conn.supports_hostbound_publickey());

    send_hostbound_ext(s.peer, "0");
    REQUIRE_FALSE(s.peer.exchange(s.sut));
    REQUIRE(s.sut.conn.supports_hostbound_publickey());

    const auto algs = std::string_view{"ssh-ed25519"};
    const wire::detail::ext_info::entry only_algs[] = {
        {"server-sig-algs", std::as_bytes(std::span{algs.data(), algs.size()})}};
    wire::detail::ext_info omit;
    omit.entries = only_algs;
    s.peer.send_msg(omit);
    REQUIRE_FALSE(s.peer.exchange(s.sut));
    REQUIRE(s.sut.conn.supports_hostbound_publickey());

    send_hostbound_ext(s.peer, "1");
    REQUIRE_FALSE(s.peer.exchange(s.sut));
    REQUIRE_FALSE(s.sut.conn.supports_hostbound_publickey());
}

TEST_CASE("the server rejects a host-bound request with the wrong host key or a bad signature",
          "[auth][publickey][hostbound]") {
    user_key uk;
    generate_user_key(prov(), crypto::sig_id::ed25519, 0, uk);
    peer_session s{core::role::server};
    s.handshake();
    const auto host = std::vector<std::byte>{s.sut.conn.initial_host_key().begin(),
                                             s.sut.conn.initial_host_key().end()};
    REQUIRE_FALSE(host.empty());
    const std::array<std::byte, 4> wrong{std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4}};
    const std::array<std::byte, 4> bogus_sig{std::byte{9}, std::byte{9}, std::byte{9}, std::byte{9}};

    struct row {
        const char* name;
        bool has_signature;
        bool wrong_host;
    };
    const row rows[] = {
        {"probe, wrong host", false, true},
        {"signed, wrong host", true, true},
        {"signed, bad signature", true, false},
    };
    for (const auto& row : rows) {
        INFO(row.name);
        s.sut.handler.events.clear();
        s.peer.clear_received();
        wire::detail::userauth_request_publickey msg;
        msg.user = "alice";
        msg.service = "ssh-connection";
        msg.method = auth::method_hostbound_publickey;
        msg.has_signature = row.has_signature;
        msg.algorithm = "ssh-ed25519";
        msg.blob = uk.blob();
        msg.server_host_key = row.wrong_host ? std::span<const std::byte>{wrong} : std::span<const std::byte>{host};
        if (row.has_signature) msg.signature = bogus_sig;
        s.peer.send_msg(msg);
        REQUIRE_FALSE(s.peer.exchange(s.sut));
        REQUIRE(s.peer.take(wire::msg::userauth_failure));
        for (const auto& ev : s.sut.handler.events) {
            REQUIRE_FALSE(std::holds_alternative<recording_handler::auth_request>(ev));
        }
        REQUIRE_FALSE(s.sut.conn.failure());
    }

    wire::writer truncated;
    truncated.write_byte(static_cast<std::uint8_t>(wire::msg::userauth_request));
    truncated.write_string("alice");
    truncated.write_string("ssh-connection");
    truncated.write_string(auth::method_hostbound_publickey);
    truncated.write_bool(true);
    truncated.write_string("ssh-ed25519");
    s.peer.send(truncated.data());
    REQUIRE(s.peer.exchange(s.sut) == code::invalid_format);
}
