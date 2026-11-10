#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/agent/packets.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/keys/private_key.hpp>

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using namespace yanterm::ssh;

namespace {

std::vector<std::byte> bytes(std::initializer_list<int> vs) {
    std::vector<std::byte> out;
    out.reserve(vs.size());
    for (int v : vs) out.push_back(static_cast<std::byte>(v));
    return out;
}

std::vector<std::byte> take(wire::writer& w) { return w.take(); }

void append_u32(std::vector<std::byte>& out, std::uint32_t v) {
    out.push_back(static_cast<std::byte>(v >> 24));
    out.push_back(static_cast<std::byte>(v >> 16));
    out.push_back(static_cast<std::byte>(v >> 8));
    out.push_back(static_cast<std::byte>(v));
}

void append_str(std::vector<std::byte>& out, std::string_view s) {
    append_u32(out, static_cast<std::uint32_t>(s.size()));
    for (char c : s) out.push_back(static_cast<std::byte>(c));
}

void append_blob(std::vector<std::byte>& out, std::string_view s) { append_str(out, s); }

std::span<const std::byte> as_bytes(std::string_view s) {
    return {reinterpret_cast<const std::byte*>(s.data()), s.size()};
}

}  // namespace

TEST_CASE("agent refusals stay distinct request denials", "[agent][packets]") {
    const auto failure = agent::make_error_code(agent::refusal::failure);
    const auto extension = agent::make_error_code(agent::refusal::extension_failure);
    CHECK(failure == agent::refusal::failure);
    CHECK(extension == agent::refusal::extension_failure);
    CHECK(failure != extension);
    CHECK(failure == errc::request_denied);
    CHECK(extension == errc::request_denied);
    CHECK(failure != errc::transport_failed);
    CHECK(failure.category() == agent::error_category());
    CHECK(failure.category().name() == std::string_view{"yanterm-ssh.agent"});
}

TEST_CASE("agent frame length counts the type and rejects an empty frame", "[agent][packets]") {
    wire::writer w;
    agent::encode_frame_header(w, 1);
    agent::encode_failure(w);
    CHECK(take(w) == bytes({0, 0, 0, 1, 5}));

    CHECK(agent::decode_frame_header(bytes({0, 0, 0, 1})) == 1);
    CHECK(agent::decode_frame_header(bytes({0, 0, 1})) == 0);
    CHECK(agent::message_length_ok(1, agent::default_max_message_length));
    CHECK_FALSE(agent::message_length_ok(0, agent::default_max_message_length));
    CHECK_FALSE(agent::message_length_ok(agent::default_max_message_length + 1,
                                         agent::default_max_message_length));
}

TEST_CASE("agent fixed messages match RFC 9987 type bytes", "[agent][packets]") {
    struct row {
        const char* name;
        std::vector<std::byte> wire;
        bool (*decode)(std::span<const std::byte>);
        void (*encode)(wire::writer&);
    };
    const row rows[] = {
        {"failure", bytes({5}), &agent::decode_failure, &agent::encode_failure},
        {"success", bytes({6}), &agent::decode_success, &agent::encode_success},
        {"request identities", bytes({11}), &agent::decode_request_identities,
         &agent::encode_request_identities},
        {"extension failure", bytes({28}), &agent::decode_extension_failure,
         &agent::encode_extension_failure},
    };
    for (const auto& row : rows) {
        INFO(row.name);
        wire::writer w;
        row.encode(w);
        CHECK(take(w) == row.wire);
        CHECK(row.decode(row.wire));
        auto extra = row.wire;
        extra.push_back(std::byte{0});
        CHECK_FALSE(row.decode(extra));
        CHECK_FALSE(row.decode({}));
    }
}

TEST_CASE("agent identities answer is a count of key and comment pairs", "[agent][packets]") {
    std::vector<std::byte> hand;
    hand.push_back(std::byte{12});
    append_u32(hand, 2);
    append_blob(hand, "k1");
    append_str(hand, "one");
    append_blob(hand, "k2");
    append_str(hand, "two");

    const agent::identity_view ids[] = {as_bytes("k1"), "one", as_bytes("k2"), "two"};
    wire::writer w;
    agent::encode_identities_answer(w, ids);
    CHECK(take(w) == hand);

    std::vector<agent::identity_view> out;
    REQUIRE(agent::decode_identities_answer(hand, out));
    REQUIRE(out.size() == 2);
    CHECK(out[0].key_blob.data() == hand.data() + 9);
    CHECK(std::string_view{reinterpret_cast<const char*>(out[0].key_blob.data()),
                           out[0].key_blob.size()} == "k1");
    CHECK(out[0].comment == "one");
    CHECK(out[1].comment == "two");

    auto trailing = hand;
    trailing.push_back(std::byte{0});
    CHECK_FALSE(agent::decode_identities_answer(trailing, out));
    CHECK(out.empty());

    std::vector<std::byte> short_count;
    short_count.push_back(std::byte{12});
    append_u32(short_count, 2);
    append_blob(short_count, "k1");
    append_str(short_count, "one");
    CHECK_FALSE(agent::decode_identities_answer(short_count, out));

    std::vector<std::byte> huge;
    huge.push_back(std::byte{12});
    append_u32(huge, 0xffffffffu);
    CHECK_FALSE(agent::decode_identities_answer(huge, out));
    CHECK(out.empty());
}

TEST_CASE("agent sign request orders key, data, then flags", "[agent][packets]") {
    std::vector<std::byte> hand;
    hand.push_back(std::byte{13});
    append_blob(hand, "key");
    append_blob(hand, "data");
    append_u32(hand, 2);

    wire::writer w;
    agent::encode_sign_request(w, as_bytes("key"), as_bytes("data"), agent::sign_flags::rsa_sha2_256);
    CHECK(take(w) == hand);

    std::span<const std::byte> key;
    std::span<const std::byte> data;
    std::uint32_t flags = 0;
    REQUIRE(agent::decode_sign_request(hand, key, data, flags));
    CHECK(flags == 2);
    CHECK(key.data() == hand.data() + 5);

    hand.back() = std::byte{4};
    REQUIRE(agent::decode_sign_request(hand, key, data, flags));
    CHECK(flags == agent::sign_flags::rsa_sha2_512);

    hand.pop_back();
    CHECK_FALSE(agent::decode_sign_request(hand, key, data, flags));
    hand.push_back(std::byte{4});
    hand.push_back(std::byte{0});
    CHECK_FALSE(agent::decode_sign_request(hand, key, data, flags));
}

TEST_CASE("agent sign response borrows the signature blob", "[agent][packets]") {
    std::vector<std::byte> hand;
    hand.push_back(std::byte{14});
    append_blob(hand, "sig");

    wire::writer w;
    agent::encode_sign_response(w, as_bytes("sig"));
    CHECK(take(w) == hand);

    std::span<const std::byte> signature;
    REQUIRE(agent::decode_sign_response(hand, signature));
    CHECK(signature.data() == hand.data() + 5);
    CHECK(signature.size() == 3);

    hand.push_back(std::byte{1});
    CHECK_FALSE(agent::decode_sign_response(hand, signature));
}

TEST_CASE("agent extension keeps the remainder after the name", "[agent][packets]") {
    std::vector<std::byte> hand;
    hand.push_back(std::byte{27});
    append_str(hand, "query@example");
    hand.insert(hand.end(), {std::byte{9}, std::byte{8}, std::byte{7}});

    wire::writer w;
    agent::encode_extension(w, "query@example", bytes({9, 8, 7}));
    CHECK(take(w) == hand);

    std::string_view name;
    std::span<const std::byte> data;
    REQUIRE(agent::decode_extension(hand, name, data));
    CHECK(name == "query@example");
    CHECK(data.size() == 3);
    CHECK(data.data() == hand.data() + hand.size() - 3);

    auto truncated = hand;
    truncated.resize(1 + 4);
    CHECK_FALSE(agent::decode_extension(truncated, name, data));
}

TEST_CASE("agent session-bind follows the OpenSSH field order", "[agent][packets]") {
    const auto build = [](bool forwarding) {
        std::vector<std::byte> hand;
        hand.push_back(std::byte{27});
        append_str(hand, agent::session_bind_extension);
        append_blob(hand, "host");
        append_blob(hand, "sess");
        append_blob(hand, "kexsig");
        hand.push_back(static_cast<std::byte>(forwarding ? 1 : 0));
        return hand;
    };

    for (const bool forwarding : {false, true}) {
        const auto hand = build(forwarding);
        wire::writer w;
        agent::encode_session_bind(w, as_bytes("host"), as_bytes("sess"), as_bytes("kexsig"),
                                   forwarding);
        CHECK(take(w) == hand);

        std::span<const std::byte> host;
        std::span<const std::byte> session_id;
        std::span<const std::byte> signature;
        bool got = !forwarding;
        REQUIRE(agent::decode_session_bind(hand, host, session_id, signature, got));
        CHECK(got == forwarding);
        CHECK(std::string_view{reinterpret_cast<const char*>(host.data()), host.size()} == "host");
        CHECK(std::string_view{reinterpret_cast<const char*>(session_id.data()), session_id.size()}
              == "sess");
        CHECK(std::string_view{reinterpret_cast<const char*>(signature.data()), signature.size()}
              == "kexsig");
    }

    auto wrong_name = build(false);
    wrong_name[5] = std::byte{'X'};
    std::span<const std::byte> host;
    std::span<const std::byte> session_id;
    std::span<const std::byte> signature;
    bool forwarding = false;
    CHECK_FALSE(agent::decode_session_bind(wrong_name, host, session_id, signature, forwarding));

    auto truncated = build(true);
    truncated.pop_back();
    CHECK_FALSE(agent::decode_session_bind(truncated, host, session_id, signature, forwarding));

    auto extra = build(false);
    extra.push_back(std::byte{0});
    CHECK_FALSE(agent::decode_session_bind(extra, host, session_id, signature, forwarding));
}

TEST_CASE("agent management messages match RFC 9987", "[agent][packets]") {
    CHECK(static_cast<int>(agent::msg::add_identity) == 17);
    CHECK(static_cast<int>(agent::msg::remove_identity) == 18);
    CHECK(static_cast<int>(agent::msg::remove_all_identities) == 19);
    CHECK(static_cast<int>(agent::msg::add_smartcard_key) == 20);
    CHECK(static_cast<int>(agent::msg::remove_smartcard_key) == 21);
    CHECK(static_cast<int>(agent::msg::lock) == 22);
    CHECK(static_cast<int>(agent::msg::unlock) == 23);
    CHECK(static_cast<int>(agent::msg::add_id_constrained) == 25);
    CHECK(static_cast<int>(agent::msg::add_smartcard_key_constrained) == 26);
    CHECK(static_cast<int>(agent::msg::extension_response) == 29);
    CHECK(agent::constrain::lifetime == 1);
    CHECK(agent::constrain::confirm == 2);
    CHECK(agent::constrain::extension == 255);

    {
        wire::writer w;
        agent::encode_remove_all_identities(w);
        CHECK(take(w) == bytes({19}));
        CHECK(agent::decode_remove_all_identities(bytes({19})));
        CHECK_FALSE(agent::decode_remove_all_identities(bytes({19, 0})));
    }
    {
        std::vector<std::byte> hand;
        hand.push_back(std::byte{18});
        append_blob(hand, "blob");
        wire::writer w;
        agent::encode_remove_identity(w, as_bytes("blob"));
        CHECK(take(w) == hand);
        std::span<const std::byte> blob;
        REQUIRE(agent::decode_remove_identity(hand, blob));
        CHECK(std::string_view{reinterpret_cast<const char*>(blob.data()), blob.size()} == "blob");
        hand.push_back(std::byte{1});
        CHECK_FALSE(agent::decode_remove_identity(hand, blob));
        hand.pop_back();
        hand.pop_back();
        CHECK_FALSE(agent::decode_remove_identity(hand, blob));
    }
    {
        std::vector<std::byte> hand;
        hand.push_back(std::byte{22});
        append_str(hand, "pw");
        wire::writer w;
        agent::encode_lock(w, "pw");
        CHECK(take(w) == hand);
        std::string_view pw;
        REQUIRE(agent::decode_lock(hand, pw));
        CHECK(pw == "pw");
        hand.push_back(std::byte{0});
        CHECK_FALSE(agent::decode_lock(hand, pw));
    }
    {
        std::vector<std::byte> hand;
        hand.push_back(std::byte{23});
        append_str(hand, "pw");
        wire::writer w;
        agent::encode_unlock(w, "pw");
        CHECK(take(w) == hand);
        std::string_view pw;
        REQUIRE(agent::decode_unlock(hand, pw));
        CHECK(pw == "pw");
        hand.resize(hand.size() - 1);
        CHECK_FALSE(agent::decode_unlock(hand, pw));
    }
    {
        std::vector<std::byte> hand;
        hand.push_back(std::byte{21});
        append_str(hand, "token");
        append_str(hand, "pin");
        wire::writer w;
        agent::encode_remove_smartcard_key(w, "token", "pin");
        CHECK(take(w) == hand);
        std::string_view token;
        std::string_view pin;
        REQUIRE(agent::decode_remove_smartcard_key(hand, token, pin));
        CHECK(token == "token");
        CHECK(pin == "pin");
        hand.push_back(std::byte{0});
        CHECK_FALSE(agent::decode_remove_smartcard_key(hand, token, pin));
    }
    {
        agent::key_constraints constraints;
        constraints.lifetime_seconds = 9;
        std::vector<std::byte> hand;
        hand.push_back(std::byte{26});
        append_str(hand, "token");
        append_str(hand, "pin");
        hand.push_back(std::byte{agent::constrain::lifetime});
        append_u32(hand, 9);
        wire::writer w;
        agent::encode_add_smartcard_key(w, "token", "pin", constraints);
        CHECK(take(w) == hand);
        std::string_view token;
        std::string_view pin;
        agent::key_constraints got;
        REQUIRE(agent::decode_add_smartcard_key(hand, token, pin, got));
        CHECK(token == "token");
        CHECK(pin == "pin");
        REQUIRE(got.lifetime_seconds);
        CHECK(*got.lifetime_seconds == 9);
        hand.push_back(std::byte{9});
        CHECK_FALSE(agent::decode_add_smartcard_key(hand, token, pin, got));
        CHECK_FALSE(got.lifetime_seconds);
    }
    {
        std::vector<std::byte> hand;
        hand.push_back(std::byte{29});
        append_str(hand, "query");
        append_str(hand, "session-bind@openssh.com");
        append_str(hand, "query");
        wire::writer inner;
        inner.write_string("session-bind@openssh.com");
        inner.write_string("query");
        wire::writer w;
        agent::encode_extension_response(w, "query", inner.data());
        CHECK(take(w) == hand);
        std::vector<std::string> names;
        REQUIRE(agent::decode_query_response(hand, names));
        REQUIRE(names.size() == 2);
        CHECK(names[0] == "session-bind@openssh.com");
        CHECK(names[1] == "query");

        hand.push_back(std::byte{0});
        CHECK_FALSE(agent::decode_query_response(hand, names));
        CHECK(names.empty());

        wire::writer huge;
        huge.write_byte(29);
        huge.write_string(agent::query_extension);
        for (std::uint32_t i = 0; i < agent::max_identities_count + 1; ++i) huge.write_string("");
        CHECK_FALSE(agent::decode_query_response(huge.data(), names));
        CHECK(names.empty());
    }
}

TEST_CASE("agent add identity follows the RFC key layouts", "[agent][packets]") {
    crypto::openssl_backend backend;
    auto p = crypto::provider::wrap(backend);

    const auto expect_key = [](const keys::private_key& key, std::string_view comment,
                               bool constrained) {
        const auto m = key.material();
        wire::writer hand;
        hand.write_byte(constrained ? 25 : 17);
        hand.write_string(key.pub().algorithm_name());
        if (key.pub().algorithm_name() == "ssh-ed25519") {
            hand.write_string(m.public_key);
            REQUIRE(m.seed.size() == 32);
            REQUIRE(m.public_key.size() == 32);
            hand.write_uint32(64);
            hand.write_bytes(m.seed);
            hand.write_bytes(m.public_key);
        } else if (key.pub().algorithm_name() == "ssh-rsa") {
            hand.write_mpint(m.n);
            hand.write_mpint(m.e);
            hand.write_mpint(m.d);
            hand.write_mpint(m.iqmp);
            hand.write_mpint(m.p);
            hand.write_mpint(m.q);
        } else {
            REQUIRE(key.pub().algorithm_name() == "ecdsa-sha2-nistp256");
            hand.write_string("nistp256");
            hand.write_string(m.public_key);
            hand.write_mpint(m.seed);
        }
        hand.write_string(comment);
        if (constrained) {
            hand.write_byte(agent::constrain::lifetime);
            hand.write_uint32(60);
            hand.write_byte(agent::constrain::confirm);
            hand.write_byte(agent::constrain::extension);
            hand.write_string("ext@example.com");
            hand.write_bytes(as_bytes("details"));
        }

        wire::writer body;
        REQUIRE_FALSE(keys::detail::encode_private_body(key.pub(), m, body));
        agent::key_constraints constraints;
        if (constrained) {
            constraints.lifetime_seconds = 60;
            constraints.confirm = true;
            constraints.extensions.push_back(
                {"ext@example.com",
                 std::vector<std::byte>(as_bytes("details").begin(), as_bytes("details").end())});
        }
        wire::writer encoded;
        agent::encode_add_identity(encoded, body.data(), comment, constraints);
        CHECK(take(encoded) == take(hand));
    };

    keys::private_key ed;
    REQUIRE_FALSE(keys::private_key::generate(p, crypto::sig_id::ed25519, 0, "ed", ed));
    expect_key(ed, "comment", false);
    keys::private_key ec;
    REQUIRE_FALSE(keys::private_key::generate(p, crypto::sig_id::ecdsa_nistp256, 0, "ec", ec));
    expect_key(ec, "comment", false);
    keys::private_key rsa;
    REQUIRE_FALSE(keys::private_key::generate(p, crypto::sig_id::rsa_pkcs1_sha256, 2048, "rsa", rsa));
    expect_key(rsa, "comment", true);

    wire::writer encoded;
    const auto m = ed.material();
    wire::writer body;
    REQUIRE_FALSE(keys::detail::encode_private_body(ed.pub(), m, body));
    agent::key_constraints constraints;
    constraints.lifetime_seconds = 60;
    constraints.confirm = true;
    constraints.extensions.push_back({"ext@example.com", {std::byte{'d'}}});
    agent::encode_add_identity(encoded, body.data(), "comment", constraints);
    std::span<const std::byte> key;
    std::string_view comment;
    agent::key_constraints got;
    REQUIRE(agent::decode_add_identity(encoded.data(), key, comment, got));
    CHECK(comment == "comment");
    REQUIRE(got.lifetime_seconds);
    CHECK(*got.lifetime_seconds == 60);
    CHECK(got.confirm);
    REQUIRE(got.extensions.size() == 1);
    CHECK(got.extensions[0].name == "ext@example.com");
    CHECK(got.extensions[0].details.size() == 1);

    wire::writer bare;
    bare.write_byte(25);
    bare.write_string("ssh-ed25519");
    bare.write_string(m.public_key);
    bare.write_uint32(64);
    bare.write_bytes(m.seed);
    bare.write_bytes(m.public_key);
    bare.write_string("comment");
    bare.write_byte(9);
    CHECK_FALSE(agent::decode_add_identity(bare.data(), key, comment, got));

    wire::writer dsa;
    dsa.write_byte(17);
    dsa.write_string("ssh-dss");
    for (int i = 0; i < 5; ++i) dsa.write_mpint(as_bytes("\x01"));
    dsa.write_string("dsa-comment");
    REQUIRE(agent::decode_add_identity(dsa.data(), key, comment, got));
    CHECK(comment == "dsa-comment");
    CHECK(agent::constraints_empty(got));
    auto extra_dsa = take(dsa);
    extra_dsa.push_back(std::byte{0});
    CHECK_FALSE(agent::decode_add_identity(extra_dsa, key, comment, got));

    wire::writer other;
    other.write_byte(17);
    other.write_string("ssh-unknown");
    other.write_string("comment");
    CHECK_FALSE(agent::decode_add_identity(other.data(), key, comment, got));

    auto truncated = extra_dsa;
    truncated.pop_back();
    truncated.pop_back();
    CHECK_FALSE(agent::decode_add_identity(truncated, key, comment, got));
}
