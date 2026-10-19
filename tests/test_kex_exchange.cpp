#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/kex/algorithms.hpp>
#include <yanterm-ssh/kex/detail/tables.hpp>
#include <yanterm-ssh/core/detail/kex_exchange.hpp>
#include <yanterm-ssh/wire/detail/messages.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/detail/error.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#ifndef YANTERM_SSH_FIXTURE_DIR
#error "YANTERM_SSH_FIXTURE_DIR must be defined"
#endif

using namespace yanterm::ssh;

namespace {

crypto::provider prov() {
    static crypto::openssl_backend backend;
    return crypto::provider::wrap(backend);
}

std::vector<std::byte> load_fixture(std::string_view name) {
    const std::string path = std::string{YANTERM_SSH_FIXTURE_DIR} + "/" + std::string{name};
    std::ifstream in{path, std::ios::binary};
    REQUIRE(in);
    in.seekg(0, std::ios::end);
    const auto n = static_cast<std::size_t>(in.tellg());
    in.seekg(0, std::ios::beg);
    std::vector<std::byte> out(n);
    if (n > 0) {
        in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(n));
        REQUIRE(in);
    }
    return out;
}

kex::negotiated make_negotiated(crypto::kex_id id, std::string_view name,
                                crypto::hash_id hash) {
    kex::negotiated n;
    n.kex = id;
    n.kex_name = name;
    n.host_key = crypto::sig_id::ed25519;
    n.host_key_name = "ssh-ed25519";
    n.exchange_hash = hash;
    return n;
}

bool is_ecdh(crypto::kex_id id) {
    return kex::detail::uses_ecdh_messages(id);
}

struct host_signer {
    std::vector<std::byte> blob;
    std::vector<std::byte> seed;
    crypto::signing_key key;
    crypto::public_key_material pub{};
};

host_signer make_ed25519_signer(crypto::provider p) {
    host_signer hs;
    hs.blob = load_fixture("ed25519.blob");
    hs.seed = load_fixture("ed25519.seed");
    core::detail::host_key_view view;
    REQUIRE_FALSE(core::detail::parse_host_key(hs.blob, view));
    hs.pub = view.material;
    crypto::private_key_material sk{crypto::sig_id::ed25519, hs.seed, hs.pub.a};
    hs.key = p.new_signing_key(sk);
    REQUIRE(static_cast<bool>(hs.key));
    return hs;
}

struct exchange_fixture {
    std::string v_c = "SSH-2.0-yanterm_client";
    std::string v_s = "SSH-2.0-yanterm_server";
    std::vector<std::byte> i_c;
    std::vector<std::byte> i_s;

    exchange_fixture() {
        // Minimal stand-ins for full KEXINIT payloads (include message id byte).
        i_c = {std::byte{20}, std::byte{'C'}, std::byte{1}, std::byte{2}, std::byte{3}};
        i_s = {std::byte{20}, std::byte{'S'}, std::byte{4}, std::byte{5}, std::byte{6}};
    }

    [[nodiscard]] core::detail::exchange_context ctx() const noexcept {
        return {v_c, v_s, i_c, i_s};
    }
};

struct round_trip_result {
    std::vector<std::byte> client_hash;
    std::vector<std::byte> server_hash;
    std::vector<std::byte> client_secret;
    std::vector<std::byte> server_secret;
    std::vector<std::byte> reply;
    std::vector<std::byte> init;
};

round_trip_result run_round_trip(crypto::provider p, const kex::negotiated& n,
                                 host_signer& hs, const exchange_fixture& fx) {
    round_trip_result rt;
    core::detail::key_exchange client{p, n, core::role::client};
    core::detail::key_exchange server{p, n, core::role::server};

    wire::writer init_w;
    REQUIRE_FALSE(client.start(init_w));
    rt.init.assign(init_w.data().begin(), init_w.data().end());

    wire::writer reply_w;
    std::span<const std::byte> server_hash;
    REQUIRE_FALSE(server.accept_init(fx.ctx(), rt.init, hs.blob, hs.key, reply_w, server_hash));
    rt.reply.assign(reply_w.data().begin(), reply_w.data().end());
    rt.server_hash.assign(server_hash.begin(), server_hash.end());
    rt.server_secret.assign(server.shared_secret().begin(), server.shared_secret().end());

    core::detail::host_key_view host_key;
    std::span<const std::byte> client_hash;
    REQUIRE_FALSE(client.accept_reply(fx.ctx(), rt.reply, host_key, client_hash));
    rt.client_hash.assign(client_hash.begin(), client_hash.end());
    rt.client_secret.assign(client.shared_secret().begin(), client.shared_secret().end());
    REQUIRE(host_key.blob.size() == hs.blob.size());
    client.consume_shared_secret();
    server.consume_shared_secret();
    REQUIRE(client.shared_secret().empty());
    REQUIRE(server.shared_secret().empty());
    return rt;
}

std::vector<std::byte> manual_exchange_hash(crypto::provider p, const kex::negotiated& n,
                                            const exchange_fixture& fx,
                                            std::span<const std::byte> ks,
                                            std::span<const std::byte> q_c,
                                            std::span<const std::byte> q_s,
                                            std::span<const std::byte> secret_mag) {
    wire::writer w;
    w.write_string(fx.v_c);
    w.write_string(fx.v_s);
    w.write_string(fx.i_c);
    w.write_string(fx.i_s);
    w.write_string(ks);
    if (is_ecdh(n.kex)) {
        w.write_string(q_c);
        w.write_string(q_s);
    } else {
        w.write_mpint(q_c);
        w.write_mpint(q_s);
    }
    w.write_mpint(secret_mag);

    std::vector<std::byte> out(crypto::hash_output_size(n.exchange_hash));
    REQUIRE(p.hash(n.exchange_hash, w.data(), out));
    return out;
}

struct fail_agree_overlay {
    crypto::provider inner_;

    [[nodiscard]] crypto::provider inner() const noexcept { return inner_; }

    void* kex_new(crypto::kex_id id) noexcept {
        auto h = inner_.new_kex(id);
        if (!h) return nullptr;
        return new (std::nothrow) crypto::kex_agreement(std::move(h));
    }
    void kex_free(void* ctx) noexcept { delete static_cast<crypto::kex_agreement*>(ctx); }
    bool kex_public(void* ctx, std::byte* out, std::size_t cap, std::size_t* out_len) noexcept {
        if (ctx == nullptr || out_len == nullptr) return false;
        return static_cast<crypto::kex_agreement*>(ctx)->public_value(
            std::span<std::byte>{out, cap}, *out_len);
    }
    bool kex_agree(void*, const std::byte*, std::size_t, std::byte*, std::size_t,
                   std::size_t*) noexcept {
        return false;
    }
};

}  // namespace

TEST_CASE("client/server kex round-trip agrees on H and K", "[kex][exchange]") {
    crypto::provider p = prov();
    auto hs = make_ed25519_signer(p);
    exchange_fixture fx;

    const struct {
        crypto::kex_id id;
        std::string_view name;
        crypto::hash_id hash;
    } cases[] = {
        {crypto::kex_id::curve25519, "curve25519-sha256", crypto::hash_id::sha256},
        {crypto::kex_id::ecdh_nistp256, "ecdh-sha2-nistp256", crypto::hash_id::sha256},
        {crypto::kex_id::ecdh_nistp521, "ecdh-sha2-nistp521", crypto::hash_id::sha512},
        {crypto::kex_id::dh_group14, "diffie-hellman-group14-sha256", crypto::hash_id::sha256},
        {crypto::kex_id::dh_group16, "diffie-hellman-group16-sha512", crypto::hash_id::sha512},
        {crypto::kex_id::ecdh_sm2, "ecgm-sm2-sm3", crypto::hash_id::sm3},
        {crypto::kex_id::sm2_kap, "sm2-sm3", crypto::hash_id::sm3},
    };

    for (const auto& c : cases) {
        INFO(c.name);
        if (c.id == crypto::kex_id::ecdh_sm2 && !p.supports(c.id)) continue;
        const auto n = make_negotiated(c.id, c.name, c.hash);
        const auto rt = run_round_trip(p, n, hs, fx);
        REQUIRE(rt.client_hash == rt.server_hash);
        REQUIRE(rt.client_secret == rt.server_secret);
        REQUIRE_FALSE(rt.client_hash.empty());
        REQUIRE_FALSE(rt.client_secret.empty());
    }
}

TEST_CASE("tampered I_C makes client signature verification fail", "[kex][exchange]") {
    crypto::provider p = prov();
    auto hs = make_ed25519_signer(p);
    exchange_fixture fx;
    const auto n =
        make_negotiated(crypto::kex_id::curve25519, "curve25519-sha256", crypto::hash_id::sha256);

    core::detail::key_exchange client{p, n, core::role::client};
    core::detail::key_exchange server{p, n, core::role::server};

    wire::writer init_w;
    REQUIRE_FALSE(client.start(init_w));

    wire::writer reply_w;
    std::span<const std::byte> server_hash;
    REQUIRE_FALSE(
        server.accept_init(fx.ctx(), init_w.data(), hs.blob, hs.key, reply_w, server_hash));

    auto tampered_fx = fx;
    tampered_fx.i_c[1] ^= std::byte{0x01};

    core::detail::host_key_view host_key;
    std::span<const std::byte> client_hash;
    const auto ec = client.accept_reply(tampered_fx.ctx(), reply_w.data(), host_key, client_hash);
    REQUIRE(ec == code::signature_verification_failed);
}

TEST_CASE("tampered server signature fails verification", "[kex][exchange]") {
    crypto::provider p = prov();
    auto hs = make_ed25519_signer(p);
    exchange_fixture fx;
    const auto n =
        make_negotiated(crypto::kex_id::curve25519, "curve25519-sha256", crypto::hash_id::sha256);

    core::detail::key_exchange client{p, n, core::role::client};
    core::detail::key_exchange server{p, n, core::role::server};

    wire::writer init_w;
    REQUIRE_FALSE(client.start(init_w));

    wire::writer reply_w;
    std::span<const std::byte> server_hash;
    REQUIRE_FALSE(
        server.accept_init(fx.ctx(), init_w.data(), hs.blob, hs.key, reply_w, server_hash));

    auto tampered = std::vector<std::byte>(reply_w.data().begin(), reply_w.data().end());
    tampered.back() ^= std::byte{0x01};

    core::detail::host_key_view host_key;
    std::span<const std::byte> client_hash;
    const auto ec = client.accept_reply(fx.ctx(), tampered, host_key, client_hash);
    REQUIRE(ec == code::signature_verification_failed);
}

TEST_CASE("wrong Q_S length yields invalid_kex_reply", "[kex][exchange]") {
    crypto::provider p = prov();
    auto hs = make_ed25519_signer(p);
    exchange_fixture fx;
    const auto n =
        make_negotiated(crypto::kex_id::curve25519, "curve25519-sha256", crypto::hash_id::sha256);

    core::detail::key_exchange client{p, n, core::role::client};
    wire::writer init_w;
    REQUIRE_FALSE(client.start(init_w));

    // Craft an ECDH reply with a truncated Q_S.
    const std::array<std::byte, 16> bad_qs{};
    const std::array<std::byte, 4> bogus_sig{std::byte{0}, std::byte{0}, std::byte{0},
                                             std::byte{0}};
    wire::writer reply_w;
    wire::detail::kex_ecdh_reply reply;
    reply.host_key = hs.blob;
    reply.server_public = bad_qs;
    reply.signature = bogus_sig;
    reply.encode(reply_w);

    core::detail::host_key_view host_key;
    std::span<const std::byte> client_hash;
    const auto ec = client.accept_reply(fx.ctx(), reply_w.data(), host_key, client_hash);
    REQUIRE(ec == code::invalid_kex_reply);
}

TEST_CASE("non-curve25519 agree failure is invalid_kex_reply", "[kex][exchange]") {
    crypto::provider p = prov();
    auto hs = make_ed25519_signer(p);
    exchange_fixture fx;
    const auto n = make_negotiated(crypto::kex_id::dh_group14, "diffie-hellman-group14-sha256",
                                   crypto::hash_id::sha256);

    fail_agree_overlay ov{p};
    crypto::provider client_p = crypto::provider::decorate(ov);
    core::detail::key_exchange client{client_p, n, core::role::client};
    core::detail::key_exchange server{p, n, core::role::server};

    wire::writer init_w;
    REQUIRE_FALSE(client.start(init_w));

    wire::writer reply_w;
    std::span<const std::byte> server_hash;
    REQUIRE_FALSE(
        server.accept_init(fx.ctx(), init_w.data(), hs.blob, hs.key, reply_w, server_hash));

    core::detail::host_key_view host_key;
    std::span<const std::byte> client_hash;
    const auto ec = client.accept_reply(fx.ctx(), reply_w.data(), host_key, client_hash);
    REQUIRE(ec == code::invalid_kex_reply);
}

TEST_CASE("curve25519 agree failure with a legal peer key is weak_shared_secret",
          "[kex][exchange]") {
    crypto::provider p = prov();
    auto hs = make_ed25519_signer(p);
    exchange_fixture fx;
    const auto n =
        make_negotiated(crypto::kex_id::curve25519, "curve25519-sha256", crypto::hash_id::sha256);

    fail_agree_overlay ov{p};
    crypto::provider client_p = crypto::provider::decorate(ov);
    core::detail::key_exchange client{client_p, n, core::role::client};
    core::detail::key_exchange server{p, n, core::role::server};

    wire::writer init_w;
    REQUIRE_FALSE(client.start(init_w));

    wire::writer reply_w;
    std::span<const std::byte> server_hash;
    REQUIRE_FALSE(
        server.accept_init(fx.ctx(), init_w.data(), hs.blob, hs.key, reply_w, server_hash));

    core::detail::host_key_view host_key;
    std::span<const std::byte> client_hash;
    const auto ec = client.accept_reply(fx.ctx(), reply_w.data(), host_key, client_hash);
    REQUIRE(ec == code::weak_shared_secret);
}

TEST_CASE("shared secret with high bit set is mpinted with 0x00 in H", "[kex][exchange]") {
    crypto::provider p = prov();
    auto hs = make_ed25519_signer(p);
    exchange_fixture fx;
    const auto n = make_negotiated(crypto::kex_id::dh_group14, "diffie-hellman-group14-sha256",
                                   crypto::hash_id::sha256);

    bool hit = false;
    for (int attempt = 0; attempt < 64; ++attempt) {
        core::detail::key_exchange client{p, n, core::role::client};
        core::detail::key_exchange server{p, n, core::role::server};

        wire::writer init_w;
        REQUIRE_FALSE(client.start(init_w));

        wire::writer reply_w;
        std::span<const std::byte> server_hash;
        REQUIRE_FALSE(
            server.accept_init(fx.ctx(), init_w.data(), hs.blob, hs.key, reply_w, server_hash));

        core::detail::host_key_view host_key;
        std::span<const std::byte> client_hash;
        REQUIRE_FALSE(client.accept_reply(fx.ctx(), reply_w.data(), host_key, client_hash));

        const auto secret = client.shared_secret();
        REQUIRE_FALSE(secret.empty());
        if ((std::to_integer<std::uint8_t>(secret[0]) & 0x80u) == 0) continue;

        // Confirm write_mpint would insert a leading 0x00.
        wire::writer mp;
        mp.write_mpint(secret);
        REQUIRE(mp.data().size() >= 5);
        REQUIRE(mp.data()[4] == std::byte{0x00});

        // Recover Q_C / Q_S from the wire messages for a manual H rebuild.
        wire::reader init_r{init_w.data()};
        wire::detail::kexdh_init init_msg;
        REQUIRE(init_msg.decode(init_r));
        wire::reader reply_r{reply_w.data()};
        wire::detail::kexdh_reply reply_msg;
        REQUIRE(reply_msg.decode(reply_r));

        const auto expected = manual_exchange_hash(p, n, fx, reply_msg.host_key, init_msg.e,
                                                   reply_msg.f, secret);
        REQUIRE(std::vector<std::byte>(client_hash.begin(), client_hash.end()) == expected);
        hit = true;
        break;
    }
    REQUIRE(hit);
}

TEST_CASE("shared_secret returns canonical magnitude without leading zeros", "[kex][exchange]") {
    crypto::provider p = prov();
    auto hs = make_ed25519_signer(p);
    exchange_fixture fx;
    const auto n = make_negotiated(crypto::kex_id::dh_group14, "diffie-hellman-group14-sha256",
                                   crypto::hash_id::sha256);

    const auto rt = run_round_trip(p, n, hs, fx);
    REQUIRE_FALSE(rt.client_secret.empty());
    // Canonical magnitude never starts with 0x00 (unless the value is zero, which DH rejects).
    REQUIRE(rt.client_secret[0] != std::byte{0x00});
    // And it is not forced to the full modulus width.
    REQUIRE(rt.client_secret.size() <= crypto::kex_secret_size(crypto::kex_id::dh_group14));
}
