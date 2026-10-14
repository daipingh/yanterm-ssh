#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/core/config.hpp>
#include <yanterm-ssh/core/connection.hpp>
#include <yanterm-ssh/core/detail/host_key.hpp>
#include <yanterm-ssh/core/types.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>

#include "fixed_random_provider.hpp"
#include "hex_util.hpp"
#include "drive.hpp"
#include "handshake_fixture.hpp"
#include "loopback.hpp"
#include "replay.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#ifndef YANTERM_SSH_FIXTURE_DIR
#error "YANTERM_SSH_FIXTURE_DIR must be defined"
#endif

#ifndef YANTERM_SSH_CORPUS_DIR
#error "YANTERM_SSH_CORPUS_DIR must be defined"
#endif

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

namespace {

crypto::provider raw_prov() {
    static crypto::openssl_backend backend;
    return crypto::provider::wrap(backend);
}

std::vector<std::byte> load_bin(std::string_view name) {
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

struct host_material {
    std::vector<std::byte> blob;
    std::vector<std::byte> seed;
    std::vector<std::byte> pub;
    crypto::private_key_material priv{};
};

host_material make_ed25519_host() {
    host_material hm;
    hm.blob = load_bin("ed25519.blob");
    hm.seed = load_bin("ed25519.seed");
    core::detail::host_key_view view;
    REQUIRE_FALSE(core::detail::parse_host_key(hm.blob, view));
    hm.pub.assign(view.material.a.begin(), view.material.a.end());
    hm.priv = {crypto::sig_id::ed25519, hm.seed, hm.pub};
    return hm;
}

struct stream_capture {
    std::vector<std::byte> client_out;
    std::vector<std::byte> server_out;
};

// Drive loopback while recording every byte each side emits (in transfer order).
bool run_loopback_capture(wired_connection& client, wired_connection& server,
                          stream_capture& cap, trace_writer* client_trace = nullptr) {
    auto drain_recorded = [&](wired_connection& peer, bool is_client) {
        for (const auto& ev : peer.handler.events) {
            if (is_client && client_trace) {
                using replay_detail::sha256_fingerprint;
                if (const auto* banner =
                        std::get_if<recording_handler::peer_identification>(&ev)) {
                    client_trace->event_line("peer_identification", banner->banner);
                } else if (const auto* host =
                                 std::get_if<recording_handler::verify_host_key>(&ev)) {
                    const auto fp = sha256_fingerprint(raw_prov(), host->blob);
                    client_trace->event_line("verify_host_key", fp);
                    client.conn.resolve(host->ticket, core::host_key_verdict::accept);
                    client_trace->resolve_line("accept");
                } else if (std::holds_alternative<recording_handler::handshake_done>(
                               ev)) {
                    client_trace->event_line("handshake_done");
                }
            } else if (is_client) {
                if (const auto* host =
                        std::get_if<recording_handler::verify_host_key>(&ev)) {
                    client.conn.resolve(host->ticket, core::host_key_verdict::accept);
                }
            }
        }
        peer.handler.events.clear();
    };

    drain_recorded(client, true);
    drain_recorded(server, false);

    for (int round = 0; round < 64; ++round) {
        bool progress = false;
        auto transfer = [&](wired_connection& from, wired_connection& to,
                            bool to_is_client, std::vector<std::byte>& sink, bool from_is_client) {
            const auto out = from.conn.pending_output0();
            if (out.empty()) return;
            std::error_code ec;
            std::size_t n = 0;
            ec = to.conn.feed(out, n);
            (void)ec;
            if (n == 0) return;
            const auto accepted = out.first(n);
            sink.insert(sink.end(), accepted.begin(), accepted.end());
            if (client_trace && from_is_client) client_trace->out_bytes(accepted);
            if (client_trace && !from_is_client) client_trace->in_bytes(accepted);
            from.conn.consume_output(n);
            progress = true;
            drain_recorded(to, to_is_client);
        };

        transfer(client, server, false, cap.client_out, true);
        transfer(server, client, true, cap.server_out, false);

        if (!progress) {
            return !client.conn.failure() && !server.conn.failure();
        }
    }
    return false;
}

std::vector<std::byte> random_seq(crypto::provider p, std::size_t n, int rounds) {
    std::vector<std::byte> all;
    std::vector<std::byte> chunk(n);
    for (int i = 0; i < rounds; ++i) {
        REQUIRE_FALSE(static_cast<bool>(p.random_bytes(chunk)));
        all.insert(all.end(), chunk.begin(), chunk.end());
    }
    return all;
}

}  // namespace

TEST_CASE("fixed_random_provider same seed same stream; different seed differs",
          "[replay][fixed_random]") {
    constexpr std::uint64_t seed_a = 0x1234567890abcdefull;
    constexpr std::uint64_t seed_b = 0xfedcba0987654321ull;

    fixed_random_provider fa1{raw_prov(), seed_a};
    fixed_random_provider fa2{raw_prov(), seed_a};
    fixed_random_provider fb{raw_prov(), seed_b};

    const auto a1 = random_seq(fa1.get(), 64, 5);
    const auto a2 = random_seq(fa2.get(), 64, 5);
    const auto b = random_seq(fb.get(), 64, 5);
    REQUIRE(a1 == a2);
    REQUIRE(a1 != b);
}

TEST_CASE("fixed_random_provider loopback is byte-identical across runs",
          "[replay][fixed_random][loopback]") {
    constexpr std::uint64_t seed_c = 0x1111222233334444ull;
    constexpr std::uint64_t seed_s = 0x5555666677778888ull;
    auto hm = make_ed25519_host();

    auto once = [&] {
        fixed_random_provider fr_c{raw_prov(), seed_c};
        fixed_random_provider fr_s{raw_prov(), seed_s};
        wired_connection client{core::role::client, fr_c.get(), {}};
        wired_connection server{core::role::server, fr_s.get(), {}};
        REQUIRE_FALSE(server.conn.set_host_key(hm.blob, hm.priv));
        stream_capture cap;
        REQUIRE(run_loopback_capture(client, server, cap));
        return cap;
    };

    const auto a = once();
    const auto b = once();
    REQUIRE(a.client_out == b.client_out);
    REQUIRE(a.server_out == b.server_out);
    REQUIRE_FALSE(a.client_out.empty());
    REQUIRE_FALSE(a.server_out.empty());
}

TEST_CASE("loopback capture replays through replay_trace_body", "[replay]") {
    // Client and server must use independent PRNGs: a shared stream would
    // interleave server draws into the client's sequence and break client-only
    // replay (which is how OpenSSH corpus traces work).
    constexpr std::uint64_t seed = 0xabcddcba11223344ull;
    constexpr std::uint64_t seed_server = 0x0123456789abcdefull;
    auto hm = make_ed25519_host();

    trace_writer tw;
    replay_config rc;
    rc.seed = seed;
    rc.role = core::role::client;
    rc.kex = "curve25519-sha256";
    rc.cipher = "chacha20-poly1305@openssh.com";
    rc.hostkey = "ssh-ed25519";
    tw.header(rc);

    {
        fixed_random_provider fr_c{raw_prov(), seed};
        fixed_random_provider fr_s{raw_prov(), seed_server};
        std::vector<std::string_view> kex{rc.kex}, hostkey{rc.hostkey}, cipher{rc.cipher}, mac;
        core::config cfg = make_config_from_trace(rc, kex, hostkey, cipher, mac);
        wired_connection client{core::role::client, fr_c.get(), cfg};
        wired_connection server{core::role::server, fr_s.get(), cfg};
        REQUIRE_FALSE(server.conn.set_host_key(hm.blob, hm.priv));
        stream_capture cap;
        REQUIRE(run_loopback_capture(client, server, cap, &tw));
    }

    const std::string trace_text = tw.str();
    INFO(trace_text);

    fixed_random_provider fr{raw_prov(), seed};
    crypto::provider p = fr.get();
    std::vector<std::string_view> kex{rc.kex}, hostkey{rc.hostkey}, cipher{rc.cipher}, mac;
    core::config cfg = make_config_from_trace(rc, kex, hostkey, cipher, mac);
    recording_handler handler;
    core::connection client{core::role::client, p, cfg, handler};

    std::istringstream full{trace_text};
    std::string line;
    std::ostringstream body;
    int skipped = 0;
    while (std::getline(full, line)) {
        auto t = replay_detail::trim(line);
        if (skipped < 3
            && (t.rfind("seed ", 0) == 0 || t.rfind("role ", 0) == 0 || t == "config"
                || t.rfind("config ", 0) == 0)) {
            ++skipped;
            continue;
        }
        body << line << '\n';
    }
    const auto mismatch = replay_trace_body(p, client, handler, body.str());
    if (mismatch) {
        FAIL(mismatch->message << " line=" << mismatch->line << " off=" << mismatch->offset);
    }
}

TEST_CASE("replay reports byte offset on corrupted output line", "[replay]") {
    constexpr std::uint64_t seed = 0x5555666677778888ull;
    constexpr std::uint64_t seed_server = 0x9999aaaabbbbccccull;
    auto hm = make_ed25519_host();

    trace_writer tw;
    replay_config rc;
    rc.seed = seed;
    rc.role = core::role::client;
    tw.header(rc);
    {
        fixed_random_provider fr_c{raw_prov(), seed};
        fixed_random_provider fr_s{raw_prov(), seed_server};
        wired_connection client{core::role::client, fr_c.get(), {}};
        wired_connection server{core::role::server, fr_s.get(), {}};
        REQUIRE_FALSE(server.conn.set_host_key(hm.blob, hm.priv));
        stream_capture cap;
        REQUIRE(run_loopback_capture(client, server, cap, &tw));
    }

    std::string text = tw.str();
    // Flip one hex nibble in the first '>' line (the local banner is stable).
    const auto pos = text.find('>');
    REQUIRE(pos != std::string::npos);
    auto hex_pos = pos + 2;
    while (hex_pos < text.size() && text[hex_pos] == ' ') ++hex_pos;
    REQUIRE(hex_pos + 1 < text.size());
    text[hex_pos] = (text[hex_pos] == '0') ? '1' : '0';

    fixed_random_provider fr{raw_prov(), seed};
    crypto::provider p = fr.get();
    recording_handler handler;
    core::connection client{core::role::client, p, {}, handler};

    std::istringstream full{text};
    std::string line;
    std::ostringstream body;
    int skipped = 0;
    while (std::getline(full, line)) {
        auto t = replay_detail::trim(line);
        if (skipped < 3
            && (t.rfind("seed ", 0) == 0 || t.rfind("role ", 0) == 0 || t == "config"
                || t.rfind("config ", 0) == 0)) {
            ++skipped;
            continue;
        }
        body << line << '\n';
    }
    const auto mismatch = replay_trace_body(p, client, handler, body.str());
    REQUIRE(mismatch);
    INFO(mismatch->message);
    REQUIRE(mismatch->message.find("output byte mismatch") != std::string::npos);
    REQUIRE(mismatch->message.find("offset=") != std::string::npos);
}

TEST_CASE("corpus OpenSSH traces replay", "[replay][corpus]") {
    namespace fs = std::filesystem;
    const fs::path dir{YANTERM_SSH_CORPUS_DIR};
    if (!fs::exists(dir)) {
        WARN("corpus dir missing: " << dir.string());
        return;
    }
    int seen = 0;
    for (const auto& ent : fs::directory_iterator(dir)) {
        if (!ent.is_regular_file()) continue;
        if (ent.path().extension() != ".ssh-trace") continue;
        ++seen;
        INFO(ent.path().string());
        loaded_trace tr;
        std::string err;
        REQUIRE(load_trace_file(ent.path().string(), tr, err));
        fixed_random_provider fr{raw_prov(), tr.cfg.seed};
        crypto::provider p = fr.get();
        std::vector<std::string_view> kex, hostkey, cipher, mac;
        core::config cfg = make_config_from_trace(tr.cfg, kex, hostkey, cipher, mac);
        recording_handler handler;
        core::connection client{tr.cfg.role, p, cfg, handler};
        const auto mismatch = replay_trace_body(p, client, handler, tr.body);
        if (mismatch) {
            FAIL(ent.path().filename().string()
                 << ": " << mismatch->message << " line=" << mismatch->line
                 << " off=" << mismatch->offset);
        }
    }
    // Required OpenSSH captures for M1 acceptance.
    REQUIRE(fs::exists(dir / "openssh-8.9p1-curve25519-chacha20-ed25519.ssh-trace"));
    REQUIRE(
        fs::exists(dir / "openssh-8.9p1-ecdh-nistp256-aes256-gcm-rsa-sha2-256.ssh-trace"));
    if (seen == 0) {
        FAIL("no .ssh-trace files in corpus");
    }
}
