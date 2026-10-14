#include "client.h"

#include "net.h"
#include "report.h"
#include "spawn.h"
#include "tty.h"

#include <yanterm-ssh/channel.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/detail/error.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/crypto/secure_buffer.hpp>
#include <yanterm-ssh/keys/io.hpp>
#include <yanterm-ssh/keys/private_key.hpp>
#include <yanterm-ssh/options.hpp>
#include <yanterm-ssh/session.hpp>

#include <auv/error.hpp>
#include <auv/stream.hpp>
#include <auv/uv.hpp>
#include <auv/uv/timer.hpp>
#include <corral/corral.h>
#include <uv.h>

#include <chrono>
#include <cstddef>
#include <iostream>
#include <map>
#include <memory>
#include <numeric>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

namespace ssh = yanterm::ssh;
namespace crypto = yanterm::ssh::crypto;
namespace keys = yanterm::ssh::keys;

namespace bench {
namespace {

void apply_options(ssh::session_options& o, const client_config& cfg) {
    if (!cfg.algo.kex.empty()) o.preferred_kex = cfg.algo.kex;
    if (!cfg.algo.cipher.empty()) o.preferred_cipher = cfg.algo.cipher;
    if (!cfg.algo.mac.empty()) o.preferred_mac = cfg.algo.mac;
    if (!cfg.algo.hostkey.empty()) o.preferred_host_key = cfg.algo.hostkey;
    o.initial_window = cfg.tuning.initial_window;
    o.max_channel_packet = cfg.tuning.max_packet;
    o.rekey_bytes = cfg.tuning.rekey_bytes;
}

struct chain_outcome {
    std::error_code ec;
    std::vector<double> hop_ms;
    negotiated_names names;
    throughput_stats stats;
};

corral::Task<std::error_code> authenticate_client(ssh::client_session& cs, std::string_view user,
                                                  std::string_view password,
                                                  const keys::private_key* identity) {
    auto hs = co_await cs.handshake([](ssh::host_key_view k) -> corral::Task<bool> {
        (void)k.fingerprint();
        co_return true;
    });
    if (hs) co_return hs;

    std::error_code aec;
    ssh::auth_result auth{};
    if (identity) {
        std::tie(aec, auth) = co_await cs.auth_publickey(user, *identity);
    } else {
        std::tie(aec, auth) = co_await cs.auth_password(user, password);
    }
    if (aec) co_return aec;
    if (!auth.success) co_return std::make_error_code(std::errc::permission_denied);
    co_return {};
}

struct hop_endpoint {
    std::string user;
    std::string host;
    std::string password;
    std::string identity_path;
    int port = 22;
    std::string label;
};

std::vector<hop_endpoint> make_chain(const client_config& cfg) {
    std::vector<hop_endpoint> chain;
    chain.reserve(cfg.jumps.size() + 1);
    for (std::size_t i = 0; i < cfg.jumps.size(); ++i) {
        const auto& j = cfg.jumps[i];
        hop_endpoint h;
        h.host = j.host;
        h.port = j.port;
        h.user = j.user.empty() ? cfg.user : j.user;
        const bool hop_cred = !j.identity.empty() || !j.password.empty();
        h.identity_path = hop_cred ? j.identity : cfg.identity_path;
        h.password = hop_cred ? j.password : cfg.password;
        h.label = "hop" + std::to_string(i + 1) + " " + j.host + ":" + std::to_string(j.port);
        chain.push_back(std::move(h));
    }
    hop_endpoint target;
    target.user = cfg.user;
    target.host = cfg.host;
    target.port = cfg.port;
    target.password = cfg.password;
    target.identity_path = cfg.identity_path;
    target.label = "target " + cfg.host + ":" + std::to_string(cfg.port);
    chain.push_back(std::move(target));
    return chain;
}

using identity_cache = std::map<std::string, keys::private_key>;

std::error_code load_private_key_interactive(const char* path, crypto::provider p,
                                             keys::private_key& out) {
    if (auto ec = keys::io::check_private_key_permissions(path)) return ec;
    std::vector<std::byte> bytes;
    if (auto ec = keys::io::read_file(path, bytes)) return ec;
    if (auto ec = keys::private_key::parse(bytes, p, {}, out); !ec) return {};
    else if (ec != ssh::errc::passphrase_required) return ec;

    constexpr int k_tries = 3;
    for (int i = 0; i < k_tries; ++i) {
        const std::string prompt = "Enter passphrase for " + std::string{path} + ": ";
        std::error_code pec;
        {
            crypto::secure_bytes pass;
            if (auto rec = read_controlling_tty_passphrase(prompt, pass)) return rec;
            pec = keys::private_key::parse(bytes, p, pass.span(), out);
        }
        if (!pec) return {};
        if (pec != ssh::errc::incorrect_passphrase) return pec;
        if (i + 1 < k_tries) std::cerr << "incorrect passphrase\n";
    }
    return ssh::make_error_code(ssh::code::incorrect_passphrase);
}

std::error_code load_identity_cache(crypto::provider p, const client_config& cfg,
                                    identity_cache& cache) {
    for (const auto& hop : make_chain(cfg)) {
        if (hop.identity_path.empty() || cache.contains(hop.identity_path)) continue;
        keys::private_key key;
        if (auto ec = load_private_key_interactive(hop.identity_path.c_str(), p, key)) {
            std::cerr << "load identity " << hop.identity_path << ": " << ec.message() << '\n';
            return ec;
        }
        cache.emplace(hop.identity_path, std::move(key));
    }
    return {};
}

std::string exec_command_for(const client_config& cfg, direction dir) {
    if (dir == direction::upload) {
        return cfg.exec_upload.empty() ? default_exec_command(direction::upload) : cfg.exec_upload;
    }
    return cfg.exec_download.empty() ? default_exec_command(direction::download)
                                     : cfg.exec_download;
}

corral::Task<std::error_code> transfer_throughput(ssh::client_session& cs, const client_config& cfg,
                                                  direction dir, throughput_stats& stats) {
    auto opened = co_await cs.open_session_channel();
    if (opened.ec) co_return opened.ec;

    const std::string cmd = exec_command_for(cfg, dir);
    if (auto eec = co_await opened.ch.request_exec(cmd)) co_return eec;

    const bool by_bytes = cfg.bytes > 0;
    const uint64_t warmup_ns = static_cast<uint64_t>(cfg.warmup_seconds * 1.0e9);
    const uint64_t window_ns = static_cast<uint64_t>(cfg.seconds * 1.0e9);
    std::vector<char> buf(cfg.tuning.max_packet > 0 ? cfg.tuning.max_packet : 32768, 0);
    auto chs = auv::stream::borrow(opened.ch);
    const bool yield_pumps = !cfg.jumps.empty();
    const uint64_t t_start = uv_hrtime();
    uint64_t t_count_start = 0;
    std::uint64_t counted = 0;

    auto counting = [&](uint64_t now) -> bool {
        if (now - t_start < warmup_ns) return false;
        if (t_count_start == 0) t_count_start = now;
        return true;
    };
    auto window_done = [&](uint64_t now) -> bool {
        if (by_bytes) return counted >= cfg.bytes;
        return t_count_start != 0 && now - t_count_start >= window_ns;
    };

    if (dir == direction::download) {
        for (;;) {
            auto [rec, n] = co_await chs.read([&] { return auv::buffer(buf.data(), buf.size()); });
            if (n == 0 && !rec) continue;
            if (n == 0 || rec) {
                if (counted > 0 && !by_bytes) break;
                co_return rec ? rec : std::make_error_code(std::errc::broken_pipe);
            }
            const uint64_t now = uv_hrtime();
            if (yield_pumps) co_await corral::yield;
            if (!counting(now)) continue;
            if (by_bytes) {
                const auto room = cfg.bytes - counted;
                counted += n < room ? n : room;
            } else {
                counted += n;
            }
            if (window_done(uv_hrtime())) break;
        }
    } else {
        for (;;) {
            const uint64_t now = uv_hrtime();
            const bool in_count = counting(now);
            std::size_t chunk = buf.size();
            if (in_count && by_bytes) {
                const auto room = cfg.bytes - counted;
                if (room == 0) break;
                if (chunk > room) chunk = static_cast<std::size_t>(room);
            }
            auv::buffer wb{buf.data(), chunk};
            auto wec = co_await chs.write(&wb, std::size_t{1});
            if (wec) {
                if (counted > 0 && !by_bytes) break;
                co_return wec;
            }
            if (yield_pumps) co_await corral::yield;
            if (in_count) counted += chunk;
            if (window_done(uv_hrtime())) break;
        }
    }

    stats.payload_bytes = counted;
    const uint64_t t_end = uv_hrtime();
    const uint64_t origin = t_count_start ? t_count_start : t_end;
    stats.seconds = static_cast<double>(t_end - origin) / 1.0e9;

    (void)co_await opened.ch.shutdown();
    co_await opened.ch.close();
    co_return {};
}

corral::Task<chain_outcome> one_chain(uv_loop_t& loop, crypto::provider p, const client_config& cfg,
                                      const identity_cache& ids, std::optional<direction> tp_dir) {
    chain_outcome out;
    auto hops = make_chain(cfg);
    out.hop_ms.assign(hops.size(), 0);

    std::vector<const keys::private_key*> idptrs(hops.size(), nullptr);
    for (std::size_t i = 0; i < hops.size(); ++i) {
        if (hops[i].identity_path.empty()) continue;
        const auto it = ids.find(hops[i].identity_path);
        if (it == ids.end()) {
            out.ec = std::make_error_code(std::errc::no_such_file_or_directory);
            co_return out;
        }
        idptrs[i] = &it->second;
    }

    auto [ec, first] = co_await tcp_connect(loop, hops.front().host, hops.front().port);
    if (ec) {
        out.ec = ec;
        co_return out;
    }
    auv::stream transport = std::move(first);

    std::vector<std::unique_ptr<ssh::client_session>> sessions;
    sessions.reserve(hops.size());

    CORRAL_WITH_NURSERY(n) {
        CORRAL_TRY {
            for (std::size_t i = 0; i < hops.size(); ++i) {
                ssh::client_options co;
                apply_options(co, cfg);
                sessions.push_back(std::make_unique<ssh::client_session>(
                    std::move(transport), p, std::move(co)));
                auto* cs = sessions.back().get();
                co_await n.start(&ssh::client_session::run, cs);

                const uint64_t t0 = uv_hrtime();
                if (auto aec = co_await authenticate_client(*cs, hops[i].user, hops[i].password,
                                                            idptrs[i])) {
                    out.ec = aec;
                    break;
                }
                out.hop_ms[i] = static_cast<double>(uv_hrtime() - t0) / 1.0e6;
                if (const auto* neg = cs->negotiated()) out.names = describe(*neg);

                if (i + 1 < hops.size()) {
                    const auto& next = hops[i + 1];
                    auto opened = co_await cs->open_direct_tcpip(
                        next.host, static_cast<std::uint32_t>(next.port), "127.0.0.1", 0);
                    if (opened.ec) {
                        out.ec = opened.ec;
                        break;
                    }
                    transport = auv::stream::own(std::move(opened.ch));
                }
            }

            if (!out.ec && tp_dir) {
                out.ec = co_await transfer_throughput(*sessions.back(), cfg, *tp_dir, out.stats);
            }
        }
        CORRAL_FINALLY {
            for (auto it = sessions.rbegin(); it != sessions.rend(); ++it) {
                co_await (*it)->disconnect(ssh::disconnect_reason::by_application, {});
            }
        };
        co_return corral::cancel;
    };

    co_return out;
}

struct handshake_run {
    int rc = 0;
    handshake_stats stats;
    negotiated_names names;
    std::vector<hop_handshake> hops;
};

corral::Task<handshake_run> run_handshake(uv_loop_t& loop, crypto::provider p,
                                          const client_config& cfg, const identity_cache& ids) {
    handshake_run out;
    std::vector<double> samples;
    samples.reserve(static_cast<std::size_t>(cfg.repeat));
    const bool report_hops = !cfg.jumps.empty();
    std::vector<std::vector<double>> hop_samples;
    if (report_hops) hop_samples.resize(cfg.jumps.size() + 1);

    for (int i = 0; i < cfg.repeat; ++i) {
        std::optional<chain_outcome> result;
        if (cfg.timeout_seconds > 0) {
            auv::Timer watchdog(&loop, std::chrono::duration<double>(cfg.timeout_seconds));
            auto outcome = co_await corral::anyOf(one_chain(loop, p, cfg, ids, std::nullopt), watchdog);
            if (!std::get<0>(outcome)) {
                std::cerr << "handshake timed out after " << cfg.timeout_seconds << " s\n";
                out.rc = 1;
                co_return out;
            }
            result = std::move(*std::get<0>(outcome));
        } else {
            result = co_await one_chain(loop, p, cfg, ids, std::nullopt);
        }
        if (result->ec) {
            std::cerr << "handshake failed: " << result->ec.message() << '\n';
            out.rc = 1;
            co_return out;
        }
        samples.push_back(std::accumulate(result->hop_ms.begin(), result->hop_ms.end(), 0.0));
        if (report_hops) {
            for (std::size_t h = 0; h < result->hop_ms.size() && h < hop_samples.size(); ++h) {
                hop_samples[h].push_back(result->hop_ms[h]);
            }
        }
        out.names = std::move(result->names);
    }

    out.stats = summarize_handshake(std::move(samples));
    if (report_hops) {
        const auto hops = make_chain(cfg);
        out.hops.reserve(hop_samples.size());
        for (std::size_t i = 0; i < hop_samples.size(); ++i) {
            hop_handshake hh;
            hh.label = hops[i].label;
            hh.stats = summarize_handshake(std::move(hop_samples[i]));
            out.hops.push_back(std::move(hh));
        }
    }
    co_return out;
}

struct throughput_run {
    int rc = 0;
    throughput_stats stats;
    negotiated_names names;
};

const char* peer_label(peer_kind k) {
    switch (k) {
    case peer_kind::spawn_server: return "yanterm";
    case peer_kind::spawn_sshd: return "openssh";
    case peer_kind::external: return "external";
    }
    return "external";
}

corral::Task<throughput_run> run_throughput(uv_loop_t& loop, crypto::provider p,
                                            const client_config& cfg, const identity_cache& ids,
                                            direction dir) {
    throughput_run out;
    const char* label = dir == direction::upload ? "upload" : "download";
    std::optional<chain_outcome> result;
    if (cfg.timeout_seconds > 0) {
        auv::Timer watchdog(&loop, std::chrono::duration<double>(cfg.timeout_seconds));
        auto outcome = co_await corral::anyOf(one_chain(loop, p, cfg, ids, dir), watchdog);
        if (!std::get<0>(outcome)) {
            std::cerr << label << " timed out after " << cfg.timeout_seconds << " s\n";
            out.rc = 1;
            co_return out;
        }
        result = std::move(*std::get<0>(outcome));
    } else {
        result = co_await one_chain(loop, p, cfg, ids, dir);
    }
    if (result->ec) {
        std::cerr << label << " failed: " << result->ec.message() << '\n';
        out.rc = 1;
        co_return out;
    }
    out.stats = result->stats;
    out.names = std::move(result->names);
    co_return out;
}

void emit_record(const client_config& cfg, const run_record& rec) {
    if (cfg.json) print_json(rec);
    else print_table(rec);
}

corral::Task<int> run_workloads(uv_loop_t& loop, crypto::provider p, const client_config& cfg) {
    identity_cache ids;
    if (auto ec = load_identity_cache(p, cfg, ids)) co_return 1;

    run_record rec;
    rec.role = "client";
    rec.peer = peer_label(cfg.peer);
    rec.tuning = cfg.tuning;

    const bool do_hs = cfg.work == workload::handshake || cfg.work == workload::all;
    const bool do_dl = cfg.work == workload::download || cfg.work == workload::all;
    const bool do_ul = cfg.work == workload::upload || cfg.work == workload::all;

    if (do_hs) {
        const auto hs = co_await run_handshake(loop, p, cfg, ids);
        if (hs.rc != 0) co_return hs.rc;
        rec.handshake = hs.stats;
        rec.hops = hs.hops;
        rec.algos = hs.names;
    }
    if (do_dl) {
        const auto tp = co_await run_throughput(loop, p, cfg, ids, direction::download);
        if (tp.rc != 0) co_return tp.rc;
        rec.throughput_download = tp.stats;
        rec.algos = tp.names;
    }
    if (do_ul) {
        const auto tp = co_await run_throughput(loop, p, cfg, ids, direction::upload);
        if (tp.rc != 0) co_return tp.rc;
        rec.throughput_upload = tp.stats;
        rec.algos = tp.names;
    }
    emit_record(cfg, rec);
    co_return 0;
}

}  // namespace

int run_client(const client_config& cfg) {
    auto current_username = []() -> std::string {
        uv_passwd_t pwd{};
        if (uv_os_get_passwd(&pwd) == 0) {
            std::string name = pwd.username ? pwd.username : "";
            uv_os_free_passwd(&pwd);
            if (!name.empty()) return name;
        }
        char buf[256];
        std::size_t sz = sizeof(buf);
        if (uv_os_getenv("USER", buf, &sz) == 0 && buf[0] != '\0') return std::string(buf, sz);
#ifdef _WIN32
        sz = sizeof(buf);
        if (uv_os_getenv("USERNAME", buf, &sz) == 0 && buf[0] != '\0') return std::string(buf, sz);
#endif
        return {};
    };

    client_config local = cfg;
    if (local.peer == peer_kind::spawn_server) {
        if (local.user.empty()) local.user = "bench";
        if (local.password.empty()) local.password = "bench";
    } else if (local.peer == peer_kind::spawn_sshd) {
        if (local.user.empty()) local.user = current_username();
        if (local.user.empty()) {
            std::cerr << "could not determine current username (pass --user)\n";
            return 1;
        }
        local.password.clear();
    } else if (local.peer == peer_kind::external) {
        if (local.user.empty()) local.user = current_username();
        if (local.user.empty()) {
            std::cerr << "could not determine current username (pass --user)\n";
            return 1;
        }
        if (local.password.empty() && local.identity_path.empty()) {
            std::cerr << "connect requires --password or --identity\n";
            return 1;
        }
    }

    crypto::openssl_backend backend;
    auto p = crypto::provider::wrap(backend);

    uv_loop_t loop{};
    if (uv_loop_init(&loop) < 0) {
        std::cerr << "uv_loop_init failed\n";
        return 1;
    }
    const int rc = corral::run(loop, [&]() -> corral::Task<int> {
        spawned_peer server_peer;
        sshd_peer sshd;
        if (local.peer == peer_kind::spawn_server) {
            auto [ec, spawned] = co_await spawn_bench_server(loop, local);
            if (ec) {
                std::cerr << "spawn-server failed: " << ec.message() << '\n';
                co_return 1;
            }
            server_peer = std::move(spawned);
            local.host = server_peer.host;
            local.port = server_peer.port;
        } else if (local.peer == peer_kind::spawn_sshd) {
            auto [ec, spawned] = co_await spawn_openssh_sshd(loop, local);
            if (ec) {
                std::cerr << "spawn-sshd failed: " << ec.message() << '\n';
                co_return 1;
            }
            sshd = std::move(spawned);
            local.host = sshd.peer.host;
            local.port = sshd.peer.port;
            local.identity_path = sshd.identity_path;
            local.password.clear();
        }
        co_return co_await run_workloads(loop, p, local);
    }());
    drain_and_close(loop);
    return rc;
}

}  // namespace bench
