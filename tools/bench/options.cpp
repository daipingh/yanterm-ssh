#include "options.h"

#include <charconv>
#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace bench {
namespace {

bool eq(std::string_view a, const char* b) noexcept { return a == b; }

bool parse_i32(std::string_view s, int& out) {
    if (s.empty()) return false;
    int v = 0;
    const auto* first = s.data();
    const auto* last = s.data() + s.size();
    auto [ptr, ec] = std::from_chars(first, last, v);
    if (ec != std::errc{} || ptr != last) return false;
    out = v;
    return true;
}

bool parse_u32(std::string_view s, std::uint32_t& out) {
    if (s.empty()) return false;
    std::uint32_t v = 0;
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || ptr != s.data() + s.size()) return false;
    out = v;
    return true;
}

bool parse_u64(std::string_view s, std::uint64_t& out) {
    if (s.empty()) return false;
    std::uint64_t v = 0;
    auto [ptr, ec] = std::from_chars(s.data(), s.data() + s.size(), v);
    if (ec != std::errc{} || ptr != s.data() + s.size()) return false;
    out = v;
    return true;
}

bool parse_f64(std::string_view s, double& out) {
    if (s.empty()) return false;
    try {
        std::size_t idx = 0;
        const double v = std::stod(std::string{s}, &idx);
        if (idx != s.size()) return false;
        out = v;
        return true;
    } catch (...) {
        return false;
    }
}

bool parse_port(std::string_view s, int& out) {
    if (!parse_i32(s, out) || out < 0 || out > 65535) return false;
    return true;
}

std::optional<jump_hop> parse_endpoint(std::string_view spec, std::string_view what,
                                       std::string& error) {
    jump_hop hop;
    std::string rest{spec};
    const auto at = rest.find('@');
    if (at != std::string::npos) {
        hop.user = rest.substr(0, at);
        rest.erase(0, at + 1);
    }
    if (rest.starts_with('[')) {
        const auto rb = rest.find(']');
        if (rb == std::string::npos) {
            error = "invalid " + std::string{what} + " (missing ']')";
            return std::nullopt;
        }
        hop.host = rest.substr(1, rb - 1);
        rest.erase(0, rb + 1);
        if (rest.empty()) return hop;
        if (!rest.starts_with(':') || !parse_port(rest.substr(1), hop.port)) {
            error = "invalid " + std::string{what} + " port";
            return std::nullopt;
        }
        return hop;
    }
    const auto first_colon = rest.find(':');
    const auto last_colon = rest.rfind(':');
    if (first_colon != std::string::npos && first_colon == last_colon) {
        hop.host = rest.substr(0, first_colon);
        if (!parse_port(rest.substr(first_colon + 1), hop.port)) {
            error = "invalid " + std::string{what} + " port";
            return std::nullopt;
        }
    } else {
        hop.host = rest;
    }
    if (hop.host.empty()) {
        error = "invalid " + std::string{what} + " (empty host)";
        return std::nullopt;
    }
    return hop;
}

void append_usage(std::string& error) {
    if (!error.empty() && error.back() != '\n') error.push_back('\n');
    error += usage_text();
}

}  // namespace

std::string usage_text() {
    return
        "Usage: yanterm-ssh-bench <server|spawn-server|spawn-sshd|connect> [options]\n"
        "       yanterm-ssh-bench connect [user@]host[:port] [options]\n"
        "\n"
        "server options:\n"
        "  --bind ADDR                 listen address (default 127.0.0.1)\n"
        "  --port PORT                 listen port (default 0 = ephemeral)\n"
        "  --user NAME                 allowed username\n"
        "  --password PASS             password authentication secret\n"
        "  --authorized PATH           authorized_keys file for publickey auth\n"
        "  --host-key PATH             host private key (default: generate ed25519)\n"
        "  --kex NAME                  preferred KEX algorithm\n"
        "  --cipher NAME               preferred cipher\n"
        "  --mac NAME                  preferred MAC (CTR ciphers)\n"
        "  --hostkey NAME              preferred host-key algorithm\n"
        "  --initial-window BYTES      channel initial window (default 2097152)\n"
        "  --max-packet BYTES          max channel packet (default 32768)\n"
        "  --rekey-bytes BYTES         rekey after this many bytes (default 1GiB)\n"
        "\n"
        "common options (spawn-server, spawn-sshd, connect):\n"
        "  --user NAME                 authentication username\n"
        "  --workload handshake|download|upload|all  (default all)\n"
        "  --repeat N                  handshake samples (default 21)\n"
        "  --warmup SECONDS            throughput warmup (default 1)\n"
        "  --seconds SECONDS           throughput duration (default 5); exclusive with --bytes\n"
        "  --bytes N                   throughput payload; exclusive with --seconds\n"
        "  --exec-download CMD         remote command for download\n"
        "  --exec-upload CMD           remote command for upload\n"
        "  --timeout SECONDS           per-iteration watchdog (default 30)\n"
        "  --kex NAME                  preferred KEX algorithm\n"
        "  --cipher NAME               preferred cipher\n"
        "  --mac NAME                  preferred MAC (CTR ciphers)\n"
        "  --hostkey NAME              preferred host-key algorithm\n"
        "  --initial-window BYTES      channel initial window (default 2097152)\n"
        "  --max-packet BYTES          max channel packet (default 32768)\n"
        "  --rekey-bytes BYTES         rekey after this many bytes (default 1GiB)\n"
        "  --json                      JSON-only stdout (no human table)\n"
        "\n"
        "spawn-server options:\n"
        "  --password PASS             password for the spawned server (default bench)\n"
        "\n"
        "spawn-sshd options:\n"
        "  --sshd PATH                 sshd binary (default: PATH, then /usr/sbin/sshd)\n"
        "\n"
        "connect options:\n"
        "  --port PORT                 peer port; overrides host[:port] (default 22)\n"
        "  --password PASS             password authentication secret\n"
        "  --identity PATH             private key for publickey authentication\n"
        "  --jump [user@]host[:port]   jump hop; repeatable\n"
        "  --jump-identity PATH        identity for the next unmatched jump\n"
        "  --jump-password PASS        password for the next unmatched jump\n";
}

std::optional<parsed_command> parse_command(int argc, char** argv, std::string& error) {
    error.clear();
    parsed_command out{};
    if (argc < 2) {
        error = "missing subcommand (server, spawn-server, spawn-sshd, or connect)";
        append_usage(error);
        return std::nullopt;
    }

    const std::string_view cmd = argv[1];
    if (eq(cmd, "server")) {
        out.cmd = subcommand::server;
    } else if (eq(cmd, "spawn-server")) {
        out.cmd = subcommand::spawn_server;
        out.client.peer = peer_kind::spawn_server;
    } else if (eq(cmd, "spawn-sshd")) {
        out.cmd = subcommand::spawn_sshd;
        out.client.peer = peer_kind::spawn_sshd;
    } else if (eq(cmd, "connect")) {
        out.cmd = subcommand::connect;
        out.client.peer = peer_kind::external;
    } else if (eq(cmd, "--help") || eq(cmd, "-h")) {
        error.clear();
        return std::nullopt;
    } else {
        error = "unknown subcommand '" + std::string{cmd} + "'";
        append_usage(error);
        return std::nullopt;
    }

    auto fail = [&](std::string msg) -> std::optional<parsed_command> {
        error = std::move(msg);
        append_usage(error);
        return std::nullopt;
    };

    bool saw_user = false;
    bool saw_port = false;
    bool saw_seconds = false;
    bool saw_bytes = false;
    std::string dest;
    std::vector<std::string> jump_identities;
    std::vector<std::string> jump_passwords;
    algo_options* algo = (out.cmd == subcommand::server) ? &out.server.algo : &out.client.algo;
    tuning_options* tuning =
        (out.cmd == subcommand::server) ? &out.server.tuning : &out.client.tuning;

    auto need = [&](int& i, std::string& into) -> bool {
        if (i + 1 >= argc) return false;
        into = argv[++i];
        return true;
    };

    for (int i = 2; i < argc; ++i) {
        const std::string_view a = argv[i];
        if (eq(a, "--help") || eq(a, "-h")) {
            error.clear();
            return std::nullopt;
        }

        if (eq(a, "--kex")) {
            if (!need(i, algo->kex)) return fail("--kex requires an argument");
        } else if (eq(a, "--cipher")) {
            if (!need(i, algo->cipher)) return fail("--cipher requires an argument");
        } else if (eq(a, "--mac")) {
            if (!need(i, algo->mac)) return fail("--mac requires an argument");
        } else if (eq(a, "--hostkey")) {
            if (!need(i, algo->hostkey)) return fail("--hostkey requires an argument");
        } else if (eq(a, "--initial-window")) {
            std::string v;
            if (!need(i, v) || !parse_u32(v, tuning->initial_window)) {
                return fail("invalid --initial-window");
            }
        } else if (eq(a, "--max-packet")) {
            std::string v;
            if (!need(i, v) || !parse_u32(v, tuning->max_packet)) {
                return fail("invalid --max-packet");
            }
        } else if (eq(a, "--rekey-bytes")) {
            std::string v;
            if (!need(i, v) || !parse_u64(v, tuning->rekey_bytes)) {
                return fail("invalid --rekey-bytes");
            }
        } else if (out.cmd == subcommand::server) {
            if (eq(a, "--bind")) {
                if (!need(i, out.server.bind)) return fail("--bind requires an argument");
            } else if (eq(a, "--port")) {
                std::string v;
                if (!need(i, v) || !parse_port(v, out.server.port)) {
                    return fail("invalid --port");
                }
            } else if (eq(a, "--user")) {
                if (!need(i, out.server.user)) return fail("--user requires an argument");
            } else if (eq(a, "--password")) {
                if (!need(i, out.server.password)) return fail("--password requires an argument");
            } else if (eq(a, "--authorized")) {
                if (!need(i, out.server.authorized_path)) {
                    return fail("--authorized requires an argument");
                }
            } else if (eq(a, "--host-key")) {
                if (!need(i, out.server.host_key_path)) {
                    return fail("--host-key requires an argument");
                }
            } else {
                return fail("unknown server option '" + std::string{a} + "'");
            }
        } else {
            if (eq(a, "--user")) {
                if (!need(i, out.client.user)) return fail("--user requires an argument");
                saw_user = true;
            } else if (eq(a, "--password")) {
                if (out.cmd == subcommand::spawn_sshd) {
                    return fail("--password is not valid with spawn-sshd");
                }
                if (!need(i, out.client.password)) return fail("--password requires an argument");
            } else if (eq(a, "--port")) {
                if (out.cmd != subcommand::connect) {
                    return fail("--port is only valid with connect");
                }
                std::string v;
                if (!need(i, v) || !parse_port(v, out.client.port)) {
                    return fail("invalid --port");
                }
                saw_port = true;
            } else if (eq(a, "--sshd")) {
                if (out.cmd != subcommand::spawn_sshd) {
                    return fail("--sshd is only valid with spawn-sshd");
                }
                if (!need(i, out.client.sshd_path)) return fail("--sshd requires an argument");
            } else if (eq(a, "--identity")) {
                if (out.cmd != subcommand::connect) {
                    return fail("--identity is only valid with connect");
                }
                if (!need(i, out.client.identity_path)) {
                    return fail("--identity requires an argument");
                }
            } else if (eq(a, "--jump")) {
                if (out.cmd != subcommand::connect) {
                    return fail("--jump is only valid with connect");
                }
                std::string v;
                if (!need(i, v)) return fail("--jump requires an argument");
                auto hop = parse_endpoint(v, "--jump", error);
                if (!hop) {
                    append_usage(error);
                    return std::nullopt;
                }
                out.client.jumps.push_back(std::move(*hop));
            } else if (eq(a, "--jump-identity")) {
                if (out.cmd != subcommand::connect) {
                    return fail("--jump-identity is only valid with connect");
                }
                std::string v;
                if (!need(i, v)) return fail("--jump-identity requires an argument");
                jump_identities.push_back(std::move(v));
            } else if (eq(a, "--jump-password")) {
                if (out.cmd != subcommand::connect) {
                    return fail("--jump-password is only valid with connect");
                }
                std::string v;
                if (!need(i, v)) return fail("--jump-password requires an argument");
                jump_passwords.push_back(std::move(v));
            } else if (eq(a, "--workload")) {
                std::string v;
                if (!need(i, v)) return fail("--workload requires an argument");
                if (v == "handshake") out.client.work = workload::handshake;
                else if (v == "download") out.client.work = workload::download;
                else if (v == "upload") out.client.work = workload::upload;
                else if (v == "all") out.client.work = workload::all;
                else return fail("invalid --workload (handshake|download|upload|all)");
            } else if (eq(a, "--repeat")) {
                std::string v;
                if (!need(i, v) || !parse_i32(v, out.client.repeat) || out.client.repeat < 1) {
                    return fail("invalid --repeat");
                }
            } else if (eq(a, "--warmup")) {
                std::string v;
                if (!need(i, v) || !parse_f64(v, out.client.warmup_seconds)
                    || out.client.warmup_seconds < 0) {
                    return fail("invalid --warmup");
                }
            } else if (eq(a, "--seconds")) {
                std::string v;
                if (!need(i, v) || !parse_f64(v, out.client.seconds) || out.client.seconds <= 0) {
                    return fail("invalid --seconds");
                }
                saw_seconds = true;
            } else if (eq(a, "--bytes")) {
                std::string v;
                if (!need(i, v) || !parse_u64(v, out.client.bytes)) {
                    return fail("invalid --bytes");
                }
                saw_bytes = true;
            } else if (eq(a, "--exec-download")) {
                if (!need(i, out.client.exec_download)) {
                    return fail("--exec-download requires an argument");
                }
            } else if (eq(a, "--exec-upload")) {
                if (!need(i, out.client.exec_upload)) {
                    return fail("--exec-upload requires an argument");
                }
            } else if (eq(a, "--timeout")) {
                std::string v;
                if (!need(i, v) || !parse_f64(v, out.client.timeout_seconds)
                    || out.client.timeout_seconds < 0) {
                    return fail("invalid --timeout");
                }
            } else if (eq(a, "--json")) {
                out.client.json = true;
            } else if (!a.empty() && a.front() != '-') {
                if (out.cmd != subcommand::connect) {
                    return fail("unexpected argument '" + std::string{a} + "'");
                }
                if (!dest.empty()) {
                    return fail("unexpected extra argument '" + std::string{a} + "'");
                }
                dest = std::string{a};
            } else {
                return fail("unknown option '" + std::string{a} + "'");
            }
        }
    }

    if (out.cmd != subcommand::server) {
        if (saw_seconds && saw_bytes) {
            return fail("--seconds and --bytes are mutually exclusive");
        }
    }
    if (out.cmd == subcommand::connect) {
        if (dest.empty()) return fail("connect requires a destination ([user@]host[:port])");
        auto hop = parse_endpoint(dest, "destination", error);
        if (!hop) {
            append_usage(error);
            return std::nullopt;
        }
        out.client.host = std::move(hop->host);
        if (!saw_port) out.client.port = hop->port;
        if (!saw_user && !hop->user.empty()) out.client.user = std::move(hop->user);
        if (jump_identities.size() > out.client.jumps.size()
            || jump_passwords.size() > out.client.jumps.size()) {
            return fail("--jump-identity/--jump-password count exceeds --jump hops");
        }
        for (std::size_t i = 0; i < jump_identities.size(); ++i) {
            out.client.jumps[i].identity = std::move(jump_identities[i]);
        }
        for (std::size_t i = 0; i < jump_passwords.size(); ++i) {
            out.client.jumps[i].password = std::move(jump_passwords[i]);
        }
    }

    return out;
}

std::string default_exec_command(direction dir) {
#ifdef _WIN32
    if (dir == direction::upload) {
        return "powershell -NoProfile -Command \"$input | Out-Null\"";
    }
    return "powershell -NoProfile -Command "
           "while ($true) { [Console]::OpenStandardOutput().Write([byte[]]::new(65536)) }";
#else
    if (dir == direction::upload) return "cat >/dev/null";
    return "cat /dev/zero";
#endif
}

}  // namespace bench
