#pragma once

#include <yanterm-ssh/core/config.hpp>
#include <yanterm-ssh/core/connection.hpp>
#include <yanterm-ssh/core/types.hpp>
#include <yanterm-ssh/crypto/algorithms.hpp>
#include <yanterm-ssh/crypto/provider.hpp>

#include "drive.hpp"
#include "hex_util.hpp"
#include "recording_handler.hpp"

#include <array>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace yanterm::ssh::testing {

struct replay_config {
    std::uint64_t seed = 0;
    core::role role = core::role::client;
    std::string kex;
    std::string cipher;
    std::string hostkey;
    std::string mac;
};

// V_C is an input to the exchange hash, so capture and replay share one
// identification string. A library version bump must not rewrite stored traces.
inline constexpr std::string_view replay_software = "yanterm_ssh_0.1.0";

struct replay_mismatch {
    std::string message;
    std::size_t line = 0;
    std::size_t offset = 0;
};

struct loaded_trace {
    replay_config cfg;
    std::string body;
};

namespace replay_detail {

inline std::string trim(std::string_view s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.remove_suffix(1);
    return std::string{s};
}

inline bool parse_u64_hex(std::string_view s, std::uint64_t& out) {
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s.remove_prefix(2);
    if (s.empty()) return false;
    std::uint64_t v = 0;
    for (char c : s) {
        int n = -1;
        if (c >= '0' && c <= '9') n = c - '0';
        else if (c >= 'a' && c <= 'f') n = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') n = c - 'A' + 10;
        if (n < 0) return false;
        v = (v << 4) | static_cast<std::uint64_t>(n);
    }
    out = v;
    return true;
}

inline std::string b64_nopad(std::span<const std::byte> in) {
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((in.size() + 2) / 3 * 4);
    for (std::size_t i = 0; i < in.size(); i += 3) {
        const unsigned b0 = std::to_integer<unsigned>(in[i]);
        const unsigned b1 = (i + 1 < in.size()) ? std::to_integer<unsigned>(in[i + 1]) : 0;
        const unsigned b2 = (i + 2 < in.size()) ? std::to_integer<unsigned>(in[i + 2]) : 0;
        const unsigned n = (b0 << 16) | (b1 << 8) | b2;
        out.push_back(kAlphabet[(n >> 18) & 63]);
        out.push_back(kAlphabet[(n >> 12) & 63]);
        if (i + 1 < in.size()) out.push_back(kAlphabet[(n >> 6) & 63]);
        if (i + 2 < in.size()) out.push_back(kAlphabet[n & 63]);
    }
    return out;
}

inline std::string sha256_fingerprint(crypto::provider p, std::span<const std::byte> blob) {
    std::array<std::byte, 32> dig{};
    if (!p.hash(crypto::hash_id::sha256, blob, dig)) return {};
    return "sha256:" + b64_nopad(dig);
}

inline std::string hex_context(std::span<const std::byte> data, std::size_t offset,
                               std::size_t window = 16) {
    const std::size_t begin = offset > window ? offset - window : 0;
    const std::size_t end = std::min(data.size(), offset + window);
    std::ostringstream oss;
    oss << "offset=" << offset << " context[" << begin << "," << end << ")=";
    oss << hex(std::span{data}.subspan(begin, end - begin));
    return oss.str();
}

inline std::optional<std::string> kv_value(std::string_view line, std::string_view key) {
    const std::string prefix = std::string{key} + "=";
    std::size_t pos = 0;
    while (pos < line.size()) {
        while (pos < line.size() && std::isspace(static_cast<unsigned char>(line[pos]))) ++pos;
        if (pos >= line.size()) break;
        const std::size_t start = pos;
        while (pos < line.size() && !std::isspace(static_cast<unsigned char>(line[pos]))) ++pos;
        const auto tok = line.substr(start, pos - start);
        if (tok.size() >= prefix.size() && tok.substr(0, prefix.size()) == prefix) {
            return std::string{tok.substr(prefix.size())};
        }
    }
    return std::nullopt;
}

}  // namespace replay_detail

inline bool load_trace_file(const std::string& path, loaded_trace& out, std::string& err) {
    std::ifstream in{path};
    if (!in) {
        err = "cannot open " + path;
        return false;
    }
    out = {};
    std::string line;
    std::size_t line_no = 0;
    bool header_done = false;
    std::ostringstream body;
    bool have_seed = false;
    bool have_role = false;
    while (std::getline(in, line)) {
        ++line_no;
        auto t = replay_detail::trim(line);
        if (!header_done) {
            if (t.empty() || t[0] == '#') continue;
            if (t.rfind("seed ", 0) == 0) {
                if (!replay_detail::parse_u64_hex(t.substr(5), out.cfg.seed)) {
                    err = "invalid seed at line " + std::to_string(line_no);
                    return false;
                }
                have_seed = true;
                continue;
            }
            if (t.rfind("role ", 0) == 0) {
                const auto r = replay_detail::trim(t.substr(5));
                if (r == "client") out.cfg.role = core::role::client;
                else if (r == "server") out.cfg.role = core::role::server;
                else {
                    err = "invalid role";
                    return false;
                }
                have_role = true;
                continue;
            }
            if (t.rfind("config ", 0) == 0 || t == "config") {
                const auto b = (t == "config") ? std::string_view{} : std::string_view{t}.substr(7);
                if (auto v = replay_detail::kv_value(b, "kex")) out.cfg.kex = *v;
                if (auto v = replay_detail::kv_value(b, "cipher")) out.cfg.cipher = *v;
                if (auto v = replay_detail::kv_value(b, "hostkey")) out.cfg.hostkey = *v;
                if (auto v = replay_detail::kv_value(b, "mac")) out.cfg.mac = *v;
                continue;
            }
            header_done = true;
            body << line << '\n';
            continue;
        }
        body << line << '\n';
    }
    if (!have_seed || !have_role) {
        err = "missing seed or role";
        return false;
    }
    out.body = body.str();
    return true;
}

inline core::config make_config_from_trace(const replay_config& cfg,
                                           std::vector<std::string_view>& kex,
                                           std::vector<std::string_view>& hostkey,
                                           std::vector<std::string_view>& cipher,
                                           std::vector<std::string_view>& mac) {
    core::config c;
    c.software = replay_software;
    kex.clear();
    hostkey.clear();
    cipher.clear();
    mac.clear();
    if (!cfg.kex.empty()) {
        kex.push_back(cfg.kex);
        c.preferred_kex = kex.back();
    }
    if (!cfg.hostkey.empty()) {
        hostkey.push_back(cfg.hostkey);
        c.preferred_host_key = hostkey.back();
    }
    if (!cfg.cipher.empty()) {
        cipher.push_back(cfg.cipher);
        c.preferred_cipher = cipher.back();
    }
    if (!cfg.mac.empty()) {
        mac.push_back(cfg.mac);
        c.preferred_mac = mac.back();
    }
    return c;
}

inline std::optional<replay_mismatch> replay_trace_body(crypto::provider p, core::connection& conn,
                                                        recording_handler& handler,
                                                        std::string_view body) {
    std::istringstream in{std::string{body}};
    std::string line;
    std::size_t line_no = 0;
    std::optional<core::host_key_ticket> pending;
    std::vector<std::byte> inbound_;

    auto fail = [&](std::string msg, std::size_t off = 0) -> std::optional<replay_mismatch> {
        return replay_mismatch{std::move(msg), line_no, off};
    };

    auto pump = [&]() -> std::optional<replay_mismatch> {
        for (;;) {
            std::size_t accepted = 0;
            const std::error_code ec = conn.feed(inbound_, accepted);
            if (accepted > 0) {
                inbound_.erase(inbound_.begin(),
                               inbound_.begin() + static_cast<std::ptrdiff_t>(accepted));
            }
            if (ec) return fail("feed failed ec=" + ec.message());
            if (accepted == 0) return std::nullopt;
        }
    };

    while (std::getline(in, line)) {
        ++line_no;
        auto t = replay_detail::trim(line);
        if (t.empty() || t[0] == '#') continue;

        if (t[0] == '>') {
            auto expect = unhex(replay_detail::trim(t.substr(1)));
            const auto got_buf = collect_output(conn);
            std::span<const std::byte> got{got_buf};
            if (got.size() < expect.size()) {
                return fail("output shorter than expected: got " + std::to_string(got.size())
                                + " want " + std::to_string(expect.size()) + " "
                                + replay_detail::hex_context(expect, got.size()),
                            got.size());
            }
            for (std::size_t i = 0; i < expect.size(); ++i) {
                if (got[i] != expect[i]) {
                    return fail("output byte mismatch: " + replay_detail::hex_context(got, i)
                                    + " expected_byte=" + hex(std::span{expect}.subspan(i, 1)),
                                i);
                }
            }
            conn.consume_output(expect.size());
            continue;
        }

        if (t[0] == '<') {
            auto bytes = unhex(replay_detail::trim(t.substr(1)));
            inbound_.insert(inbound_.end(), bytes.begin(), bytes.end());
            if (auto err = pump()) return err;
            continue;
        }

        if (t.rfind("event ", 0) == 0) {
            auto rest = replay_detail::trim(t.substr(6));
            std::string name;
            std::string arg;
            const auto sp = rest.find(' ');
            if (sp == std::string::npos) name = rest;
            else {
                name = rest.substr(0, sp);
                arg = replay_detail::trim(rest.substr(sp + 1));
            }
            if (name == "channel_released") {
                return fail("channel_released is not a replay event");
            }
            if (handler.events.empty()) {
                return fail("expected recorded event " + name + " but handler empty");
            }
            const auto got_name = recorded_event_name(handler.events.front());
            if (got_name != name) {
                return fail(std::string{"recorded event mismatch got "} + std::string{got_name}
                            + " want " + name);
            }
            const auto front = std::move(handler.events.front());
            handler.events.erase(handler.events.begin());
            if (name == "peer_identification" && !arg.empty()) {
                const auto* peer = std::get_if<recording_handler::peer_identification>(&front);
                if (!peer || peer->banner != arg) {
                    return fail("peer_identification mismatch");
                }
            }
            if (name == "verify_host_key") {
                const auto* host = std::get_if<recording_handler::verify_host_key>(&front);
                if (!host) return fail("verify_host_key variant mismatch");
                pending = host->ticket;
                if (!arg.empty()) {
                    if (host->blob.empty()) return fail("verify_host_key missing host_key");
                    const auto fp = replay_detail::sha256_fingerprint(p, host->blob);
                    if (fp != arg) {
                        return fail("host key fingerprint mismatch got '" + fp + "' want '" + arg
                                    + "'");
                    }
                }
            }
            if (name == "debug_message" && !arg.empty()) {
                const auto* dbg = std::get_if<recording_handler::debug_message>(&front);
                if (!dbg || dbg->text != arg) return fail("debug text mismatch");
            }
            continue;
        }

        if (t.rfind("resolve ", 0) == 0) {
            const auto v = replay_detail::trim(t.substr(8));
            if (!pending) return fail("resolve without prior verify_host_key event");
            if (v == "accept") conn.resolve(*pending, core::host_key_verdict::accept);
            else if (v == "reject") conn.resolve(*pending, core::host_key_verdict::reject);
            else return fail("invalid resolve verdict");
            pending.reset();
            if (auto err = pump()) return err;
            continue;
        }

        return fail("unrecognized directive: " + t);
    }

    for (const auto& leftover : handler.events) {
        const auto name = recorded_event_name(leftover);
        if (is_handler_transport_event(name)) {
            return fail(std::string{"unexpected leftover recorded event "} + std::string{name});
        }
    }
    if (conn.pending_output_bytes() != 0) {
        return fail("unexpected leftover output bytes="
                    + std::to_string(conn.pending_output_bytes()));
    }
    if (!inbound_.empty()) {
        return fail("unconsumed inbound bytes=" + std::to_string(inbound_.size()));
    }
    if (conn.failure()) {
        return fail("connection failure: " + conn.failure().message());
    }
    return std::nullopt;
}

// Append one trace line recording local output / peer input / events.
class trace_writer {
public:
    void comment(std::string_view c) { lines_.emplace_back("# " + std::string{c}); }

    void header(const replay_config& cfg) {
        std::ostringstream seed;
        seed << std::hex << cfg.seed;
        lines_.push_back("seed " + seed.str());
        lines_.push_back(std::string{"role "}
                         + (cfg.role == core::role::client ? "client" : "server"));
        std::ostringstream conf;
        conf << "config";
        if (!cfg.kex.empty()) conf << " kex=" << cfg.kex;
        if (!cfg.cipher.empty()) conf << " cipher=" << cfg.cipher;
        if (!cfg.hostkey.empty()) conf << " hostkey=" << cfg.hostkey;
        if (!cfg.mac.empty()) conf << " mac=" << cfg.mac;
        // Always emit a trailing marker so parsers can match "config " reliably
        // even when no algorithm overrides are set.
        if (cfg.kex.empty() && cfg.cipher.empty() && cfg.hostkey.empty() && cfg.mac.empty()) {
            conf << " kex=";
        }
        lines_.push_back(conf.str());
    }

    void out_bytes(std::span<const std::byte> b) {
        if (!b.empty()) lines_.push_back("> " + hex(b));
    }

    void in_bytes(std::span<const std::byte> b) {
        if (!b.empty()) lines_.push_back("< " + hex(b));
    }

    void event_line(std::string_view name, std::string_view arg = {}) {
        if (arg.empty()) lines_.push_back("event " + std::string{name});
        else lines_.push_back("event " + std::string{name} + " " + std::string{arg});
    }

    void resolve_line(std::string_view verdict) {
        lines_.push_back("resolve " + std::string{verdict});
    }

    [[nodiscard]] std::string str() const {
        std::ostringstream oss;
        for (const auto& l : lines_) oss << l << '\n';
        return oss.str();
    }

    bool write_file(const std::string& path) const {
        std::ofstream out{path, std::ios::binary | std::ios::trunc};
        if (!out) return false;
        out << str();
        return static_cast<bool>(out);
    }

private:
    std::vector<std::string> lines_;
};

}  // namespace yanterm::ssh::testing
