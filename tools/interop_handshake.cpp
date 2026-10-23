// TCP handshake harness against a real sshd. This is the only M1 code allowed
// to perform I/O; the library headers remain sans-I/O.
#include <yanterm-ssh/core/config.hpp>
#include <yanterm-ssh/core/connection.hpp>
#include <yanterm-ssh/core/types.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/kex/algorithms.hpp>

#include "fixed_random_provider.hpp"
#include "hex_util.hpp"
#include "recording_handler.hpp"
#include "replay.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

using namespace yanterm::ssh;

namespace {

struct options {
    std::string host = "127.0.0.1";
    int port = 22;
    std::uint64_t seed = 0x1234567890abcdefull;
    std::string trace_path;
    std::string kex = "curve25519-sha256";
    std::string cipher = "chacha20-poly1305@openssh.com";
    std::string hostkey = "ssh-ed25519";
    std::string mac = "hmac-sha2-256-etm@openssh.com";
    bool post_handshake_traffic = true;
    bool list_kex = false;
};

void usage(const char* argv0) {
    std::cerr
        << "Usage: " << argv0
        << " --host HOST --port PORT --seed HEX [--trace PATH]\n"
        << "         [--kex NAME] [--cipher NAME] [--hostkey NAME] [--mac NAME]\n"
        << "         [--no-traffic]\n"
        << "       " << argv0 << " --list-kex\n";
}

bool parse_args(int argc, char** argv, options& opt) {
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto need = [&](std::string& dest) {
            if (i + 1 >= argc) return false;
            dest = argv[++i];
            return true;
        };
        if (a == "--host") {
            if (!need(opt.host)) return false;
        } else if (a == "--port") {
            std::string v;
            if (!need(v)) return false;
            opt.port = std::stoi(v);
        } else if (a == "--seed") {
            std::string v;
            if (!need(v)) return false;
            if (!testing::replay_detail::parse_u64_hex(v, opt.seed)) return false;
        } else if (a == "--trace") {
            if (!need(opt.trace_path)) return false;
        } else if (a == "--kex") {
            if (!need(opt.kex)) return false;
        } else if (a == "--cipher") {
            if (!need(opt.cipher)) return false;
        } else if (a == "--hostkey") {
            if (!need(opt.hostkey)) return false;
        } else if (a == "--mac") {
            if (!need(opt.mac)) return false;
        } else if (a == "--no-traffic") {
            opt.post_handshake_traffic = false;
        } else if (a == "--list-kex") {
            opt.list_kex = true;
        } else if (a == "--help" || a == "-h") {
            usage(argv[0]);
            std::exit(0);
        } else {
            std::cerr << "unknown arg: " << a << '\n';
            return false;
        }
    }
    return true;
}

int connect_tcp(const std::string& host, int port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<std::uint16_t>(port));
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        ::close(fd);
        return -1;
    }
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return -1;
    }
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags >= 0) ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    return fd;
}

bool flush_output(int fd, core::connection& conn, testing::trace_writer* tw) {
    for (;;) {
        const auto out = conn.pending_output0();
        if (out.empty()) return true;
        const ssize_t n =
            ::send(fd, out.data(), out.size(), MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
            return false;
        }
        if (n == 0) return false;
        if (tw) tw->out_bytes(out.first(static_cast<std::size_t>(n)));
        conn.consume_output(static_cast<std::size_t>(n));
    }
}

bool pump_inbound(core::connection& conn, std::vector<std::byte>& inbound) {
    for (;;) {
        std::size_t accepted = 0;
        const std::error_code ec = conn.feed(inbound, accepted);
        if (accepted > 0) {
            inbound.erase(inbound.begin(),
                          inbound.begin() + static_cast<std::ptrdiff_t>(accepted));
        }
        if (ec) {
            std::cerr << "feed failed: " << ec.message() << '\n';
            return false;
        }
        if (accepted == 0) return true;
    }
}

bool read_into(int fd, core::connection& conn, std::vector<std::byte>& inbound,
               testing::trace_writer* tw) {
    std::byte buf[16 * 1024];
    const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
        return false;
    }
    if (n == 0) return false;
    const std::span<const std::byte> bytes{buf, static_cast<std::size_t>(n)};
    if (tw) tw->in_bytes(bytes);
    inbound.insert(inbound.end(), bytes.begin(), bytes.end());
    return pump_inbound(conn, inbound);
}

}  // namespace

int main(int argc, char** argv) {
    options opt;
    if (!parse_args(argc, argv, opt)) {
        usage(argv[0]);
        return 2;
    }

    crypto::openssl_backend backend;
    if (opt.list_kex) {
        std::cout << kex::supported_kex_algorithms(crypto::provider::wrap(backend)) << '\n';
        return 0;
    }
    testing::fixed_random_provider fr{crypto::provider::wrap(backend), opt.seed};
    crypto::provider p = fr.get();

    testing::replay_config rc;
    rc.seed = opt.seed;
    rc.role = core::role::client;
    rc.kex = opt.kex;
    rc.cipher = opt.cipher;
    rc.hostkey = opt.hostkey;
    rc.mac = opt.mac;

    std::vector<std::string_view> kex{rc.kex}, hostkey{rc.hostkey}, cipher{rc.cipher}, mac;
    if (!rc.mac.empty()) mac.push_back(rc.mac);
    core::config cfg = testing::make_config_from_trace(rc, kex, hostkey, cipher, mac);

    testing::trace_writer tw;
    tw.comment("captured against OpenSSH via yanterm-ssh-interop-handshake");
    tw.header(rc);
    testing::trace_writer* twp = opt.trace_path.empty() ? nullptr : &tw;

    testing::recording_handler handler;
    core::connection conn{core::role::client, p, cfg, handler};
    std::vector<std::byte> inbound;

    const int fd = connect_tcp(opt.host, opt.port);
    if (fd < 0) {
        std::cerr << "connect failed to " << opt.host << ":" << opt.port << " errno=" << errno
                  << '\n';
        return 1;
    }

    bool handshake_done = false;
    bool saw_ignore = false;
    bool saw_debug = false;
    bool sent_ignore = false;
    bool sent_debug = false;

    auto handle_events = [&] {
        while (!handler.events.empty()) {
            auto ev = std::move(handler.events.front());
            handler.events.erase(handler.events.begin());
            using testing::replay_detail::sha256_fingerprint;
            if (const auto* peer =
                    std::get_if<testing::recording_handler::peer_identification>(&ev)) {
                if (twp) twp->event_line("peer_identification", peer->banner);
                std::cerr << "peer: " << peer->banner << '\n';
            } else if (const auto* host =
                           std::get_if<testing::recording_handler::verify_host_key>(&ev)) {
                const auto fp = sha256_fingerprint(p, host->blob);
                if (twp) {
                    twp->event_line("verify_host_key", fp);
                    twp->resolve_line("accept");
                }
                conn.resolve(host->ticket, core::host_key_verdict::accept);
                // resolve() queues our NEWKEYS and SERVICE_REQUEST in
                // pending_output. Record/send them before emitting later
                // events so traces stay ordered for replay.
                if (!flush_output(fd, conn, twp)) return false;
                if (!pump_inbound(conn, inbound)) return false;
            } else if (std::holds_alternative<testing::recording_handler::handshake_done>(ev)) {
                if (twp) twp->event_line("handshake_done");
                handshake_done = true;
                std::cerr << "handshake_done\n";
            } else if (std::holds_alternative<testing::recording_handler::ignore_message>(ev)) {
                saw_ignore = true;
            } else if (std::holds_alternative<testing::recording_handler::debug_message>(ev)) {
                saw_debug = true;
            } else if (std::holds_alternative<testing::recording_handler::disconnected>(ev)) {
                std::cerr << "disconnected\n";
                return false;
            }
        }
        return !conn.failure();
    };

    // Initial local banner.
    if (!flush_output(fd, conn, twp) || !handle_events()) {
        ::close(fd);
        return 1;
    }

    for (int iter = 0; iter < 10000; ++iter) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = 50 * 1000;
        const int sel = ::select(fd + 1, &rfds, nullptr, nullptr, &tv);
        if (sel < 0) {
            std::cerr << "select failed\n";
            ::close(fd);
            return 1;
        }
        if (sel > 0 && FD_ISSET(fd, &rfds)) {
            if (!read_into(fd, conn, inbound, twp) || !handle_events()) {
                ::close(fd);
                return 1;
            }
        }
        if (!flush_output(fd, conn, twp) || !handle_events()) {
            ::close(fd);
            return 1;
        }

        if (handshake_done && opt.post_handshake_traffic) {
            if (!sent_ignore) {
                const std::byte payload[] = {std::byte{'x'}, std::byte{'s'}, std::byte{'s'},
                                             std::byte{'h'}};
                if (auto ec = conn.send_ignore(payload)) {
                    std::cerr << "send_ignore failed: " << ec.message() << '\n';
                    ::close(fd);
                    return 1;
                }
                sent_ignore = true;
            } else if (!sent_debug) {
                if (auto ec = conn.send_debug(false, "yanterm-ssh interop")) {
                    std::cerr << "send_debug failed: " << ec.message() << '\n';
                    ::close(fd);
                    return 1;
                }
                sent_debug = true;
            } else if (sent_ignore && sent_debug) {
                // Give the peer a moment to process; we do not require it to echo.
                if (!flush_output(fd, conn, twp)) {
                    ::close(fd);
                    return 1;
                }
                break;
            }
        } else if (handshake_done && !opt.post_handshake_traffic) {
            break;
        }
    }

    ::close(fd);

    if (!handshake_done) {
        std::cerr << "handshake did not complete\n";
        return 1;
    }
    if (conn.failure()) {
        std::cerr << "connection failure: " << conn.failure().message() << '\n';
        return 1;
    }

    if (!opt.trace_path.empty()) {
        // Trace captures through handshake_done only (pre-traffic), so strip any
        // post-handshake lines by rewriting from a handshake-scoped writer.
        // We already appended handshake_done before sending IGNORE/DEBUG; any
        // further out_bytes after that are post-handshake. For corpus stability,
        // rewrite: keep lines until handshake_done inclusive.
        const std::string full = tw.str();
        std::istringstream in{full};
        std::ostringstream kept;
        std::string line;
        while (std::getline(in, line)) {
            kept << line << '\n';
            if (testing::replay_detail::trim(line) == "event handshake_done") break;
        }
        std::ofstream out{opt.trace_path, std::ios::binary | std::ios::trunc};
        if (!out) {
            std::cerr << "cannot write trace " << opt.trace_path << '\n';
            return 1;
        }
        out << kept.str();
        std::cerr << "wrote trace " << opt.trace_path << '\n';
    }

    (void)saw_ignore;
    (void)saw_debug;
    std::cerr << "ok (ignore_sent=" << sent_ignore << " debug_sent=" << sent_debug << ")\n";
    return 0;
}
