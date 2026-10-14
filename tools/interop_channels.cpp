// TCP channel harness against OpenSSH. This is the only M4 channel code allowed
// to perform I/O; the library headers remain sans-I/O.
#include <yanterm-ssh/channels/requests.hpp>
#include <yanterm-ssh/channels/types.hpp>
#include <yanterm-ssh/core/config.hpp>
#include <yanterm-ssh/core/connection.hpp>
#include <yanterm-ssh/core/types.hpp>
#include <yanterm-ssh/wire/message_ids.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/keys/private_key.hpp>
#include <yanterm-ssh/keys/public_key.hpp>

#include "legacy_loopback_event.hpp"
#include "recording_handler.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

using namespace yanterm::ssh;

using auth::auth_verdict;

namespace {

constexpr std::string_view k_kex = "curve25519-sha256";
constexpr std::string_view k_cipher = "chacha20-poly1305@openssh.com";
constexpr std::string_view k_hostkey = "ssh-ed25519";
constexpr std::string_view k_methods = "publickey,password,keyboard-interactive";
constexpr std::string_view k_pty_marker = "YANTERM_M4_PTY";
constexpr std::string_view k_pty_script = "echo YANTERM_M4_PTY\nexit\n";
constexpr std::string_view k_ping = "PING\n";
constexpr auto k_channel_timeout = std::chrono::seconds(10);

struct options {
    std::string mode;
    std::string host = "127.0.0.1";
    int port = 22;
    int listen = 0;
    std::string user;
    std::string identity;
    std::string host_key;
    std::string authorized;
    std::string scenario;
    std::string forward_host = "127.0.0.1";
    int forward_port = 0;
};

void usage(const char* argv0) {
    std::cerr
        << "Usage:\n  " << argv0
        << " --mode client --host HOST --port PORT --user USER --identity PATH\n"
        << "             --scenario pty-shell|direct-tcpip [--forward-host H --forward-port P]\n  "
        << argv0
        << " --mode server --listen PORT --host-key PATH --user USER --authorized PATH\n"
        << "             --scenario exec-true|direct-tcpip\n";
}

bool parse_args(int argc, char** argv, options& opt) {
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto need = [&](std::string& dest) {
            if (i + 1 >= argc) return false;
            dest = argv[++i];
            return true;
        };
        if (a == "--mode") {
            if (!need(opt.mode)) return false;
        } else if (a == "--host") {
            if (!need(opt.host)) return false;
        } else if (a == "--port") {
            std::string v;
            if (!need(v)) return false;
            opt.port = std::stoi(v);
        } else if (a == "--listen") {
            std::string v;
            if (!need(v)) return false;
            opt.listen = std::stoi(v);
        } else if (a == "--user") {
            if (!need(opt.user)) return false;
        } else if (a == "--identity") {
            if (!need(opt.identity)) return false;
        } else if (a == "--host-key") {
            if (!need(opt.host_key)) return false;
        } else if (a == "--authorized") {
            if (!need(opt.authorized)) return false;
        } else if (a == "--scenario") {
            if (!need(opt.scenario)) return false;
        } else if (a == "--forward-host") {
            if (!need(opt.forward_host)) return false;
        } else if (a == "--forward-port") {
            std::string v;
            if (!need(v)) return false;
            opt.forward_port = std::stoi(v);
        } else if (a == "--help" || a == "-h") {
            usage(argv[0]);
            std::exit(0);
        } else {
            std::cerr << "unknown arg: " << a << '\n';
            return false;
        }
    }
    if (opt.mode == "client") {
        if (opt.user.empty() || opt.identity.empty() || opt.port <= 0) return false;
        if (opt.scenario == "pty-shell") return true;
        if (opt.scenario == "direct-tcpip") return opt.forward_port > 0 && !opt.forward_host.empty();
        return false;
    }
    if (opt.mode == "server") {
        return !opt.user.empty() && !opt.host_key.empty() && !opt.authorized.empty()
            && opt.listen > 0
            && (opt.scenario == "exec-true" || opt.scenario == "direct-tcpip");
    }
    return false;
}

std::error_code load_bytes(const std::string& path, std::vector<std::byte>& out) {
    std::ifstream in{path, std::ios::binary};
    if (!in) return std::make_error_code(std::errc::no_such_file_or_directory);
    in.seekg(0, std::ios::end);
    const auto n = static_cast<std::size_t>(in.tellg());
    in.seekg(0, std::ios::beg);
    out.resize(n);
    if (n > 0) {
        in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(n));
        if (!in) return std::make_error_code(std::errc::io_error);
    }
    return {};
}

std::error_code load_private(const std::string& path, crypto::provider p, keys::private_key& out) {
    std::vector<std::byte> bytes;
    if (auto ec = load_bytes(path, bytes)) return ec;
    return keys::private_key::parse(bytes, p, {}, out);
}

std::error_code load_authorized(const std::string& path, keys::public_key& out) {
    std::vector<std::byte> bytes;
    if (auto ec = load_bytes(path, bytes)) return ec;
    std::string_view text{reinterpret_cast<const char*>(bytes.data()), bytes.size()};
    const auto nl = text.find_first_of("\r\n");
    if (nl != std::string_view::npos) text = text.substr(0, nl);
    return keys::public_key::parse_line(text, out);
}

core::config pinned_config(std::string_view& kex, std::string_view& hostkey,
                           std::string_view& cipher) {
    kex = k_kex;
    hostkey = k_hostkey;
    cipher = k_cipher;
    core::config cfg;
    cfg.preferred_kex = kex;
    cfg.preferred_host_key = hostkey;
    cfg.preferred_cipher = cipher;
    return cfg;
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
    int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags >= 0) ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    const int cr = ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (cr != 0 && errno != EINPROGRESS) {
        ::close(fd);
        return -1;
    }
    if (cr != 0) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);
        timeval tv{};
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        const int sel = ::select(fd + 1, nullptr, &wfds, nullptr, &tv);
        if (sel <= 0) {
            ::close(fd);
            return -1;
        }
        int soerr = 0;
        socklen_t slen = sizeof(soerr);
        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) != 0 || soerr != 0) {
            ::close(fd);
            return -1;
        }
    }
    return fd;
}

int listen_tcp(int port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    const int yes = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<std::uint16_t>(port));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return -1;
    }
    if (::listen(fd, 1) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

int accept_tcp(int listen_fd) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(listen_fd, &rfds);
    timeval tv{};
    tv.tv_sec = 15;
    tv.tv_usec = 0;
    const int sel = ::select(listen_fd + 1, &rfds, nullptr, nullptr, &tv);
    if (sel <= 0) return -1;
    sockaddr_in peer{};
    socklen_t len = sizeof(peer);
    const int fd = ::accept(listen_fd, reinterpret_cast<sockaddr*>(&peer), &len);
    if (fd < 0) return -1;
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags >= 0) ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    return fd;
}

bool flush_output(int fd, core::connection& conn) {
    for (;;) {
        const auto out = conn.pending_output0();
        if (out.empty()) return true;
        const ssize_t n = ::send(fd, out.data(), out.size(), MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
            return false;
        }
        if (n == 0) return false;
        conn.consume_output(static_cast<std::size_t>(n));
    }
}

bool pump_inbound(core::connection& conn, std::vector<std::byte>& inbound, bool tolerate_teardown) {
    for (;;) {
        std::size_t accepted = 0;
        const std::error_code ec = conn.feed(inbound, accepted);
        if (accepted > 0) {
            inbound.erase(inbound.begin(),
                          inbound.begin() + static_cast<std::ptrdiff_t>(accepted));
        }
        if (ec) {
            if (tolerate_teardown) {
                std::cerr << "feed after channel_ok: " << ec.message() << '\n';
                inbound.clear();
                return true;
            }
            std::cerr << "feed failed: " << ec.message() << '\n';
            return false;
        }
        if (accepted == 0) return true;
    }
}

bool read_into(int fd, core::connection& conn, std::vector<std::byte>& inbound,
               bool tolerate_teardown) {
    std::byte buf[16 * 1024];
    const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
        return false;
    }
    if (n == 0) return tolerate_teardown;
    inbound.insert(inbound.end(), buf, buf + n);
    return pump_inbound(conn, inbound, tolerate_teardown);
}

bool blob_eq(std::span<const std::byte> a, std::span<const std::byte> b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}

bool write_channel(core::connection& conn, core::channel_ref id, std::string& pending) {
    while (!pending.empty()) {
        const auto b = std::as_bytes(std::span<const char>{pending.data(), pending.size()});
        std::span<const std::byte> frags[] = {b};
        std::size_t accepted = 0;
        if (auto ec = conn.channel_write(id, frags, accepted)) {
            std::cerr << "channel_write: " << ec.message() << '\n';
            return false;
        }
        if (accepted == 0) return true;
        pending.erase(0, accepted);
    }
    return true;
}

void drain_channel(core::connection& conn, core::channel_ref id, std::string& acc) {
    std::byte buf[8 * 1024];
    for (;;) {
        const auto n = conn.channel_read(id, 0, buf);
        if (n == 0) break;
        acc.append(reinterpret_cast<const char*>(buf), n);
    }
    for (;;) {
        const auto n = conn.channel_read(id, channels::extended_data_stderr, buf);
        if (n == 0) break;
        acc.append(reinterpret_cast<const char*>(buf), n);
    }
}

struct tcp_bridge {
    int fd = -1;
    core::channel_ref ch{};
    bool attached = false;  // channel 0 is a valid id; do not use ch==0 as unset
    std::string to_tcp;
    std::string to_ch;
    bool tcp_eof = false;
    bool ch_eof_sent = false;
    bool ch_eof_recv = false;
    bool closed = false;
    std::size_t from_tcp = 0;

    void close_fd() {
        if (fd >= 0) {
            ::close(fd);
            fd = -1;
        }
    }
};

bool finish_bridge(core::connection& conn, tcp_bridge& br, bool* channel_ok) {
    if (br.closed) return true;
    if (!br.ch_eof_sent) {
        (void)conn.channel_eof(br.ch);
        br.ch_eof_sent = true;
    }
    (void)conn.channel_close(br.ch);
    br.closed = true;
    br.close_fd();
    *channel_ok = true;
    std::cerr << "channel_ok direct-tcpip" << std::endl;
    return true;
}

bool pump_bridge(core::connection& conn, tcp_bridge& br, bool* channel_ok) {
    if (!br.attached || br.fd < 0 || br.closed) return true;
    drain_channel(conn, br.ch, br.to_tcp);

    if (!br.to_ch.empty() && !write_channel(conn, br.ch, br.to_ch)) return false;

    if (!br.tcp_eof) {
        char buf[8 * 1024];
        const ssize_t n = ::recv(br.fd, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                std::cerr << "backend recv failed errno=" << errno << '\n';
                return false;
            }
        } else if (n == 0) {
            br.tcp_eof = true;
        } else {
            br.to_ch.append(buf, static_cast<std::size_t>(n));
            br.from_tcp += static_cast<std::size_t>(n);
            if (!write_channel(conn, br.ch, br.to_ch)) return false;
        }
    }

    while (!br.to_tcp.empty()) {
        const ssize_t n = ::send(br.fd, br.to_tcp.data(), br.to_tcp.size(), MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            std::cerr << "backend send failed errno=" << errno << '\n';
            return false;
        }
        if (n == 0) break;
        br.to_tcp.erase(0, static_cast<std::size_t>(n));
    }

    if (br.ch_eof_recv && br.to_tcp.empty() && br.fd >= 0) {
        ::shutdown(br.fd, SHUT_WR);
    }

    if (br.tcp_eof && br.to_ch.empty() && !br.ch_eof_sent) {
        if (auto ec = conn.channel_eof(br.ch)) {
            std::cerr << "channel_eof: " << ec.message() << '\n';
            return false;
        }
        br.ch_eof_sent = true;
    }

    if (br.tcp_eof && br.to_ch.empty() && (br.ch_eof_recv || br.from_tcp > 0)) {
        return finish_bridge(conn, br, channel_ok);
    }
    return true;
}

bool event_loop(int fd, core::connection& conn, auto&& handle_events, auto&& extra_fd_of,
                auto&& extra_want_write, auto&& pump_extra, bool* auth_ok, bool* channel_ok,
                auto&& teardown_ok) {
    std::vector<std::byte> inbound;
    auto done = [&] { return channel_ok && *channel_ok; };
    auto tolerate = [&] { return done() || teardown_ok(); };
    auto step = [&] {
        if (!handle_events()) return done();
        if (!flush_output(fd, conn) || !handle_events()) return done();
        if (!pump_inbound(conn, inbound, tolerate()) || !handle_events()) return done();
        if (!pump_extra()) return done();
        if (!flush_output(fd, conn) || !handle_events()) return done();
        return true;
    };
    if (!flush_output(fd, conn) || !step()) {
        return done();
    }

    using clock = std::chrono::steady_clock;
    std::optional<clock::time_point> deadline;
    int post_ok = -1;
    for (int iter = 0; iter < 10000; ++iter) {
        if (auth_ok && *auth_ok && !deadline) {
            deadline = clock::now() + k_channel_timeout;
        }
        if (done()) {
            if (post_ok < 0) post_ok = 8;
            if (post_ok-- <= 0) return true;
        } else if (deadline && clock::now() >= *deadline) {
            std::cerr << "timeout waiting for channel_ok\n";
            return false;
        }

        fd_set rfds;
        fd_set wfds;
        FD_ZERO(&rfds);
        FD_ZERO(&wfds);
        FD_SET(fd, &rfds);
        int maxfd = fd;
        const int extra = extra_fd_of();
        if (extra >= 0) {
            FD_SET(extra, &rfds);
            if (extra_want_write()) FD_SET(extra, &wfds);
            if (extra > maxfd) maxfd = extra;
        }
        timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = 50 * 1000;
        if (deadline && !done()) {
            const auto remain = std::chrono::duration_cast<std::chrono::microseconds>(*deadline
                                                                                      - clock::now());
            if (remain.count() <= 0) {
                std::cerr << "timeout waiting for channel_ok\n";
                return false;
            }
            if (remain.count() < tv.tv_usec) {
                tv.tv_usec = static_cast<suseconds_t>(remain.count());
            }
        }
        const int sel = ::select(maxfd + 1, &rfds, extra >= 0 ? &wfds : nullptr, nullptr, &tv);
        if (sel < 0) {
            std::cerr << "select failed\n";
            return false;
        }
        if (sel > 0 && FD_ISSET(fd, &rfds)) {
            if (!read_into(fd, conn, inbound, tolerate()) || !step()) {
                return done();
            }
        } else if (!step()) {
            return done();
        }
    }
    return done();
}

enum class client_phase : std::uint8_t {
    wait_auth,
    wait_opened,
    wait_pty,
    wait_shell,
    wait_data,
    closing,
};

int run_client(const options& opt, crypto::provider p, keys::private_key& ident) {
    std::string_view kex, hostkey, cipher;
    const core::config cfg = pinned_config(kex, hostkey, cipher);
    testing::recording_handler handler;
    core::connection conn{core::role::client, p, cfg, handler};

    const int fd = connect_tcp(opt.host, opt.port);
    if (fd < 0) {
        std::cerr << "connect failed to " << opt.host << ":" << opt.port << " errno=" << errno
                  << '\n';
        return 1;
    }

    bool handshake_done = false;
    bool auth_started = false;
    bool auth_ok = false;
    bool channel_ok = false;
    client_phase phase = client_phase::wait_auth;
    core::channel_ref open_id{};
    core::channel_ref ch_id{};
    std::string pending_write;
    std::string acc;

    auto start_open = [&]() -> std::error_code {
        channels::channel_open_spec spec;
        if (opt.scenario == "direct-tcpip") {
            spec.type = channels::channel_type::direct_tcpip;
            spec.host = opt.forward_host;
            spec.port = static_cast<std::uint32_t>(opt.forward_port);
            spec.originator_host = "127.0.0.1";
            spec.originator_port = 1;
        }
        return conn.open_channel(spec, nullptr, open_id);
    };

    auto maybe_succeed = [&](std::string_view label) {
        if (auto ec = conn.channel_eof(ch_id)) {
            std::cerr << "channel_eof: " << ec.message() << '\n';
            return false;
        }
        if (auto ec = conn.channel_close(ch_id)) {
            std::cerr << "channel_close: " << ec.message() << '\n';
            return false;
        }
        channel_ok = true;
        phase = client_phase::closing;
        std::cerr << "channel_ok " << label << std::endl;
        return true;
    };

    auto handle_events = [&] {
        bool stop = false;
        auto on_legacy = [&](const testing::legacy_event& ev) {
            if (stop) return;
            if (ev.type == testing::legacy_event_type::auth_response) {
                if (!ev.auth.success) {
                    std::cerr << "auth failed methods=" << ev.auth.methods << '\n';
                    stop = true;
                    return;
                }
                auth_ok = true;
                std::cerr << "auth_ok publickey\n";
                if (auto ec = start_open()) {
                    std::cerr << "open_channel failed: " << ec.message() << '\n';
                    stop = true;
                    return;
                }
                phase = client_phase::wait_opened;
            } else if (ev.type == testing::legacy_event_type::channel_open_request) {
                conn.resolve(ev.inbound_open, channels::channel_open_verdict::rejected(
                                         channels::channel_open_reason::administratively_prohibited, "no"));
            } else if (ev.type == testing::legacy_event_type::channel_request) {
                conn.resolve(ev.channel_req, true);
            } else if (ev.type == testing::legacy_event_type::global_request) {
                conn.resolve(ev.global_req, ev.request_type == "tcpip-forward");
            } else if (ev.type == testing::legacy_event_type::channel_open_failed) {
                std::cerr << "channel_open_failed reason=" << static_cast<unsigned>(ev.open_reason)
                          << " " << ev.text << '\n';
                stop = true;
            } else if (ev.type == testing::legacy_event_type::channel_opened) {
                if (phase != client_phase::wait_opened) return;
                ch_id = ev.ref;
                if (opt.scenario == "pty-shell") {
                    channels::pty_spec pty;
                    pty.term = "xterm-256color";
                    pty.width = 80;
                    pty.height = 24;
                    if (auto ec = conn.request_pty(ch_id, pty)) {
                        std::cerr << "request_pty failed: " << ec.message() << '\n';
                        stop = true;
                        return;
                    }
                    phase = client_phase::wait_pty;
                } else {
                    pending_write.assign(k_ping);
                    if (!write_channel(conn, ch_id, pending_write)) stop = true;
                    phase = client_phase::wait_data;
                }
            } else if (ev.type == testing::legacy_event_type::channel_response) {
                if (!ev.request_success) {
                    std::cerr << "channel_response failure id=" << ev.ref.index << '\n';
                    stop = true;
                    return;
                }
                if (phase == client_phase::wait_pty) {
                    if (auto ec = conn.request_shell(ch_id)) {
                        std::cerr << "request_shell failed: " << ec.message() << '\n';
                        stop = true;
                        return;
                    }
                    phase = client_phase::wait_shell;
                } else if (phase == client_phase::wait_shell) {
                    pending_write.assign(k_pty_script);
                    if (!write_channel(conn, ch_id, pending_write)) stop = true;
                    phase = client_phase::wait_data;
                }
            } else if (ev.type == testing::legacy_event_type::channel_readable) {
                drain_channel(conn, ev.ref, acc);
                if (phase == client_phase::wait_data) {
                    if (opt.scenario == "pty-shell" && acc.find(k_pty_marker) != std::string::npos) {
                        if (!maybe_succeed("pty-shell")) stop = true;
                    } else if (opt.scenario == "direct-tcpip"
                               && acc.find("PONG") != std::string::npos) {
                        if (!maybe_succeed("direct-tcpip")) stop = true;
                    }
                }
            } else if (ev.type == testing::legacy_event_type::channel_writable) {
                if (ch_id.seq != 0 && !pending_write.empty()
                    && !write_channel(conn, ch_id, pending_write)) {
                    stop = true;
                }
            }
        };
        // Peer, host key, and handshake are not on legacy_event. Everything else
        // is dispatched in arrival order so a later disconnect cannot drop it.
        while (!handler.events.empty() && !stop) {
            auto hev = std::move(handler.events.front());
            handler.events.erase(handler.events.begin());
            if (const auto* peer =
                    std::get_if<testing::recording_handler::peer_identification>(&hev)) {
                std::cerr << "peer: " << peer->banner << '\n';
            } else if (const auto* host =
                           std::get_if<testing::recording_handler::verify_host_key>(&hev)) {
                conn.resolve(host->ticket, core::host_key_verdict::accept);
                if (!flush_output(fd, conn)) return false;
            } else if (std::holds_alternative<testing::recording_handler::handshake_done>(hev)) {
                handshake_done = true;
                std::cerr << "handshake_done\n";
                if (!auth_started) {
                    if (auto ec = conn.auth_publickey(opt.user, ident.pub().blob(), ident.material())) {
                        std::cerr << "auth_publickey failed: " << ec.message() << '\n';
                        return false;
                    }
                    auth_started = true;
                }
            } else if (std::holds_alternative<testing::recording_handler::disconnected>(hev)) {
                return channel_ok;
            } else {
                testing::legacy_event::scratch scratch;
                if (auto ev = testing::legacy_event_from_recorded(hev, scratch)) on_legacy(*ev);
            }
        }
        if (stop) return false;
        return !conn.failure() || channel_ok;
    };

    auto extra_fd_of = [] { return -1; };
    auto extra_want_write = [] { return false; };
    auto pump_extra = [&] {
        if (ch_id.seq != 0 && !pending_write.empty()) {
            return write_channel(conn, ch_id, pending_write);
        }
        return true;
    };
    auto teardown_ok = [&] { return false; };

    const bool ok =
        event_loop(fd, conn, handle_events, extra_fd_of, extra_want_write, pump_extra, &auth_ok,
                   &channel_ok, teardown_ok);
    (void)flush_output(fd, conn);
    ::close(fd);
    if (!ok || !channel_ok) {
        std::cerr << "client channel did not succeed handshake_done=" << handshake_done
                  << " auth_ok=" << auth_ok << " scenario=" << opt.scenario << '\n';
        return 1;
    }
    return 0;
}

int run_server(const options& opt, crypto::provider p, keys::private_key& host,
               const keys::public_key& authorized) {
    const int lfd = listen_tcp(opt.listen);
    if (lfd < 0) {
        std::cerr << "listen failed on " << opt.listen << " errno=" << errno << '\n';
        return 1;
    }
    std::cerr << "listening " << opt.listen << std::endl;

    const int fd = accept_tcp(lfd);
    ::close(lfd);
    if (fd < 0) {
        std::cerr << "accept failed errno=" << errno << '\n';
        return 1;
    }

    std::string_view kex, hostkey, cipher;
    const core::config cfg = pinned_config(kex, hostkey, cipher);
    testing::recording_handler handler;
    core::connection conn{core::role::server, p, cfg, handler};
    if (auto ec = conn.set_host_key(host.pub().blob(), host.material())) {
        std::cerr << "set_host_key failed: " << ec.message() << '\n';
        ::close(fd);
        return 1;
    }

    bool handshake_done = false;
    bool auth_ok = false;
    bool channel_ok = false;
    tcp_bridge bridge;
    bool exec_done = false;

    auto reject_auth = [&](core::auth_ticket id) {
        conn.resolve(id, auth_verdict::failure(k_methods));
    };

    auto handle_events = [&] {
        bool stop = false;
        auto on_legacy = [&](const testing::legacy_event& ev) {
            if (stop) return;
            if (ev.type == testing::legacy_event_type::channel_open_request) {
                const std::string open_type{ev.request_type};
                const auto t = channels::parse_type(open_type);
                if (t == channels::channel_type::session) {
                    conn.resolve(ev.inbound_open, channels::channel_open_verdict::accepted());
                } else if (t == channels::channel_type::direct_tcpip) {
                    const std::string tcp_host{ev.tcp_host};
                    const auto tcp_port = static_cast<int>(ev.tcp_port);
                    const auto local = ev.ref;
                    const int bfd = connect_tcp(tcp_host, tcp_port);
                    if (bfd < 0) {
                        std::cerr << "backend connect failed " << tcp_host << ":" << tcp_port
                                  << " errno=" << errno << '\n';
                        conn.resolve(ev.inbound_open, channels::channel_open_verdict::rejected(
                                                 channels::channel_open_reason::connect_failed, "connect"));
                        stop = true;
                        return;
                    }
                    bridge.fd = bfd;
                    bridge.ch = local;
                    bridge.attached = true;
                    conn.resolve(ev.inbound_open, channels::channel_open_verdict::accepted());
                } else {
                    conn.resolve(ev.inbound_open,
                                 channels::channel_open_verdict::rejected(
                                     channels::channel_open_reason::unknown_channel_type, "no"));
                }
            } else if (ev.type == testing::legacy_event_type::channel_request) {
                const std::string req_type{ev.request_type};
                std::string cmd;
                if (req_type == "exec") {
                    std::string_view v;
                    if (channels::decode_exec(ev.request_payload, v)) {
                        cmd.assign(v.begin(), v.end());
                    }
                }
                conn.resolve(ev.channel_req, true);
                if (req_type == "exec" && (cmd == "true" || cmd.empty()) && !exec_done) {
                    if (auto ec = conn.send_exit_status(ev.ref, 0)) {
                        std::cerr << "send_exit_status: " << ec.message() << '\n';
                        stop = true;
                        return;
                    }
                    if (auto ec = conn.channel_eof(ev.ref)) {
                        std::cerr << "channel_eof: " << ec.message() << '\n';
                        stop = true;
                        return;
                    }
                    if (auto ec = conn.channel_close(ev.ref)) {
                        std::cerr << "channel_close: " << ec.message() << '\n';
                        stop = true;
                        return;
                    }
                    exec_done = true;
                    if (opt.scenario == "exec-true") {
                        channel_ok = true;
                        std::cerr << "channel_ok exec-true" << std::endl;
                    }
                }
            } else if (ev.type == testing::legacy_event_type::global_request) {
                conn.resolve(ev.global_req, ev.request_type == "tcpip-forward");
            } else if (ev.type == testing::legacy_event_type::channel_readable) {
                if (bridge.attached && ev.ref == bridge.ch) {
                    drain_channel(conn, ev.ref, bridge.to_tcp);
                }
            } else if (ev.type == testing::legacy_event_type::channel_writable) {
                if (bridge.attached && ev.ref == bridge.ch && !bridge.to_ch.empty()) {
                    if (!write_channel(conn, bridge.ch, bridge.to_ch)) stop = true;
                }
            } else if (ev.type == testing::legacy_event_type::channel_eof) {
                if (bridge.attached && ev.ref == bridge.ch) {
                    drain_channel(conn, ev.ref, bridge.to_tcp);
                    bridge.ch_eof_recv = true;
                    if (bridge.fd >= 0) ::shutdown(bridge.fd, SHUT_WR);
                }
            } else if (ev.type == testing::legacy_event_type::channel_closed) {
                if (bridge.attached && ev.ref == bridge.ch && !bridge.closed
                    && (bridge.from_tcp > 0 || bridge.ch_eof_recv)) {
                    (void)finish_bridge(conn, bridge, &channel_ok);
                }
            }
        };
        // handshake_done is not on legacy_event. Auth is read from the
        // recording_handler record: legacy_event only keeps the ticket.
        while (!handler.events.empty() && !stop) {
            auto hev = std::move(handler.events.front());
            handler.events.erase(handler.events.begin());
            if (const auto* peer =
                    std::get_if<testing::recording_handler::peer_identification>(&hev)) {
                std::cerr << "peer: " << peer->banner << '\n';
            } else if (std::holds_alternative<testing::recording_handler::handshake_done>(hev)) {
                handshake_done = true;
                std::cerr << "handshake_done\n";
            } else if (std::holds_alternative<testing::recording_handler::disconnected>(hev)) {
                if (bridge.attached && !bridge.closed && bridge.from_tcp > 0) {
                    (void)finish_bridge(conn, bridge, &channel_ok);
                }
                return channel_ok;
            } else if (const auto* req =
                           std::get_if<testing::recording_handler::auth_request>(&hev)) {
                if (req->user != opt.user) {
                    reject_auth(req->ticket);
                } else if (req->method == "publickey") {
                    if (blob_eq(req->public_blob, authorized.blob())) {
                        conn.resolve(req->ticket, auth_verdict::success());
                        if (req->has_signature) {
                            auth_ok = true;
                            std::cerr << "auth_ok publickey" << std::endl;
                        }
                    } else {
                        reject_auth(req->ticket);
                    }
                } else {
                    reject_auth(req->ticket);
                }
                if (!flush_output(fd, conn)) return false;
            } else {
                testing::legacy_event::scratch scratch;
                if (auto ev = testing::legacy_event_from_recorded(hev, scratch)) on_legacy(*ev);
            }
        }
        if (stop) return false;
        if (conn.failure() && channel_ok) return true;
        if (conn.failure() && bridge.attached && !bridge.closed && bridge.from_tcp > 0) {
            (void)finish_bridge(conn, bridge, &channel_ok);
            return channel_ok;
        }
        return !conn.failure();
    };

    auto extra_fd_of = [&] { return bridge.fd; };
    auto extra_want_write = [&] { return bridge.fd >= 0 && !bridge.to_tcp.empty(); };
    auto pump_extra = [&] { return pump_bridge(conn, bridge, &channel_ok); };
    auto teardown_ok = [&] { return auth_ok && bridge.attached; };

    const bool ok =
        event_loop(fd, conn, handle_events, extra_fd_of, extra_want_write, pump_extra, &auth_ok,
                   &channel_ok, teardown_ok);
    (void)flush_output(fd, conn);
    bridge.close_fd();
    ::close(fd);
    (void)handshake_done;
    if (!ok || !channel_ok) {
        std::cerr << "server channel did not succeed auth_ok=" << auth_ok
                  << " scenario=" << opt.scenario << '\n';
        return 1;
    }
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    std::cerr << std::unitbuf;
    options opt;
    if (!parse_args(argc, argv, opt)) {
        usage(argv[0]);
        return 2;
    }

    crypto::openssl_backend backend;
    crypto::provider p = crypto::provider::wrap(backend);

    if (opt.mode == "client") {
        keys::private_key ident;
        if (auto ec = load_private(opt.identity, p, ident)) {
            std::cerr << "parse identity: " << ec.message() << '\n';
            return 1;
        }
        return run_client(opt, p, ident);
    }

    keys::private_key host;
    if (auto ec = load_private(opt.host_key, p, host)) {
        std::cerr << "parse host-key: " << ec.message() << '\n';
        return 1;
    }
    keys::public_key authorized;
    if (auto ec = load_authorized(opt.authorized, authorized)) {
        std::cerr << "parse authorized: " << ec.message() << '\n';
        return 1;
    }
    return run_server(opt, p, host, authorized);
}
