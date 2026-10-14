// TCP auth harness against OpenSSH. This is the only M3 auth code allowed to
// perform I/O; the library headers remain sans-I/O.
#include <yanterm-ssh/core/config.hpp>
#include <yanterm-ssh/core/connection.hpp>
#include <yanterm-ssh/core/types.hpp>
#include <yanterm-ssh/wire/message_ids.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/keys/private_key.hpp>

#include "recording_handler.hpp"
#include <yanterm-ssh/keys/public_key.hpp>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
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
using auth::kbdint_prompt;

namespace {

constexpr std::string_view k_kex = "curve25519-sha256";
constexpr std::string_view k_cipher = "chacha20-poly1305@openssh.com";
constexpr std::string_view k_hostkey = "ssh-ed25519";
constexpr std::string_view k_mac = "hmac-sha2-256";
constexpr std::string_view k_methods = "publickey,password,keyboard-interactive";

struct options {
    std::string mode;
    std::string host = "127.0.0.1";
    int port = 22;
    int listen = 0;
    std::string user;
    std::string identity;
    std::string host_key;
    std::string authorized;
    std::string kex;
    std::string cipher;
    std::string hostkey_alg;
    std::string mac;
    std::optional<std::string> password;
    std::optional<std::string> kbdint_prompt;
    std::optional<std::string> kbdint_answer;
};

void usage(const char* argv0) {
    std::cerr
        << "Usage:\n  " << argv0
        << " --mode client --host HOST --port PORT --user USER (--identity PATH | --password SECRET)\n"
        << "             [--kex NAME] [--cipher NAME] [--hostkey NAME] [--mac NAME]\n  "
        << argv0
        << " --mode server --listen PORT --host-key PATH --user USER --authorized PATH\n"
        << "             [--password SECRET] [--kbdint-prompt P --kbdint-answer A]\n"
        << "             [--kex NAME] [--cipher NAME] [--hostkey NAME] [--mac NAME]\n";
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
        } else if (a == "--kex") {
            if (!need(opt.kex)) return false;
        } else if (a == "--cipher") {
            if (!need(opt.cipher)) return false;
        } else if (a == "--hostkey") {
            if (!need(opt.hostkey_alg)) return false;
        } else if (a == "--mac") {
            if (!need(opt.mac)) return false;
        } else if (a == "--password") {
            std::string v;
            if (!need(v)) return false;
            opt.password = std::move(v);
        } else if (a == "--kbdint-prompt") {
            std::string v;
            if (!need(v)) return false;
            opt.kbdint_prompt = std::move(v);
        } else if (a == "--kbdint-answer") {
            std::string v;
            if (!need(v)) return false;
            opt.kbdint_answer = std::move(v);
        } else if (a == "--help" || a == "-h") {
            usage(argv[0]);
            std::exit(0);
        } else {
            std::cerr << "unknown arg: " << a << '\n';
            return false;
        }
    }
    if (opt.mode == "client") {
        return !opt.user.empty() && opt.port > 0
            && (!opt.identity.empty() || opt.password.has_value());
    }
    if (opt.mode == "server") {
        return !opt.user.empty() && !opt.host_key.empty() && !opt.authorized.empty()
            && opt.listen > 0;
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

core::config pinned_config(const options& opt, std::string_view& kex, std::string_view& hostkey,
                           std::string_view& cipher, std::string_view& mac) {
    kex = opt.kex.empty() ? k_kex : std::string_view{opt.kex};
    hostkey = opt.hostkey_alg.empty() ? k_hostkey : std::string_view{opt.hostkey_alg};
    cipher = opt.cipher.empty() ? k_cipher : std::string_view{opt.cipher};
    mac = opt.mac.empty() ? k_mac : std::string_view{opt.mac};
    core::config cfg;
    cfg.preferred_kex = kex;
    cfg.preferred_host_key = hostkey;
    cfg.preferred_cipher = cipher;
    cfg.preferred_mac = mac;
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
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return -1;
    }
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags >= 0) ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
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

bool pump_inbound(core::connection& conn, std::vector<std::byte>& inbound, bool tolerate_after_auth,
                  bool auth_ok) {
    for (;;) {
        std::size_t accepted = 0;
        const std::error_code ec = conn.feed(inbound, accepted);
        if (accepted > 0) {
            inbound.erase(inbound.begin(),
                          inbound.begin() + static_cast<std::ptrdiff_t>(accepted));
        }
        if (ec) {
            if (tolerate_after_auth && auth_ok) {
                std::cerr << "feed after auth_ok: " << ec.message() << '\n';
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
               bool tolerate_after_auth, bool auth_ok) {
    std::byte buf[16 * 1024];
    const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return true;
        return false;
    }
    if (n == 0) return tolerate_after_auth && auth_ok;
    inbound.insert(inbound.end(), buf, buf + n);
    return pump_inbound(conn, inbound, tolerate_after_auth, auth_ok);
}

bool blob_eq(std::span<const std::byte> a, std::span<const std::byte> b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}

bool event_loop(int fd, core::connection& conn, auto&& handle_events, bool* auth_ok,
                bool tolerate_after_auth, int extra_iters_after_ok) {
    std::vector<std::byte> inbound;
    auto ok = [&] { return auth_ok && *auth_ok; };
    auto step = [&] {
        if (!handle_events()) return ok();
        if (!flush_output(fd, conn) || !handle_events()) return ok();
        // resolve(accept) / auth verdicts may leave peer bytes unconsumed.
        if (!pump_inbound(conn, inbound, tolerate_after_auth, ok()) || !handle_events()) {
            return ok();
        }
        return true;
    };
    if (!flush_output(fd, conn) || !step()) {
        return false;
    }

    int post_ok = -1;
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
            return false;
        }
        if (sel > 0 && FD_ISSET(fd, &rfds)) {
            if (!read_into(fd, conn, inbound, tolerate_after_auth, ok()) || !step()) {
                return ok();
            }
        } else if (!step()) {
            return ok();
        }
        if (ok()) {
            if (post_ok < 0) post_ok = extra_iters_after_ok;
            if (post_ok-- <= 0) return true;
        }
    }
    return ok();
}

int run_client(const options& opt, crypto::provider p, keys::private_key* ident) {
    std::string_view kex, hostkey, cipher, mac;
    const core::config cfg = pinned_config(opt, kex, hostkey, cipher, mac);
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

    auto handle_events = [&] {
        while (!handler.events.empty()) {
            auto ev = std::move(handler.events.front());
            handler.events.erase(handler.events.begin());
            if (const auto* peer =
                    std::get_if<testing::recording_handler::peer_identification>(&ev)) {
                std::cerr << "peer: " << peer->banner << '\n';
            } else if (const auto* host =
                           std::get_if<testing::recording_handler::verify_host_key>(&ev)) {
                conn.resolve(host->ticket, core::host_key_verdict::accept);
                if (!flush_output(fd, conn)) return false;
            } else if (std::holds_alternative<testing::recording_handler::handshake_done>(ev)) {
                handshake_done = true;
                std::cerr << "handshake_done\n";
                if (!auth_started) {
                    if (ident != nullptr) {
                        if (auto ec = conn.auth_publickey(opt.user, ident->pub().blob(),
                                                          ident->material())) {
                            std::cerr << "auth_publickey failed: " << ec.message() << '\n';
                            return false;
                        }
                    } else if (opt.password) {
                        if (auto ec = conn.auth_password(opt.user, *opt.password)) {
                            std::cerr << "auth_password failed: " << ec.message() << '\n';
                            return false;
                        }
                    } else {
                        std::cerr << "no identity or password\n";
                        return false;
                    }
                    auth_started = true;
                }
            } else if (std::holds_alternative<testing::recording_handler::disconnected>(ev)) {
                return auth_ok;
            } else if (const auto* resp =
                           std::get_if<testing::recording_handler::auth_response>(&ev)) {
                if (resp->success) {
                    auth_ok = true;
                    std::cerr << "auth_ok " << (ident != nullptr ? "publickey" : "password") << '\n';
                    (void)conn.disconnect(wire::disconnect_reason::by_application, "auth ok");
                } else {
                    std::cerr << "auth failed methods=" << resp->methods << '\n';
                    return false;
                }
            }
        }
        return !conn.failure() || auth_ok;
    };

    const bool ok = event_loop(fd, conn, handle_events, &auth_ok, false, 0);
    (void)flush_output(fd, conn);
    ::close(fd);
    if (!ok || !auth_ok) {
        std::cerr << "client auth did not succeed handshake_done=" << handshake_done << '\n';
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

    std::string_view kex, hostkey, cipher, mac;
    const core::config cfg = pinned_config(opt, kex, hostkey, cipher, mac);
    testing::recording_handler handler;
    core::connection conn{core::role::server, p, cfg, handler};
    if (auto ec = conn.set_host_key(host.pub().blob(), host.material())) {
        std::cerr << "set_host_key failed: " << ec.message() << '\n';
        ::close(fd);
        return 1;
    }

    bool handshake_done = false;
    bool auth_ok = false;
    std::string auth_ok_method;

    auto reject = [&](core::auth_ticket id) {
        conn.resolve(id, auth_verdict::failure(k_methods));
    };

    auto mark_success = [&](core::auth_ticket id, std::string_view method) {
        conn.resolve(id, auth_verdict::success());
        auth_ok = true;
        auth_ok_method.assign(method.begin(), method.end());
        std::cerr << "auth_ok " << auth_ok_method << std::endl;
    };

    auto handle_events = [&] {
        while (!handler.events.empty()) {
            auto ev = std::move(handler.events.front());
            handler.events.erase(handler.events.begin());
            if (const auto* peer =
                    std::get_if<testing::recording_handler::peer_identification>(&ev)) {
                std::cerr << "peer: " << peer->banner << '\n';
            } else if (std::holds_alternative<testing::recording_handler::handshake_done>(ev)) {
                handshake_done = true;
                std::cerr << "handshake_done\n";
            } else if (std::holds_alternative<testing::recording_handler::disconnected>(ev)) {
                return auth_ok;
            } else if (const auto* req = std::get_if<testing::recording_handler::auth_request>(&ev)) {
                if (req->user != opt.user) {
                    reject(req->ticket);
                } else if (req->method == "publickey") {
                    if (blob_eq(req->public_blob, authorized.blob())) {
                        conn.resolve(req->ticket, auth_verdict::success());
                        if (req->has_signature) {
                            auth_ok = true;
                            auth_ok_method = "publickey";
                            std::cerr << "auth_ok publickey" << std::endl;
                        }
                    } else {
                        reject(req->ticket);
                    }
                } else if (req->method == "password") {
                    if (opt.password && req->password == *opt.password) {
                        mark_success(req->ticket, "password");
                    } else {
                        reject(req->ticket);
                    }
                } else if (req->method == "keyboard-interactive") {
                    if (opt.kbdint_prompt && opt.kbdint_answer) {
                        const kbdint_prompt prompts[] = {{*opt.kbdint_prompt, false}};
                        conn.resolve(req->ticket, auth_verdict::info({}, {}, prompts));
                    } else {
                        reject(req->ticket);
                    }
                } else {
                    reject(req->ticket);
                }
                if (!flush_output(fd, conn)) return auth_ok;
            } else if (const auto* info =
                           std::get_if<testing::recording_handler::auth_info_response>(&ev)) {
                const bool match = opt.kbdint_answer && !info->responses.empty()
                                   && info->responses[0] == *opt.kbdint_answer;
                if (match) {
                    mark_success(info->ticket, "keyboard-interactive");
                } else {
                    reject(info->ticket);
                }
                if (!flush_output(fd, conn)) return auth_ok;
            }
        }
        if (conn.failure() && auth_ok) return true;
        return !conn.failure();
    };

    const bool ok = event_loop(fd, conn, handle_events, &auth_ok, true, 8);
    (void)flush_output(fd, conn);
    ::close(fd);
    (void)handshake_done;
    if (!ok || !auth_ok) {
        std::cerr << "server auth did not succeed\n";
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
        if (!opt.identity.empty()) {
            keys::private_key ident;
            if (auto ec = load_private(opt.identity, p, ident)) {
                std::cerr << "parse identity: " << ec.message() << '\n';
                return 1;
            }
            return run_client(opt, p, &ident);
        }
        return run_client(opt, p, nullptr);
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
