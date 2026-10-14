#include "server.h"

#include "net.h"
#include "proc.h"
#include "report.h"

#include <yanterm-ssh/channel.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/keys/authorized_keys.hpp>
#include <yanterm-ssh/keys/fingerprint.hpp>
#include <yanterm-ssh/keys/io.hpp>
#include <yanterm-ssh/keys/private_key.hpp>
#include <yanterm-ssh/options.hpp>
#include <yanterm-ssh/session.hpp>

#include <auv/error.hpp>
#include <auv/stream.hpp>
#include <auv/uv.hpp>
#include <corral/corral.h>
#include <uv.h>

#include <algorithm>
#include <array>
#include <iostream>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace ssh = yanterm::ssh;
namespace crypto = yanterm::ssh::crypto;
namespace keys = yanterm::ssh::keys;

namespace bench {
namespace {

void apply_options(ssh::session_options& o, const server_config& cfg) {
    if (!cfg.algo.kex.empty()) o.preferred_kex = cfg.algo.kex;
    if (!cfg.algo.cipher.empty()) o.preferred_cipher = cfg.algo.cipher;
    if (!cfg.algo.mac.empty()) o.preferred_mac = cfg.algo.mac;
    if (!cfg.algo.hostkey.empty()) o.preferred_host_key = cfg.algo.hostkey;
    o.initial_window = cfg.tuning.initial_window;
    o.max_channel_packet = cfg.tuning.max_packet;
    o.rekey_bytes = cfg.tuning.rekey_bytes;
}

std::string allowed_methods(const server_config& cfg, const keys::authorized_keys& authorized) {
    std::string methods;
    auto add = [&](std::string_view m) {
        if (!methods.empty()) methods.push_back(',');
        methods.append(m);
    };
    if (!cfg.password.empty()) add("password");
    bool have_key = false;
    for (const auto& line : authorized.lines()) {
        if (line.key) {
            have_key = true;
            break;
        }
    }
    if (have_key) add("publickey");
    if (methods.empty()) add("password");
    return methods;
}

bool user_ok(const server_config& cfg, std::string_view user) {
    return cfg.user.empty() || user == cfg.user;
}

bool public_blob_authorized(const keys::authorized_keys& authorized,
                            std::span<const std::byte> blob) {
    for (const auto& line : authorized.lines()) {
        if (!line.key) continue;
        const auto kb = line.key->blob();
        if (kb.size() == blob.size() && std::equal(kb.begin(), kb.end(), blob.begin())) {
            return true;
        }
    }
    return false;
}

constexpr std::size_t k_pump_buf = 65536;

corral::Task<void> pump_stdout_to_channel(piped_child& child, ssh::channel& ch,
                                          std::uint64_t& to_client) {
    std::array<char, k_pump_buf> buf{};
    auto to = auv::stream::borrow(ch);
    for (;;) {
        auto [ec, n] = co_await child.stdout_stream().read(
            [&] { return auv::buffer(buf.data(), buf.size()); });
        if (n == 0 || ec) co_return;
        auv::buffer wb{buf.data(), n};
        auto wec = co_await to.write(&wb, std::size_t{1});
        if (wec) {
            child.terminate();
            co_return;
        }
        to_client += n;
    }
}

corral::Task<void> pump_stderr_to_channel(piped_child& child, ssh::channel& ch,
                                          std::uint64_t& to_client) {
    std::array<char, k_pump_buf> buf{};
    for (;;) {
        auto [ec, n] = co_await child.stderr_stream().read(
            [&] { return auv::buffer(buf.data(), buf.size()); });
        if (n == 0 || ec) co_return;
        auv::buffer wb{buf.data(), n};
        auto wec = co_await ch.write_stderr(&wb, std::size_t{1});
        if (wec) {
            child.terminate();
            co_return;
        }
        to_client += n;
    }
}

corral::Task<void> pump_channel_to_stdin(ssh::channel& ch, piped_child& child,
                                         std::uint64_t& to_process) {
    std::array<char, k_pump_buf> buf{};
    auto from = auv::stream::borrow(ch);
    for (;;) {
        auto [ec, n] = co_await from.read([&] { return auv::buffer(buf.data(), buf.size()); });
        if (n == 0 || ec) {
            (void)co_await child.stdin_stream().shutdown();
            if (ec && ec != auv::errc::eof) child.terminate();
            co_return;
        }
        auv::buffer wb{buf.data(), n};
        auto wec = co_await child.stdin_stream().write(&wb, std::size_t{1});
        if (wec) {
            child.terminate();
            co_return;
        }
        to_process += n;
    }
}

corral::Task<void> pump_pty_to_channel(pty_child& child, ssh::channel& ch, std::uint64_t& to_client) {
    std::array<char, k_pump_buf> buf{};
    auto to = auv::stream::borrow(ch);
    for (;;) {
        auto [ec, n] = co_await child.io_stream().read(
            [&] { return auv::buffer(buf.data(), buf.size()); });
        if (n == 0 || ec) co_return;
        auv::buffer wb{buf.data(), n};
        auto wec = co_await to.write(&wb, std::size_t{1});
        if (wec) {
            child.terminate();
            co_return;
        }
        to_client += n;
    }
}

corral::Task<void> pump_channel_to_pty(ssh::channel& ch, pty_child& child,
                                       std::uint64_t& to_process) {
    std::array<char, k_pump_buf> buf{};
    auto from = auv::stream::borrow(ch);
    for (;;) {
        auto [ec, n] = co_await from.read([&] { return auv::buffer(buf.data(), buf.size()); });
        if (n == 0 || ec) {
            (void)co_await child.io_stream().shutdown();
            if (ec && ec != auv::errc::eof) child.terminate();
            co_return;
        }
        auv::buffer wb{buf.data(), n};
        auto wec = co_await child.io_stream().write(&wb, std::size_t{1});
        if (wec) {
            child.terminate();
            co_return;
        }
        to_process += n;
    }
}

corral::Task<void> handle_session(uv_loop_t& loop, ssh::channel ch) {
    command_spec spec;
    std::unique_ptr<piped_child> child;
    std::unique_ptr<pty_child> pty;
    bool want_pty = false;
    std::string pty_term = "xterm";
    pty_geometry pty_geo{};
    channel_transfer xfer;
    const uint64_t t0 = uv_hrtime();
    corral::Event child_started;
    corral::Event requests_done;
    std::uint32_t exit_status = 0;
    std::string exit_sig;

    struct report_line {
        channel_transfer* xfer;
        uint64_t t0;
        ~report_line() {
            xfer->seconds = static_cast<double>(uv_hrtime() - t0) / 1.0e9;
            print_channel_transfer("session", *xfer);
        }
    } report{&xfer, t0};

    auto reqs = ch.serve_requests(
        [&](ssh::inbound_channel_request req) -> corral::Task<bool> {
            if (req.type() == "env") {
                auto ev = req.env();
                if (!ev) co_return false;
                spec.env.emplace_back(std::string{ev->first}, std::string{ev->second});
                co_return true;
            }
            if (req.type() == "subsystem") co_return false;
            if (req.type() == "pty-req") {
#ifdef _WIN32
                co_return false;
#else
                if (child || pty) co_return false;
                auto p = req.pty();
                if (!p) co_return false;
                pty_term.assign(p->term.begin(), p->term.end());
                if (pty_term.empty()) pty_term = "xterm";
                pty_geo = pty_geometry{p->width, p->height, p->pixel_width, p->pixel_height};
                want_pty = true;
                co_return true;
#endif
            }
            if (req.type() == "window-change") {
                auto ws = req.window_change();
                if (!ws || !want_pty) co_return false;
                pty_geo = pty_geometry{ws->cols, ws->rows, ws->pixel_width, ws->pixel_height};
                if (!pty) co_return true;
                co_return !pty->resize(pty_geo);
            }
            if (req.type() == "signal") {
                auto name = req.signal();
                if (!name) co_return false;
                if (pty) {
                    pty->send_signal(*name);
                    co_return true;
                }
                if (!child) co_return false;
                child->send_signal(*name);
                co_return true;
            }
            if (req.type() == "exec" || req.type() == "shell") {
                if (child || pty) co_return false;
                if (req.type() == "exec") {
                    auto cmd = req.exec_command();
                    if (!cmd) co_return false;
                    spec.command.assign(cmd->begin(), cmd->end());
                } else {
                    spec.command.clear();
                }
                if (want_pty) {
                    auto [ec, started] = pty_child::start(loop, spec, pty_term, pty_geo);
                    if (ec || !started) co_return false;
                    pty = std::move(started);
                } else {
                    auto [ec, started] = piped_child::start(loop, spec);
                    if (ec || !started) co_return false;
                    child = std::move(started);
                }
                child_started.trigger();
                co_return true;
            }
            co_return false;
        });

    CORRAL_WITH_NURSERY(n) {
        n.start([&]() -> corral::Task<void> {
            co_await std::move(reqs);
            requests_done.trigger();
        });

        co_await corral::anyOf(child_started, requests_done);
        if (!child && !pty) co_return corral::join;

        struct killer {
            piped_child* c;
            pty_child* t;
            ~killer() {
                if (c) c->terminate();
                if (t) t->terminate();
            }
        } kill{child.get(), pty.get()};

        // child.wait() can return while output bytes remain. anyOf cancels
        // only channel→process; allOf joins process→channel until EOF, then
        // send_exit_* (spec §4.1).
        if (pty) {
            co_await corral::allOf(
                pump_pty_to_channel(*pty, ch, xfer.to_client_bytes),
                [&]() -> corral::Task<void> {
                    co_await corral::anyOf(
                        pump_channel_to_pty(ch, *pty, xfer.to_process_bytes), pty->wait());
                    std::tie(exit_status, exit_sig) = co_await pty->wait();
                });
        } else {
            co_await corral::allOf(
                pump_stdout_to_channel(*child, ch, xfer.to_client_bytes),
                pump_stderr_to_channel(*child, ch, xfer.to_client_bytes),
                [&]() -> corral::Task<void> {
                    co_await corral::anyOf(
                        pump_channel_to_stdin(ch, *child, xfer.to_process_bytes), child->wait());
                    std::tie(exit_status, exit_sig) = co_await child->wait();
                });
        }

        if (!exit_sig.empty()) {
            ssh::exit_signal sig;
            sig.name = exit_sig;
            (void)co_await ch.send_exit_signal(sig);
        } else {
            (void)co_await ch.send_exit_status(exit_status);
        }
        (void)co_await ch.shutdown();
        co_await ch.close();
        co_return corral::cancel;
    };
}

corral::Task<void> handle_direct_tcpip(uv_loop_t& loop, ssh::inbound_channel_open open) {
    auto [ec, sock] = co_await tcp_connect(loop, open.host(), static_cast<int>(open.port()));
    if (ec) {
        open.reject(ssh::channel_open_reason::connect_failed, ec.message());
        co_return;
    }
    ssh::channel ch = open.accept();
    channel_transfer xfer;
    const uint64_t t0 = uv_hrtime();
    struct report_line {
        channel_transfer* xfer;
        uint64_t t0;
        ~report_line() {
            xfer->seconds = static_cast<double>(uv_hrtime() - t0) / 1.0e9;
            print_channel_transfer("direct-tcpip", *xfer);
        }
    } report{&xfer, t0};

    auto chs = auv::stream::borrow(ch);
    CORRAL_WITH_NURSERY(n) {
        n.start([&]() -> corral::Task<void> {
            std::array<char, k_pump_buf> buf{};
            for (;;) {
                auto [rec, nread] =
                    co_await chs.read([&] { return auv::buffer(buf.data(), buf.size()); });
                if (nread == 0 && !rec) continue;
                if (nread == 0 || rec) {
                    (void)co_await sock.shutdown();
                    co_return;
                }
                auv::buffer wb{buf.data(), nread};
                auto wec = co_await sock.write(&wb, std::size_t{1});
                if (wec) {
                    (void)co_await sock.shutdown();
                    (void)co_await chs.shutdown();
                    co_return;
                }
                xfer.to_process_bytes += nread;
            }
        });
        n.start([&]() -> corral::Task<void> {
            std::array<char, k_pump_buf> buf{};
            for (;;) {
                auto [rec, nread] =
                    co_await sock.read([&] { return auv::buffer(buf.data(), buf.size()); });
                if (nread == 0 && !rec) continue;
                if (nread == 0 || rec) {
                    (void)co_await chs.shutdown();
                    co_return;
                }
                auv::buffer wb{buf.data(), nread};
                auto wec = co_await chs.write(&wb, std::size_t{1});
                if (wec) {
                    (void)co_await sock.shutdown();
                    (void)co_await chs.shutdown();
                    co_return;
                }
                xfer.to_client_bytes += nread;
            }
        });
        co_return corral::join;
    };
    (void)co_await ch.shutdown();
    co_await ch.close();
}

corral::Task<void> serve_connection(uv_loop_t& loop, auv::stream stream, crypto::provider p,
                                    std::span<const std::byte> host_key_blob,
                                    const server_config& cfg,
                                    const keys::authorized_keys& authorized) {
    keys::private_key hk;
    if (auto ec = keys::private_key::parse(host_key_blob, p, {}, hk)) {
        std::cerr << "host-key parse failed: " << ec.message() << std::endl;
        co_return;
    }

    ssh::server_options so;
    apply_options(so, cfg);
    so.host_keys.push_back(std::move(hk));
    ssh::server_session ss{std::move(stream), p, std::move(so)};
    const uint64_t t0 = uv_hrtime();

    CORRAL_WITH_NURSERY(n) {
        co_await n.start(&ssh::server_session::run, &ss);
        if (auto ec = co_await ss.handshake()) {
            std::cerr << "handshake failed: " << ec.message() << std::endl;
            co_return corral::cancel;
        }
        const auto methods = allowed_methods(cfg, authorized);
        const auto auth_ec = co_await ss.authenticate(
            [&](ssh::auth_request req) -> corral::Task<ssh::auth_verdict> {
                if (!user_ok(cfg, req.user())) {
                    co_return ssh::auth_verdict::failure(methods);
                }
                if (req.method() == "password") {
                    if (!cfg.password.empty() && req.password() == cfg.password) {
                        co_return ssh::auth_verdict::success();
                    }
                    co_return ssh::auth_verdict::failure(methods);
                }
                if (req.method() == "publickey") {
                    if (public_blob_authorized(authorized, req.public_blob())) {
                        // Unsigned query → USERAUTH_PK_OK via success() (facade
                        // does not treat that as authenticated). Signed → done.
                        co_return ssh::auth_verdict::success();
                    }
                    co_return ssh::auth_verdict::failure(methods);
                }
                co_return ssh::auth_verdict::failure(methods);
            });
        if (auth_ec) {
            std::cerr << "auth failed: " << auth_ec.message() << std::endl;
            co_return corral::cancel;
        }
        const uint64_t t1 = uv_hrtime();
        std::cerr << "authenticated user=" << (cfg.user.empty() ? "-" : cfg.user) << " "
                  << (static_cast<double>(t1 - t0) / 1.0e6) << " ms" << std::endl;
        co_await ss.serve(
            [&](ssh::inbound_channel_open open) -> corral::Task<void> {
                if (open.type() == ssh::channel_type::session) {
                    ssh::channel ch = open.accept();
                    if (!ch) co_return;
                    co_await handle_session(loop, std::move(ch));
                    co_return;
                }
                if (open.type() == ssh::channel_type::direct_tcpip) {
                    co_await handle_direct_tcpip(loop, std::move(open));
                    co_return;
                }
                open.reject(ssh::channel_open_reason::unknown_channel_type, "unsupported");
            },
            [](ssh::inbound_global_request req) -> corral::Task<void> {
                req.reject();
                co_return;
            });
        co_return corral::join;
    };
}

}  // namespace

crypto::sig_id host_key_sig_for_algo(std::string_view algo) {
    if (algo == "sm2") return crypto::sig_id::sm2_za;
    if (algo.find("ecdsa-sha2-nistp521") != std::string_view::npos) {
        return crypto::sig_id::ecdsa_nistp521;
    }
    if (algo.find("ecdsa-sha2-nistp384") != std::string_view::npos) {
        return crypto::sig_id::ecdsa_nistp384;
    }
    if (algo.find("ecdsa") != std::string_view::npos) return crypto::sig_id::ecdsa_nistp256;
    if (algo.find("rsa") != std::string_view::npos) return crypto::sig_id::rsa_pkcs1_sha256;
    return crypto::sig_id::ed25519;
}

int run_server(const server_config& cfg) {
    crypto::openssl_backend backend;
    auto p = crypto::provider::wrap(backend);

    keys::private_key host_key;
    if (!cfg.host_key_path.empty()) {
        if (auto ec = keys::io::load_private_key(cfg.host_key_path.c_str(), p, {}, host_key)) {
            std::cerr << "failed to load --host-key: " << ec.message() << '\n';
            return 1;
        }
    } else if (auto ec = keys::private_key::generate(
                   p, host_key_sig_for_algo(cfg.algo.hostkey), 0, "bench", host_key)) {
        std::cerr << "host-key generate failed: " << ec.message() << '\n';
        return 1;
    } else {
        std::cerr << "host-key " << keys::fingerprint_sha256(p, host_key.pub()) << std::endl;
    }

    std::vector<std::byte> host_key_blob;
    if (auto ec = host_key.serialize(p, {}, "none", host_key_blob)) {
        std::cerr << "host-key serialize failed: " << ec.message() << '\n';
        return 1;
    }

    keys::authorized_keys authorized;
    if (!cfg.authorized_path.empty()) {
        std::vector<std::byte> text;
        if (auto ec = keys::io::read_file(cfg.authorized_path.c_str(), text)) {
            std::cerr << "failed to read --authorized: " << ec.message() << '\n';
            return 1;
        }
        const std::string_view sv{reinterpret_cast<const char*>(text.data()), text.size()};
        if (auto ec = keys::authorized_keys::parse(sv, authorized)) {
            std::cerr << "failed to parse --authorized: " << ec.message() << '\n';
            return 1;
        }
    }

    uv_loop_t loop{};
    if (uv_loop_init(&loop) < 0) {
        std::cerr << "uv_loop_init failed\n";
        return 1;
    }

    const int rc = corral::run(loop, [&]() -> corral::Task<int> {
        tcp_listener listener(loop, cfg.bind, cfg.port);
        if (listener.error()) {
            std::cerr << "listen failed: " << listener.error().message() << std::endl;
            co_return 1;
        }
        std::cerr << "listening " << cfg.bind << " " << listener.local_port() << std::endl;

        CORRAL_WITH_NURSERY(n) {
            for (;;) {
                auto [ec, stream] = co_await listener.accept();
                if (ec) {
                    std::cerr << "accept failed: " << ec.message() << std::endl;
                    continue;
                }
                n.start([stream = std::move(stream), p,
                         blob = std::span<const std::byte>(host_key_blob), &cfg, &authorized,
                         &loop]() mutable -> corral::Task<void> {
                    co_await serve_connection(loop, std::move(stream), p, blob, cfg, authorized);
                });
            }
            co_return corral::join;
        };
        co_return 0;
    }());

    drain_and_close(loop);
    return rc;
}

}  // namespace bench
