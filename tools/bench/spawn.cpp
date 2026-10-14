#include "spawn.h"

#include "net.h"

#include <auv/uv.hpp>
#include <auv/uv/timer.hpp>
#include <corral/corral.h>
#include <uv.h>

#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace bench {
namespace {

constexpr std::string_view k_default_user = "bench";
constexpr std::string_view k_default_password = "bench";
constexpr std::string_view k_listening_prefix = "listening ";

#ifdef _WIN32
constexpr int k_kill_signal = SIGTERM;
#else
constexpr int k_kill_signal = SIGKILL;
#endif

bool parse_listening_line(std::string_view line, std::string& host, int& port) {
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
    if (!line.starts_with(k_listening_prefix)) return false;
    const auto rest = line.substr(k_listening_prefix.size());
    const auto sp = rest.rfind(' ');
    if (sp == std::string_view::npos || sp == 0 || sp + 1 >= rest.size()) return false;
    const auto host_sv = rest.substr(0, sp);
    const auto port_sv = rest.substr(sp + 1);
    if (host_sv.empty() || port_sv.empty()) return false;
    int value = 0;
    const auto [ptr, ec] = std::from_chars(port_sv.data(), port_sv.data() + port_sv.size(), value);
    if (ec != std::errc{} || ptr != port_sv.data() + port_sv.size()) return false;
    if (value <= 0 || value > 65535) return false;
    host.assign(host_sv);
    port = value;
    return true;
}

void append_kv(std::vector<std::string>& args, const char* flag, const std::string& value) {
    if (value.empty()) return;
    args.emplace_back(flag);
    args.push_back(value);
}

std::string exe_path() {
    char buf[4096];
    std::size_t n = sizeof(buf);
    const int r = uv_exepath(buf, &n);
    if (r < 0 || n == 0) return {};
    return std::string(buf, n);
}

constexpr std::string_view k_default_kex = "curve25519-sha256";
constexpr std::string_view k_default_cipher = "chacha20-poly1305@openssh.com";
constexpr std::string_view k_default_hostkey = "ssh-ed25519";
constexpr std::string_view k_default_mac = "hmac-sha2-256-etm@openssh.com,hmac-sha2-256";

std::string join_path(std::string_view dir, std::string_view name) {
#ifdef _WIN32
    const char sep = '\\';
#else
    const char sep = '/';
#endif
    if (!dir.empty() && (dir.back() == '/' || dir.back() == '\\')) {
        return std::string{dir} + std::string{name};
    }
    return std::string{dir} + sep + std::string{name};
}

std::string getenv_value(const char* name) {
    char buf[4096];
    std::size_t sz = sizeof(buf);
    const int r = uv_os_getenv(name, buf, &sz);
    if (r == 0) return std::string(buf, sz);
    if (r != UV_ENOBUFS) return {};
    std::string out(sz, '\0');
    std::size_t n = out.size();
    if (uv_os_getenv(name, out.data(), &n) != 0) return {};
    out.resize(n);
    return out;
}

bool file_is_executable(const std::string& path) {
    if (path.empty()) return false;
    uv_fs_t req{};
    const int r = uv_fs_access(nullptr, &req, path.c_str(), X_OK, nullptr);
    uv_fs_req_cleanup(&req);
    return r == 0;
}

bool file_exists(const std::string& path) {
    if (path.empty()) return false;
    uv_fs_t req{};
    const int r = uv_fs_access(nullptr, &req, path.c_str(), F_OK, nullptr);
    uv_fs_req_cleanup(&req);
    return r == 0;
}

std::string find_in_path(std::string_view name) {
    const std::string pathenv = getenv_value("PATH");
    if (pathenv.empty()) return {};
#ifdef _WIN32
    const char sep = ';';
#else
    const char sep = ':';
#endif
    std::size_t start = 0;
    while (start <= pathenv.size()) {
        auto end = pathenv.find(sep, start);
        if (end == std::string::npos) end = pathenv.size();
        const auto dir = pathenv.substr(start, end - start);
        if (!dir.empty()) {
            auto cand = join_path(dir, name);
            if (file_is_executable(cand)) return cand;
#ifdef _WIN32
            auto with_exe = cand + ".exe";
            if (file_is_executable(with_exe)) return with_exe;
#endif
        }
        if (end == pathenv.size()) break;
        start = end + 1;
    }
    return {};
}

std::string find_sshd(const std::string& explicit_path) {
    if (!explicit_path.empty()) {
        return file_is_executable(explicit_path) ? explicit_path : std::string{};
    }
    if (auto p = find_in_path("sshd"); !p.empty()) return p;
#ifdef _WIN32
    constexpr const char* k_win = "C:\\Windows\\System32\\OpenSSH\\sshd.exe";
    if (file_is_executable(k_win)) return k_win;
#else
    if (file_is_executable("/usr/sbin/sshd")) return "/usr/sbin/sshd";
#endif
    return {};
}

std::string find_ssh_keygen() {
    if (auto p = find_in_path("ssh-keygen"); !p.empty()) return p;
#ifdef _WIN32
    constexpr const char* k_win = "C:\\Windows\\System32\\OpenSSH\\ssh-keygen.exe";
    if (file_is_executable(k_win)) return k_win;
#else
    if (file_is_executable("/usr/bin/ssh-keygen")) return "/usr/bin/ssh-keygen";
#endif
    return {};
}

std::string make_temp_dir() {
    char tbuf[512];
    std::size_t tsz = sizeof(tbuf);
    std::string tmpdir;
    if (uv_os_tmpdir(tbuf, &tsz) == 0) tmpdir.assign(tbuf, tsz);
#ifdef _WIN32
    if (tmpdir.empty()) tmpdir = "C:\\Windows\\Temp";
#else
    if (tmpdir.empty()) tmpdir = "/tmp";
#endif
    std::string tmpl = join_path(tmpdir, "yanterm-ssh-bench-XXXXXX");
    uv_fs_t req{};
    const int r = uv_fs_mkdtemp(nullptr, &req, tmpl.data(), nullptr);
    std::string out;
    if (r == 0 && req.path) out = req.path;
    uv_fs_req_cleanup(&req);
    return out;
}

void remove_tree(const std::string& path) {
    if (path.empty()) return;
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
}

void dump_file_stderr(const std::string& path) {
    std::ifstream in(path);
    if (!in) return;
    std::cerr << in.rdbuf();
    if (!std::cerr.good()) std::cerr.clear();
}

int pick_free_port() {
#ifdef _WIN32
    SOCKET fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd == INVALID_SOCKET) return 0;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::closesocket(fd);
        return 0;
    }
    sockaddr_in got{};
    int len = sizeof(got);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&got), &len) != 0) {
        ::closesocket(fd);
        return 0;
    }
    ::closesocket(fd);
    return ntohs(got.sin_port);
#else
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return 0;
    }
    sockaddr_in got{};
    socklen_t len = sizeof(got);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&got), &len) != 0) {
        ::close(fd);
        return 0;
    }
    ::close(fd);
    return ntohs(got.sin_port);
#endif
}

enum class host_key_kind { ed25519, rsa, ecdsa };

host_key_kind host_key_kind_from_algo(std::string_view algo) {
    if (algo.find("rsa") != std::string_view::npos) return host_key_kind::rsa;
    if (algo.find("ecdsa") != std::string_view::npos) return host_key_kind::ecdsa;
    return host_key_kind::ed25519;
}

bool write_sshd_config(const std::string& path, int port, const std::string& host_key,
                       const std::string& authorized_keys, const std::string& kex,
                       const std::string& cipher, const std::string& hostkey_algo,
                       const std::string& mac, const std::string& pid_file) {
    std::ofstream out(path);
    if (!out) return false;
    out << "Port " << port << '\n'
        << "ListenAddress 127.0.0.1\n"
        << "HostKey " << host_key << '\n';
    if (!pid_file.empty()) out << "PidFile " << pid_file << '\n';
    out << "StrictModes no\n";
#ifndef _WIN32
    out << "UsePAM no\n";
#endif
    out << "PasswordAuthentication no\n"
        << "KbdInteractiveAuthentication no\n"
        << "ChallengeResponseAuthentication no\n"
        << "PubkeyAuthentication yes\n"
        << "AuthorizedKeysFile " << authorized_keys << '\n'
        << "AuthenticationMethods publickey\n"
        << "PermitRootLogin yes\n"
        << "PermitTTY yes\n"
        << "AllowTcpForwarding yes\n"
        << "KexAlgorithms " << kex << '\n'
        << "Ciphers " << cipher << '\n'
        << "HostKeyAlgorithms " << hostkey_algo << '\n'
        << "PubkeyAcceptedAlgorithms ssh-ed25519\n"
        << "MACs " << mac << '\n'
        << "LogLevel ERROR\n";
    return static_cast<bool>(out);
}

struct dir_guard {
    std::string path;
    bool armed = true;
    ~dir_guard() {
        if (armed) remove_tree(path);
    }
    void disarm() noexcept { armed = false; }
};

corral::Task<std::error_code> run_and_wait(uv_loop_t& loop, const std::string& file,
                                          const std::vector<std::string>& args, double timeout,
                                          const char* what) {
    auto [ec, proc] = child_process::launch(loop, file, args);
    if (ec) {
        if (!proc.has_exited()) {
            proc.terminate();
            co_await proc.wait_exited();
        }
        std::cerr << what << " failed to start: " << ec.message() << '\n';
        co_return ec;
    }
    if (timeout > 0) {
        auv::Timer watchdog(&loop, std::chrono::duration<double>(timeout));
        auto outcome = co_await corral::anyOf(proc.wait_exited(), watchdog);
        if (!std::get<0>(outcome)) {
            proc.terminate();
            co_await proc.wait_exited();
            std::cerr << what << " timed out\n";
            co_return std::make_error_code(std::errc::timed_out);
        }
    } else {
        co_await proc.wait_exited();
    }
    if (proc.exit_status() != 0) {
        std::cerr << what << " exited with status " << proc.exit_status() << '\n';
        co_return std::make_error_code(std::errc::io_error);
    }
    co_return {};
}

}  // namespace

struct child_process::impl {
    uv_process_t process{};
    std::unique_ptr<uv_pipe_t, auv::handle_deleter> stderr_pipe;
    corral::Event listening;
    corral::Event exited;
    std::string listen_host;
    int listen_port = 0;
    bool got_listening = false;
    bool handle_inited = false;
    bool process_spawned = false;
    bool process_exited = false;
    bool process_closed = false;
    bool orphaned = false;
    std::error_code error;
    std::int64_t exit_status = 0;
    char read_buf[4096]{};
    std::string line_buf;

    static impl* from_handle(void* data) noexcept { return static_cast<impl*>(data); }

    void consume_stderr(std::string_view bytes) {
        if (!bytes.empty()) {
            std::cerr.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
            std::cerr.flush();
            line_buf.append(bytes);
        }
        for (;;) {
            const auto nl = line_buf.find('\n');
            if (nl == std::string::npos) break;
            const std::string_view line{line_buf.data(), nl};
            if (!got_listening && parse_listening_line(line, listen_host, listen_port)) {
                got_listening = true;
                listening.trigger();
            }
            line_buf.erase(0, nl + 1);
        }
    }

    static void alloc_cb(uv_handle_t* handle, std::size_t, uv_buf_t* buf) {
        auto* self = from_handle(handle->data);
        if (!self) {
            *buf = uv_buf_init(nullptr, 0);
            return;
        }
        buf->base = self->read_buf;
        buf->len = sizeof(self->read_buf);
    }

    static void read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
        auto* self = from_handle(stream->data);
        if (!self) return;
        if (nread > 0) {
            self->consume_stderr(std::string_view{buf->base, static_cast<std::size_t>(nread)});
            return;
        }
        if (nread < 0) uv_read_stop(stream);
    }

    bool has_unreaped_child() const noexcept {
        return !process_exited && (process_spawned || process.pid != 0);
    }

    static void exit_cb(uv_process_t* proc, int64_t exit_status, int) {
        auto* self = from_handle(proc->data);
        if (!self) return;
        self->exit_status = exit_status;
        self->process_exited = true;
        // Snapshot before trigger(): Event::trigger() resumes waiters with no
        // executor, so ~child_process / abandon / uv_close (and even nested
        // uv_run via drain_and_close) may run before we return. If the owner
        // was still alive, it is the closer — do not touch self afterwards.
        const bool already_orphaned = self->orphaned;
        self->exited.trigger();
        if (!already_orphaned) return;
        self->finish_if_orphaned();
    }

    void close_process() {
        if (!handle_inited || process_closed) return;
        process_closed = true;
        process.data = this;
        uv_close(reinterpret_cast<uv_handle_t*>(&process), [](uv_handle_t* h) {
            delete from_handle(h->data);
        });
    }

    void stop_stderr() {
        if (!stderr_pipe) return;
        auto* stream = reinterpret_cast<uv_stream_t*>(stderr_pipe.get());
        if (!uv_is_closing(reinterpret_cast<uv_handle_t*>(stream))) {
            uv_read_stop(stream);
        }
        stderr_pipe.reset();
    }

    void finish_if_orphaned() {
        if (!orphaned) return;
        // Closing the process handle before exit_cb drops it from libuv's
        // waitpid list and leaves a zombie. Wait for reap first.
        if (has_unreaped_child()) return;
        stop_stderr();
        if (process_closed) {
            // uv_close callback is the only deleter once close has started.
            return;
        }
        if (handle_inited) {
            close_process();
            return;
        }
        delete this;
    }
};

void child_process::abandon() noexcept {
    if (!impl_) return;
    auto* raw = impl_.release();
    raw->orphaned = true;
    raw->finish_if_orphaned();
}

child_process::child_process() noexcept = default;

child_process::child_process(std::unique_ptr<impl> impl) noexcept : impl_(std::move(impl)) {}

child_process::child_process(child_process&& other) noexcept = default;

child_process& child_process::operator=(child_process&& other) noexcept {
    if (this != &other) {
        terminate();
        abandon();
        impl_ = std::move(other.impl_);
    }
    return *this;
}

child_process::~child_process() {
    terminate();
    abandon();
}

std::error_code child_process::error() const noexcept {
    return impl_ ? impl_->error : std::error_code{};
}

void child_process::terminate() noexcept {
    if (!impl_ || impl_->process_closed || !impl_->has_unreaped_child()) return;
    (void)uv_process_kill(&impl_->process, k_kill_signal);
}

std::tuple<std::error_code, child_process> child_process::launch(
    uv_loop_t& loop, const std::string& file, const std::vector<std::string>& args) {
    std::vector<std::string> owned = args;
    std::vector<char*> argv;
    argv.reserve(owned.size() + 1);
    for (auto& a : owned) argv.push_back(a.data());
    argv.push_back(nullptr);

    auto state = std::make_unique<impl>();
    state->stderr_pipe = auv::resource_pipe(&loop);
    state->stderr_pipe->data = state.get();
    state->process.data = state.get();

    uv_stdio_container_t stdio[3];
    std::memset(stdio, 0, sizeof(stdio));
    stdio[0].flags = UV_IGNORE;
    stdio[1].flags = UV_IGNORE;
    stdio[2].flags = static_cast<uv_stdio_flags>(UV_CREATE_PIPE | UV_WRITABLE_PIPE);
    stdio[2].data.stream = reinterpret_cast<uv_stream_t*>(state->stderr_pipe.get());

    uv_process_options_t options{};
    options.exit_cb = &impl::exit_cb;
    options.file = file.c_str();
    options.args = argv.data();
    options.stdio_count = 3;
    options.stdio = stdio;

    const int spawned = uv_spawn(&loop, &state->process, &options);
    state->handle_inited = true;
    if (state->process.pid != 0) state->process_spawned = true;
    child_process proc{std::move(state)};
    if (spawned < 0) {
        return {auv::make_uv_error_code(spawned), std::move(proc)};
    }
    const int reading = uv_read_start(reinterpret_cast<uv_stream_t*>(proc.impl_->stderr_pipe.get()),
                                      &impl::alloc_cb, &impl::read_cb);
    if (reading < 0) {
        proc.terminate();
        return {auv::make_uv_error_code(reading), std::move(proc)};
    }
    return {std::error_code{}, std::move(proc)};
}

corral::Task<void> child_process::wait_exited() {
    if (!impl_ || impl_->process_exited || !impl_->has_unreaped_child()) co_return;
    co_await impl_->exited;
}

bool child_process::has_exited() const noexcept {
    return !impl_ || impl_->process_exited;
}

std::int64_t child_process::exit_status() const noexcept {
    return impl_ ? impl_->exit_status : 0;
}

using spawn_result = std::tuple<std::error_code, spawned_peer>;

corral::Task<spawn_result> spawn_bench_server(uv_loop_t& loop, const client_config& cfg) {
    spawned_peer peer;

    const std::string exe = exe_path();
    if (exe.empty()) {
        co_return spawn_result{std::make_error_code(std::errc::no_such_file_or_directory), std::move(peer)};
    }

    const std::string user = cfg.user.empty() ? std::string{k_default_user} : cfg.user;
    const std::string password = cfg.password.empty() ? std::string{k_default_password} : cfg.password;

    std::vector<std::string> args;
    args.push_back(exe);
    args.emplace_back("server");
    args.emplace_back("--bind");
    args.emplace_back("127.0.0.1");
    args.emplace_back("--port");
    args.emplace_back("0");
    args.emplace_back("--user");
    args.push_back(user);
    args.emplace_back("--password");
    args.push_back(password);
    append_kv(args, "--kex", cfg.algo.kex);
    append_kv(args, "--cipher", cfg.algo.cipher);
    append_kv(args, "--mac", cfg.algo.mac);
    append_kv(args, "--hostkey", cfg.algo.hostkey);
    args.emplace_back("--initial-window");
    args.push_back(std::to_string(cfg.tuning.initial_window));
    args.emplace_back("--max-packet");
    args.push_back(std::to_string(cfg.tuning.max_packet));
    args.emplace_back("--rekey-bytes");
    args.push_back(std::to_string(cfg.tuning.rekey_bytes));

    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (auto& a : args) argv.push_back(a.data());
    argv.push_back(nullptr);

    auto state = std::make_unique<child_process::impl>();
    state->stderr_pipe = auv::resource_pipe(&loop);
    state->stderr_pipe->data = state.get();
    state->process.data = state.get();

    uv_stdio_container_t stdio[3];
    std::memset(stdio, 0, sizeof(stdio));
    stdio[0].flags = UV_IGNORE;
    stdio[1].flags = UV_INHERIT_FD;
    stdio[1].data.fd = 1;
    stdio[2].flags = static_cast<uv_stdio_flags>(UV_CREATE_PIPE | UV_WRITABLE_PIPE);
    stdio[2].data.stream = reinterpret_cast<uv_stream_t*>(state->stderr_pipe.get());

    uv_process_options_t options{};
    options.exit_cb = &child_process::impl::exit_cb;
    options.file = exe.c_str();
    options.args = argv.data();
    options.stdio_count = 3;
    options.stdio = stdio;

    const int spawned = uv_spawn(&loop, &state->process, &options);
    state->handle_inited = true;
    // uv_spawn can fail after fork: pid is set, exit_cb will fire, and
    // uv_close before reap drops the handle from libuv's waitpid list.
    if (state->process.pid != 0) state->process_spawned = true;
    if (spawned < 0) {
        const auto ec = auv::make_uv_error_code(spawned);
        child_process proc{std::move(state)};
        if (proc.impl_ && proc.impl_->process_spawned) {
            proc.terminate();
            co_await proc.impl_->exited;
        }
        co_return spawn_result{ec, std::move(peer)};
    }

    const int reading = uv_read_start(reinterpret_cast<uv_stream_t*>(state->stderr_pipe.get()),
                                      &child_process::impl::alloc_cb, &child_process::impl::read_cb);
    if (reading < 0) {
        (void)uv_process_kill(&state->process, k_kill_signal);
        child_process proc{std::move(state)};
        (void)proc;
        co_return spawn_result{auv::make_uv_error_code(reading), std::move(peer)};
    }

    child_process proc{std::move(state)};
    child_process::impl* st = proc.impl_.get();

    if (cfg.timeout_seconds > 0) {
        auv::Timer watchdog(&loop, std::chrono::duration<double>(cfg.timeout_seconds));
        auto outcome = co_await corral::anyOf(st->listening, st->exited, watchdog);
        if (std::get<0>(outcome)) {
            peer.host = st->listen_host;
            peer.port = st->listen_port;
            peer.proc = std::move(proc);
            co_return spawn_result{std::error_code{}, std::move(peer)};
        }
        if (std::get<1>(outcome)) {
            proc.terminate();
            co_return spawn_result{std::make_error_code(std::errc::connection_aborted), std::move(peer)};
        }
        proc.terminate();
        co_return spawn_result{std::make_error_code(std::errc::timed_out), std::move(peer)};
    }

    auto outcome = co_await corral::anyOf(st->listening, st->exited);
    if (std::get<0>(outcome)) {
        peer.host = st->listen_host;
        peer.port = st->listen_port;
        peer.proc = std::move(proc);
        co_return spawn_result{std::error_code{}, std::move(peer)};
    }
    proc.terminate();
    co_return spawn_result{std::make_error_code(std::errc::connection_aborted), std::move(peer)};
}

void sshd_peer::cleanup() noexcept {
    peer = spawned_peer{};
    if (!temp_dir.empty()) {
        remove_tree(temp_dir);
        temp_dir.clear();
    }
    identity_path.clear();
}

sshd_peer::sshd_peer(sshd_peer&& other) noexcept
    : peer(std::move(other.peer)),
      identity_path(std::move(other.identity_path)),
      temp_dir(std::move(other.temp_dir)) {
    other.temp_dir.clear();
    other.identity_path.clear();
}

sshd_peer& sshd_peer::operator=(sshd_peer&& other) noexcept {
    if (this != &other) {
        cleanup();
        peer = std::move(other.peer);
        identity_path = std::move(other.identity_path);
        temp_dir = std::move(other.temp_dir);
        other.temp_dir.clear();
        other.identity_path.clear();
    }
    return *this;
}

sshd_peer::~sshd_peer() { cleanup(); }

using sshd_result = std::tuple<std::error_code, sshd_peer>;

corral::Task<sshd_result> spawn_openssh_sshd(uv_loop_t& loop, const client_config& cfg) {
    sshd_peer peer;

    const std::string sshd = find_sshd(cfg.sshd_path);
    if (sshd.empty()) {
        if (!cfg.sshd_path.empty()) {
            std::cerr << "sshd not found or not executable: " << cfg.sshd_path << '\n';
        } else {
#ifdef _WIN32
            std::cerr << "sshd not found (tried --sshd, PATH, "
                         "C:\\Windows\\System32\\OpenSSH\\sshd.exe)\n";
#else
            std::cerr << "sshd not found (tried --sshd, PATH, /usr/sbin/sshd)\n";
#endif
        }
        co_return sshd_result{std::make_error_code(std::errc::no_such_file_or_directory), std::move(peer)};
    }

    const std::string keygen = find_ssh_keygen();
    if (keygen.empty()) {
        std::cerr << "ssh-keygen not found (install OpenSSH or put ssh-keygen on PATH)\n";
        co_return sshd_result{std::make_error_code(std::errc::no_such_file_or_directory), std::move(peer)};
    }

    const std::string tmp = make_temp_dir();
    if (tmp.empty()) {
        std::cerr << "failed to create temporary directory for sshd\n";
        co_return sshd_result{std::make_error_code(std::errc::io_error), std::move(peer)};
    }
    dir_guard guard{tmp};

    const int port = pick_free_port();
    if (port <= 0) {
        std::cerr << "failed to pick a free loopback port for sshd\n";
        co_return sshd_result{std::make_error_code(std::errc::address_in_use), std::move(peer)};
    }

    const std::string kex = cfg.algo.kex.empty() ? std::string{k_default_kex} : cfg.algo.kex;
    const std::string cipher = cfg.algo.cipher.empty() ? std::string{k_default_cipher} : cfg.algo.cipher;
    const std::string hostkey = cfg.algo.hostkey.empty() ? std::string{k_default_hostkey} : cfg.algo.hostkey;
    const std::string mac = cfg.algo.mac.empty() ? std::string{k_default_mac} : cfg.algo.mac;

    const auto hk_kind = host_key_kind_from_algo(hostkey);
    std::string host_key_path;
    std::vector<std::string> host_keygen_args{keygen, "-q", "-N", ""};
    switch (hk_kind) {
    case host_key_kind::rsa:
        host_key_path = join_path(tmp, "ssh_host_rsa_key");
        host_keygen_args.insert(host_keygen_args.end(), {"-t", "rsa", "-b", "2048"});
        break;
    case host_key_kind::ecdsa:
        host_key_path = join_path(tmp, "ssh_host_ecdsa_key");
        host_keygen_args.insert(host_keygen_args.end(), {"-t", "ecdsa", "-b", "256"});
        break;
    case host_key_kind::ed25519:
        host_key_path = join_path(tmp, "ssh_host_ed25519_key");
        host_keygen_args.insert(host_keygen_args.end(), {"-t", "ed25519"});
        break;
    }
    host_keygen_args.emplace_back("-f");
    host_keygen_args.push_back(host_key_path);

    const std::string user_key_path = join_path(tmp, "user");
    const std::string user_pub_path = join_path(tmp, "user.pub");
    const std::string config_path = join_path(tmp, "sshd_config");
    const std::string log_path = join_path(tmp, "sshd.log");
#ifdef _WIN32
    const std::string pid_file;
#else
    const std::string pid_file = join_path(tmp, "sshd.pid");
#endif

    if (auto kec = co_await run_and_wait(loop, keygen, host_keygen_args, cfg.timeout_seconds,
                                         "ssh-keygen (host key)")) {
        co_return sshd_result{kec, std::move(peer)};
    }
    std::vector<std::string> user_keygen_args{
        keygen, "-q", "-t", "ed25519", "-N", "", "-f", user_key_path};
    if (auto kec = co_await run_and_wait(loop, keygen, user_keygen_args, cfg.timeout_seconds,
                                         "ssh-keygen (user key)")) {
        co_return sshd_result{kec, std::move(peer)};
    }
    if (!file_exists(host_key_path) || !file_exists(user_key_path) || !file_exists(user_pub_path)) {
        std::cerr << "ssh-keygen did not produce expected key files in " << tmp << '\n';
        co_return sshd_result{std::make_error_code(std::errc::io_error), std::move(peer)};
    }

    if (!write_sshd_config(config_path, port, host_key_path, user_pub_path, kex, cipher, hostkey, mac,
                           pid_file)) {
        std::cerr << "failed to write " << config_path << '\n';
        co_return sshd_result{std::make_error_code(std::errc::io_error), std::move(peer)};
    }

    std::vector<std::string> test_args{sshd, "-f", config_path, "-t"};
    if (auto tec = co_await run_and_wait(loop, sshd, test_args, cfg.timeout_seconds, "sshd -t")) {
        dump_file_stderr(log_path);
        co_return sshd_result{tec, std::move(peer)};
    }

    std::vector<std::string> sshd_args{sshd, "-f", config_path, "-D", "-E", log_path};
    auto [sec, proc] = child_process::launch(loop, sshd, sshd_args);
    if (sec) {
        if (!proc.has_exited()) {
            proc.terminate();
            co_await proc.wait_exited();
        }
        std::cerr << "sshd failed to start: " << sec.message() << '\n';
        dump_file_stderr(log_path);
        co_return sshd_result{sec, std::move(peer)};
    }

    auto fail_ready = [&](std::error_code ec, const char* why) -> corral::Task<sshd_result> {
        std::cerr << why << '\n';
        dump_file_stderr(log_path);
        proc.terminate();
        if (!proc.has_exited()) co_await proc.wait_exited();
        co_return sshd_result{ec, std::move(peer)};
    };

    std::unique_ptr<auv::Timer> watchdog;
    if (cfg.timeout_seconds > 0) {
        watchdog = std::make_unique<auv::Timer>(&loop, std::chrono::duration<double>(cfg.timeout_seconds));
    }

    for (;;) {
        if (proc.has_exited()) {
            co_return co_await fail_ready(std::make_error_code(std::errc::connection_aborted),
                                          "sshd exited before accepting connections");
        }
        auto [cec, stream] = co_await tcp_connect(loop, "127.0.0.1", port);
        (void)stream;
        if (!cec) break;

        auv::Timer delay(&loop, std::chrono::milliseconds(50));
        if (watchdog) {
            auto outcome = co_await corral::anyOf(delay, proc.wait_exited(), *watchdog);
            if (std::get<1>(outcome)) {
                co_return co_await fail_ready(std::make_error_code(std::errc::connection_aborted),
                                              "sshd exited before accepting connections");
            }
            if (std::get<2>(outcome)) {
                co_return co_await fail_ready(std::make_error_code(std::errc::timed_out),
                                              "sshd did not become ready before timeout");
            }
        } else {
            auto outcome = co_await corral::anyOf(delay, proc.wait_exited());
            if (std::get<1>(outcome)) {
                co_return co_await fail_ready(std::make_error_code(std::errc::connection_aborted),
                                              "sshd exited before accepting connections");
            }
        }
    }

    peer.peer.proc = std::move(proc);
    peer.peer.host = "127.0.0.1";
    peer.peer.port = port;
    peer.identity_path = user_key_path;
    peer.temp_dir = tmp;
    guard.disarm();
    co_return sshd_result{std::error_code{}, std::move(peer)};
}

}  // namespace bench
