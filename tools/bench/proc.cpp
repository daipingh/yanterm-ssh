#include "proc.h"

#include <auv/uv.hpp>
#include <corral/Event.h>

#include <csignal>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include <utmp.h>
#if defined(__linux__)
#include <sys/syscall.h>
#endif
extern char** environ;
#endif

namespace bench {
namespace {

#ifdef _WIN32
constexpr int k_kill_signal = SIGTERM;
constexpr int k_term_signal = SIGTERM;
#else
constexpr int k_kill_signal = SIGKILL;
constexpr int k_term_signal = SIGTERM;
#endif

int ssh_name_to_signum(std::string_view name) noexcept {
    if (name.size() >= 3 && (name[0] == 'S' || name[0] == 's') && name[1] == 'I' && name[2] == 'G') {
        name.remove_prefix(3);
    }
#ifdef _WIN32
    if (name == "INT") return SIGINT;
    return k_term_signal;
#else
    if (name == "ABRT") return SIGABRT;
    if (name == "ALRM") return SIGALRM;
    if (name == "FPE") return SIGFPE;
    if (name == "HUP") return SIGHUP;
    if (name == "ILL") return SIGILL;
    if (name == "INT") return SIGINT;
    if (name == "KILL") return SIGKILL;
    if (name == "PIPE") return SIGPIPE;
    if (name == "QUIT") return SIGQUIT;
    if (name == "SEGV") return SIGSEGV;
    if (name == "TERM") return SIGTERM;
#ifdef SIGUSR1
    if (name == "USR1") return SIGUSR1;
#endif
#ifdef SIGUSR2
    if (name == "USR2") return SIGUSR2;
#endif
#ifdef SIGTSTP
    if (name == "TSTP") return SIGTSTP;
#endif
#ifdef SIGTTIN
    if (name == "TTIN") return SIGTTIN;
#endif
#ifdef SIGTTOU
    if (name == "TTOU") return SIGTTOU;
#endif
#ifdef SIGCONT
    if (name == "CONT") return SIGCONT;
#endif
#ifdef SIGSTOP
    if (name == "STOP") return SIGSTOP;
#endif
#ifdef SIGCHLD
    if (name == "CHLD" || name == "CLD") return SIGCHLD;
#endif
    return k_term_signal;
#endif
}

std::string signum_to_ssh_name(int sig) {
#ifndef _WIN32
    switch (sig) {
    case SIGABRT: return "ABRT";
    case SIGALRM: return "ALRM";
    case SIGFPE: return "FPE";
    case SIGHUP: return "HUP";
    case SIGILL: return "ILL";
    case SIGINT: return "INT";
    case SIGKILL: return "KILL";
    case SIGPIPE: return "PIPE";
    case SIGQUIT: return "QUIT";
    case SIGSEGV: return "SEGV";
    case SIGTERM: return "TERM";
#ifdef SIGUSR1
    case SIGUSR1: return "USR1";
#endif
#ifdef SIGUSR2
    case SIGUSR2: return "USR2";
#endif
#ifdef SIGTSTP
    case SIGTSTP: return "TSTP";
#endif
#ifdef SIGTTIN
    case SIGTTIN: return "TTIN";
#endif
#ifdef SIGTTOU
    case SIGTTOU: return "TTOU";
#endif
#ifdef SIGCONT
    case SIGCONT: return "CONT";
#endif
#ifdef SIGSTOP
    case SIGSTOP: return "STOP";
#endif
#ifdef SIGCHLD
    case SIGCHLD: return "CHLD";
#endif
    default: break;
    }
#else
    if (sig == SIGINT) return "INT";
    if (sig == SIGTERM) return "TERM";
#endif
    return "TERM";
}

void upsert_env(std::vector<std::string>& store, std::string_view key, std::string_view value) {
    std::string line;
    line.reserve(key.size() + 1 + value.size());
    line.append(key);
    line.push_back('=');
    line.append(value);
    const std::string prefix = std::string{key} + "=";
    for (auto& e : store) {
        if (e.size() >= prefix.size() && e.compare(0, prefix.size(), prefix) == 0) {
            e = std::move(line);
            return;
        }
    }
    store.push_back(std::move(line));
}

std::vector<std::string> inherit_environ() {
    std::vector<std::string> store;
#ifdef _WIN32
    const char* block = GetEnvironmentStringsA();
    if (!block) return store;
    for (const char* p = block; *p; p += std::strlen(p) + 1) {
        store.emplace_back(p);
    }
    FreeEnvironmentStringsA(const_cast<char*>(block));
#else
    for (char** e = environ; e && *e; ++e) store.emplace_back(*e);
#endif
    return store;
}

}  // namespace

struct piped_child::impl {
    uv_process_t process{};
    auv::stream stdin_stream;
    auv::stream stdout_stream;
    auv::stream stderr_stream;
    corral::Event exited;
    int64_t exit_status = 0;
    int term_signal = 0;
    bool handle_inited = false;
    bool process_spawned = false;
    bool process_exited = false;
    bool process_closed = false;
    bool orphaned = false;

    static impl* from_handle(void* data) noexcept { return static_cast<impl*>(data); }

    bool has_unreaped_child() const noexcept {
        return !process_exited && (process_spawned || process.pid != 0);
    }

    static void exit_cb(uv_process_t* proc, int64_t status, int signal) {
        auto* self = from_handle(proc->data);
        if (!self) return;
        self->exit_status = status;
        self->term_signal = signal;
        self->process_exited = true;
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

    void drop_pipes() {
        stdin_stream.reset();
        stdout_stream.reset();
        stderr_stream.reset();
    }

    void finish_if_orphaned() {
        if (!orphaned) return;
        if (has_unreaped_child()) return;
        drop_pipes();
        if (process_closed) return;
        if (handle_inited) {
            close_process();
            return;
        }
        delete this;
    }
};

piped_child::piped_child() noexcept = default;

piped_child::piped_child(std::unique_ptr<impl> impl) noexcept : impl_(std::move(impl)) {}

piped_child::piped_child(piped_child&&) noexcept = default;

piped_child& piped_child::operator=(piped_child&& other) noexcept {
    if (this != &other) {
        terminate();
        abandon();
        impl_ = std::move(other.impl_);
    }
    return *this;
}

piped_child::~piped_child() {
    terminate();
    abandon();
}

void piped_child::abandon() noexcept {
    if (!impl_) return;
    auto* raw = impl_.release();
    raw->orphaned = true;
    raw->finish_if_orphaned();
}

auv::stream& piped_child::stdin_stream() { return impl_->stdin_stream; }
auv::stream& piped_child::stdout_stream() { return impl_->stdout_stream; }
auv::stream& piped_child::stderr_stream() { return impl_->stderr_stream; }

corral::Task<std::tuple<std::uint32_t, std::string>> piped_child::wait() {
    if (!impl_) co_return {0u, std::string{}};
    if (!impl_->process_exited) co_await impl_->exited;
    if (impl_->term_signal != 0) {
        co_return {0u, signum_to_ssh_name(impl_->term_signal)};
    }
    co_return {static_cast<std::uint32_t>(impl_->exit_status), std::string{}};
}

void piped_child::terminate() noexcept {
    if (!impl_ || impl_->process_closed || !impl_->has_unreaped_child()) return;
    (void)uv_process_kill(&impl_->process, k_kill_signal);
}

void piped_child::send_signal(std::string_view ssh_name) noexcept {
    if (!impl_ || impl_->process_closed || !impl_->has_unreaped_child()) return;
    (void)uv_process_kill(&impl_->process, ssh_name_to_signum(ssh_name));
}

std::tuple<std::error_code, std::unique_ptr<piped_child>> piped_child::start(
    uv_loop_t& loop, const command_spec& spec) {
    auto state = std::make_unique<impl>();

    auto pin = auv::resource_pipe(&loop);
    auto pout = auv::resource_pipe(&loop);
    auto perr = auv::resource_pipe(&loop);

    std::string file;
    std::vector<std::string> args;
#ifdef _WIN32
    if (spec.command.empty()) {
        file = "powershell.exe";
        args = {file};
    } else {
        file = "cmd.exe";
        args = {file, "/c", spec.command};
    }
#else
    if (spec.command.empty()) {
        const char* sh = std::getenv("SHELL");
        file = (sh && *sh) ? sh : "/bin/sh";
        args = {file};
    } else {
        file = "/bin/sh";
        args = {file, "-c", spec.command};
    }
#endif

    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (auto& a : args) argv.push_back(a.data());
    argv.push_back(nullptr);

    std::vector<std::string> env_store;
    std::vector<char*> envp;
    if (!spec.env.empty()) {
        env_store = inherit_environ();
        for (const auto& [k, v] : spec.env) upsert_env(env_store, k, v);
        envp.reserve(env_store.size() + 1);
        for (auto& e : env_store) envp.push_back(e.data());
        envp.push_back(nullptr);
    }

    uv_stdio_container_t stdio[3];
    std::memset(stdio, 0, sizeof(stdio));
    stdio[0].flags = static_cast<uv_stdio_flags>(UV_CREATE_PIPE | UV_READABLE_PIPE);
    stdio[0].data.stream = reinterpret_cast<uv_stream_t*>(pin.get());
    stdio[1].flags = static_cast<uv_stdio_flags>(UV_CREATE_PIPE | UV_WRITABLE_PIPE);
    stdio[1].data.stream = reinterpret_cast<uv_stream_t*>(pout.get());
    stdio[2].flags = static_cast<uv_stdio_flags>(UV_CREATE_PIPE | UV_WRITABLE_PIPE);
    stdio[2].data.stream = reinterpret_cast<uv_stream_t*>(perr.get());

    uv_process_options_t options{};
    options.exit_cb = &impl::exit_cb;
    options.file = file.c_str();
    options.args = argv.data();
    if (!envp.empty()) options.env = envp.data();
    options.stdio_count = 3;
    options.stdio = stdio;

    state->process.data = state.get();
    const int spawned = uv_spawn(&loop, &state->process, &options);
    state->handle_inited = spawned >= 0 || state->process.pid != 0;
    if (state->process.pid != 0) state->process_spawned = true;
    if (spawned < 0) {
        const auto ec = auv::make_uv_error_code(spawned);
        if (state->process_spawned) {
            (void)uv_process_kill(&state->process, k_kill_signal);
            auto child = std::unique_ptr<piped_child>(new piped_child(std::move(state)));
            child->abandon();
        }
        return {ec, std::unique_ptr<piped_child>{}};
    }

    state->stdin_stream = auv::stream::own(auv::make_uv_stream(std::move(pin)));
    state->stdout_stream = auv::stream::own(auv::make_uv_stream(std::move(pout)));
    state->stderr_stream = auv::stream::own(auv::make_uv_stream(std::move(perr)));
    return {std::error_code{}, std::unique_ptr<piped_child>(new piped_child(std::move(state)))};
}

struct pty_child::impl {
    auv::stream io;
    corral::Event exited;
    int64_t exit_status = 0;
    int term_signal = 0;
    int master_fd = -1;
#ifndef _WIN32
    uv_signal_t sig{};
    pid_t pid = -1;
    bool signal_inited = false;
    bool signal_closed = false;
#endif
    bool process_exited = false;
    bool orphaned = false;

    static impl* from_handle(void* data) noexcept { return static_cast<impl*>(data); }

#ifndef _WIN32
    bool has_unreaped_child() const noexcept { return !process_exited && pid > 0; }

    void try_reap() noexcept {
        if (process_exited || pid <= 0) return;
        int st = 0;
        const pid_t r = ::waitpid(pid, &st, WNOHANG);
        if (r != pid) return;
        process_exited = true;
        if (WIFSIGNALED(st)) {
            term_signal = WTERMSIG(st);
            exit_status = 0;
        } else if (WIFEXITED(st)) {
            exit_status = WEXITSTATUS(st);
            term_signal = 0;
        }
        if (signal_inited && !signal_closed) (void)uv_signal_stop(&sig);
        const bool already_orphaned = orphaned;
        exited.trigger();
        if (!already_orphaned) return;
        finish_if_orphaned();
    }

    static void on_chld(uv_signal_t* handle, int) {
        auto* self = from_handle(handle->data);
        if (self) self->try_reap();
    }

    void close_signal() {
        if (!signal_inited || signal_closed) return;
        signal_closed = true;
        sig.data = this;
        uv_close(reinterpret_cast<uv_handle_t*>(&sig), [](uv_handle_t* h) {
            delete from_handle(h->data);
        });
    }
#endif

    void drop_io() { io.reset(); }

    void finish_if_orphaned() {
        if (!orphaned) return;
#ifndef _WIN32
        if (has_unreaped_child()) return;
        drop_io();
        if (signal_closed) return;
        if (signal_inited) {
            close_signal();
            return;
        }
#endif
        drop_io();
        delete this;
    }
};

pty_child::pty_child() noexcept = default;

pty_child::pty_child(std::unique_ptr<impl> impl) noexcept : impl_(std::move(impl)) {}

pty_child::pty_child(pty_child&&) noexcept = default;

pty_child& pty_child::operator=(pty_child&& other) noexcept {
    if (this != &other) {
        terminate();
        abandon();
        impl_ = std::move(other.impl_);
    }
    return *this;
}

pty_child::~pty_child() {
    terminate();
    abandon();
}

void pty_child::abandon() noexcept {
    if (!impl_) return;
    auto* raw = impl_.release();
    raw->orphaned = true;
    raw->finish_if_orphaned();
}

auv::stream& pty_child::io_stream() { return impl_->io; }

#ifndef _WIN32
namespace {

std::error_code errno_ec() noexcept { return {errno, std::system_category()}; }

std::error_code apply_winsize(int fd, pty_geometry g) noexcept {
    if (fd < 0) return std::make_error_code(std::errc::bad_file_descriptor);
    winsize ws{};
    ws.ws_col = static_cast<unsigned short>(g.cols);
    ws.ws_row = static_cast<unsigned short>(g.rows);
    ws.ws_xpixel = static_cast<unsigned short>(g.pixel_width);
    ws.ws_ypixel = static_cast<unsigned short>(g.pixel_height);
    if (::ioctl(fd, TIOCSWINSZ, &ws) < 0) return errno_ec();
    return {};
}

void child_close_extra_fds() noexcept {
#if defined(__linux__) && defined(__NR_close_range)
    (void)::syscall(__NR_close_range, 3, ~0u, 0);
#else
    const long cap = ::sysconf(_SC_OPEN_MAX);
    const int maxfd = (cap > 3 && cap <= 4096) ? static_cast<int>(cap) : 1024;
    for (int fd = 3; fd < maxfd; ++fd) (void)::close(fd);
#endif
}

}  // namespace
#endif

std::error_code pty_child::resize(pty_geometry geo) {
#ifdef _WIN32
    (void)geo;
    return std::make_error_code(std::errc::not_supported);
#else
    if (!impl_) return std::make_error_code(std::errc::bad_file_descriptor);
    return apply_winsize(impl_->master_fd, geo);
#endif
}

corral::Task<std::tuple<std::uint32_t, std::string>> pty_child::wait() {
    if (!impl_) co_return {0u, std::string{}};
#ifndef _WIN32
    if (!impl_->process_exited) impl_->try_reap();
    if (!impl_->process_exited) co_await impl_->exited;
#endif
    if (impl_->term_signal != 0) {
        co_return {0u, signum_to_ssh_name(impl_->term_signal)};
    }
    co_return {static_cast<std::uint32_t>(impl_->exit_status), std::string{}};
}

void pty_child::terminate() noexcept {
#ifdef _WIN32
    return;
#else
    if (!impl_ || impl_->signal_closed || !impl_->has_unreaped_child()) return;
    (void)::kill(impl_->pid, k_kill_signal);
#endif
}

void pty_child::send_signal(std::string_view ssh_name) noexcept {
#ifdef _WIN32
    (void)ssh_name;
#else
    if (!impl_ || impl_->signal_closed || !impl_->has_unreaped_child()) return;
    (void)::kill(impl_->pid, ssh_name_to_signum(ssh_name));
#endif
}

std::tuple<std::error_code, std::unique_ptr<pty_child>> pty_child::start(
    uv_loop_t& loop, const command_spec& spec, std::string_view term, pty_geometry geo) {
#ifdef _WIN32
    (void)loop;
    (void)spec;
    (void)term;
    (void)geo;
    return {std::make_error_code(std::errc::not_supported), std::unique_ptr<pty_child>{}};
#else
    std::string file;
    std::vector<std::string> args;
    if (spec.command.empty()) {
        const char* sh = std::getenv("SHELL");
        file = (sh && *sh) ? sh : "/bin/sh";
        args = {file};
    } else {
        file = "/bin/sh";
        args = {file, "-c", spec.command};
    }

    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (auto& a : args) argv.push_back(a.data());
    argv.push_back(nullptr);

    std::vector<std::string> env_store = inherit_environ();
    for (const auto& [k, v] : spec.env) upsert_env(env_store, k, v);
    upsert_env(env_store, "TERM", term.empty() ? "xterm" : term);
    std::vector<char*> envp;
    envp.reserve(env_store.size() + 1);
    for (auto& e : env_store) envp.push_back(e.data());
    envp.push_back(nullptr);

    winsize ws{};
    ws.ws_col = static_cast<unsigned short>(geo.cols);
    ws.ws_row = static_cast<unsigned short>(geo.rows);
    ws.ws_xpixel = static_cast<unsigned short>(geo.pixel_width);
    ws.ws_ypixel = static_cast<unsigned short>(geo.pixel_height);

    int master = -1;
    int slave = -1;
    if (::openpty(&master, &slave, nullptr, nullptr, &ws) < 0) {
        return {errno_ec(), std::unique_ptr<pty_child>{}};
    }
    (void)::fcntl(master, F_SETFD, FD_CLOEXEC);
    (void)::fcntl(slave, F_SETFD, FD_CLOEXEC);

    const pid_t pid = ::fork();
    if (pid < 0) {
        const auto ec = errno_ec();
        (void)::close(master);
        (void)::close(slave);
        return {ec, std::unique_ptr<pty_child>{}};
    }
    if (pid == 0) {
        (void)::close(master);
        if (::login_tty(slave) < 0) _exit(127);
        child_close_extra_fds();
        ::execve(file.c_str(), argv.data(), envp.data());
        _exit(127);
    }

    (void)::close(slave);

    auto state = std::make_unique<impl>();
    state->pid = pid;
    state->master_fd = master;

    auto pipe = auv::resource_pipe(&loop);
    const int opened = uv_pipe_open(pipe.get(), master);
    if (opened < 0) {
        (void)::kill(pid, k_kill_signal);
        (void)::waitpid(pid, nullptr, 0);
        (void)::close(master);
        return {auv::make_uv_error_code(opened), std::unique_ptr<pty_child>{}};
    }

    const int sig_init = uv_signal_init(&loop, &state->sig);
    state->signal_inited = sig_init >= 0;
    if (sig_init < 0) {
        (void)::kill(pid, k_kill_signal);
        (void)::waitpid(pid, nullptr, 0);
        return {auv::make_uv_error_code(sig_init), std::unique_ptr<pty_child>{}};
    }
    state->sig.data = state.get();
    const int sig_start = uv_signal_start(&state->sig, &impl::on_chld, SIGCHLD);
    if (sig_start < 0) {
        (void)::kill(pid, k_kill_signal);
        (void)::waitpid(pid, nullptr, 0);
        state->process_exited = true;
        auto child = std::unique_ptr<pty_child>(new pty_child(std::move(state)));
        child->abandon();
        return {auv::make_uv_error_code(sig_start), std::unique_ptr<pty_child>{}};
    }

    state->io = auv::stream::own(auv::make_uv_stream(std::move(pipe)));
    state->try_reap();
    return {std::error_code{}, std::unique_ptr<pty_child>(new pty_child(std::move(state)))};
#endif
}

}  // namespace bench
