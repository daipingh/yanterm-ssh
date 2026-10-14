#pragma once

#include <auv/stream.hpp>
#include <corral/Task.h>
#include <uv.h>

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

namespace bench {

struct command_spec {
    std::string command;       // exec 的原始命令串；空 = 起默认 shell
    std::vector<std::pair<std::string, std::string>> env;
};

// 管道模式子进程：stdin/stdout/stderr 三条 uv_pipe。
// POSIX 用 /bin/sh -c，Windows 用 cmd /c；空命令起 $SHELL / powershell。
class piped_child {
public:
    static std::tuple<std::error_code, std::unique_ptr<piped_child>> start(
        uv_loop_t& loop, const command_spec&);

    piped_child(piped_child&&) noexcept;
    piped_child& operator=(piped_child&&) noexcept;
    ~piped_child();

    piped_child(const piped_child&) = delete;
    piped_child& operator=(const piped_child&) = delete;

    auv::stream& stdin_stream();
    auv::stream& stdout_stream();
    auv::stream& stderr_stream();

    // 进程退出后可得：正常退出给 exit code，被信号杀死给信号名。
    corral::Task<std::tuple<std::uint32_t, std::string>> wait();
    void terminate() noexcept;
    // SSH 信号名（无 SIG 前缀：INT/TERM/KILL/HUP/…）→ kill(pid, …)；未知名当 TERM。
    void send_signal(std::string_view ssh_name) noexcept;

private:
    struct impl;
    std::unique_ptr<impl> impl_;

    piped_child() noexcept;
    explicit piped_child(std::unique_ptr<impl> impl) noexcept;
    void abandon() noexcept;
};

struct pty_geometry {
    std::uint32_t cols = 80;
    std::uint32_t rows = 24;
    std::uint32_t pixel_width = 0;
    std::uint32_t pixel_height = 0;
};

// POSIX：openpty + fork + login_tty + exec；master fd 交给 uv_pipe_open 包成 stream。
// Windows：start() 直接返回 errc::not_supported（调用方据此让 pty-req 失败）。
class pty_child {
public:
    static std::tuple<std::error_code, std::unique_ptr<pty_child>> start(
        uv_loop_t& loop, const command_spec&, std::string_view term, pty_geometry);

    pty_child(pty_child&&) noexcept;
    pty_child& operator=(pty_child&&) noexcept;
    ~pty_child();

    pty_child(const pty_child&) = delete;
    pty_child& operator=(const pty_child&) = delete;

    auv::stream& io_stream();  // 双向，不分离 stderr
    std::error_code resize(pty_geometry);
    corral::Task<std::tuple<std::uint32_t, std::string>> wait();
    void terminate() noexcept;
    void send_signal(std::string_view ssh_name) noexcept;

private:
    struct impl;
    std::unique_ptr<impl> impl_;

    pty_child() noexcept;
    explicit pty_child(std::unique_ptr<impl> impl) noexcept;
    void abandon() noexcept;
};

}  // namespace bench
