#pragma once

#include "options.h"

#include <corral/Task.h>
#include <uv.h>

#include <cstdint>
#include <memory>
#include <string>
#include <system_error>
#include <tuple>
#include <vector>

namespace bench {

struct spawned_peer;

// 子进程句柄：析构时 kill + reap，保证异常/超时路径不留孤儿。
class child_process {
public:
    child_process() noexcept;
    child_process(child_process&&) noexcept;
    child_process& operator=(child_process&&) noexcept;
    ~child_process();

    child_process(const child_process&) = delete;
    child_process& operator=(const child_process&) = delete;

    [[nodiscard]] std::error_code error() const noexcept;
    void terminate() noexcept;

    static std::tuple<std::error_code, child_process> launch(
        uv_loop_t& loop, const std::string& file, const std::vector<std::string>& args);

    corral::Task<void> wait_exited();
    [[nodiscard]] bool has_exited() const noexcept;
    [[nodiscard]] std::int64_t exit_status() const noexcept;

private:
    struct impl;
    std::unique_ptr<impl> impl_;

    explicit child_process(std::unique_ptr<impl> impl) noexcept;
    void abandon() noexcept;

    friend corral::Task<std::tuple<std::error_code, spawned_peer>> spawn_bench_server(
        uv_loop_t& loop, const client_config&);
};

struct spawned_peer {
    child_process proc;
    std::string host;
    int port = 0;
};

// 以本二进制（uv_exepath）再起一份 server：算法与 tuning 透传，stderr 接管道，
// 读到 "listening <ip> <port>" 为就绪；超时或子进程早退返回错误。
corral::Task<std::tuple<std::error_code, spawned_peer>> spawn_bench_server(
    uv_loop_t& loop, const client_config&);

struct sshd_peer {
    spawned_peer peer;
    std::string identity_path;  // 供 publickey 认证（不走密码，避免 PAM）
    std::string temp_dir;       // 析构时清理

    sshd_peer() noexcept = default;
    sshd_peer(sshd_peer&&) noexcept;
    sshd_peer& operator=(sshd_peer&&) noexcept;
    ~sshd_peer();

    sshd_peer(const sshd_peer&) = delete;
    sshd_peer& operator=(const sshd_peer&) = delete;

private:
    void cleanup() noexcept;
};

// 临时目录 + ssh-keygen 生成 host/user key + 生成 sshd_config + 起 sshd。
// 算法按 client_config::algo 钉死。找不到 sshd / ssh-keygen 返回错误。
corral::Task<std::tuple<std::error_code, sshd_peer>> spawn_openssh_sshd(
    uv_loop_t& loop, const client_config&);

}  // namespace bench
