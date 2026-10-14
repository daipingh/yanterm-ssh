#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace bench {

enum class subcommand { server, spawn_server, spawn_sshd, connect };
enum class peer_kind { external, spawn_server, spawn_sshd };
enum class workload { handshake, download, upload, all };
enum class direction { download, upload };

struct algo_options {            // 空串表示用库默认（现代集头条）
    std::string kex, cipher, mac, hostkey;
};

struct tuning_options {          // 映射到 ssh::session_options
    std::uint32_t initial_window = 2u * 1024u * 1024u;
    std::uint32_t max_packet = 32768;
    std::uint64_t rekey_bytes = 1ull << 30;
};

struct jump_hop { std::string user, host, identity, password; int port = 22; };

struct server_config {
    std::string bind = "127.0.0.1";
    int port = 0;
    std::string user, password, authorized_path, host_key_path;
    algo_options algo; tuning_options tuning;
};

struct client_config {
    peer_kind peer = peer_kind::external;
    std::string host = "127.0.0.1"; int port = 22;
    std::string user, password, identity_path, sshd_path;
    std::vector<jump_hop> jumps;
    workload work = workload::all;
    int repeat = 21;
    double warmup_seconds = 1.0, seconds = 5.0;   // seconds 与 bytes 互斥
    std::uint64_t bytes = 0;                      // 0 = 用时间窗
    std::string exec_download, exec_upload;       // 空 = 按对端平台取默认
    double timeout_seconds = 30.0;
    algo_options algo; tuning_options tuning;
    bool json = false;
};

struct parsed_command {
    subcommand cmd;
    server_config server;
    client_config client;
};

// 解析失败返回 nullopt 并填 error（含用法提示）；互斥冲突算失败。
std::optional<parsed_command> parse_command(int argc, char** argv, std::string& error);

[[nodiscard]] std::string usage_text();

// POSIX：download `cat /dev/zero`，upload `cat >/dev/null`。Windows 为编译期分支。
[[nodiscard]] std::string default_exec_command(direction dir);

}  // namespace bench
