#pragma once

#include "options.h"

#include <yanterm-ssh/kex/algorithms.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ssh = yanterm::ssh;

namespace bench {

struct handshake_stats { int samples; double min_ms, median_ms, mean_ms; };
handshake_stats summarize_handshake(std::vector<double> samples_ms);

struct throughput_stats { std::uint64_t payload_bytes; double seconds; };
[[nodiscard]] double mib_per_second(const throughput_stats&);

struct negotiated_names { std::string kex, cipher, mac, host_key; };
negotiated_names describe(const ssh::kex::negotiated&);   // 取自 session::negotiated()

struct hop_handshake {
    std::string label;              // "hop1 bastion:22" / "target host:22"
    handshake_stats stats;
};

struct run_record {                 // client 一次运行的完整结果
    std::string role;               // "client"
    std::string peer;               // "yanterm" / "openssh" / "external"
    negotiated_names algos;
    std::optional<handshake_stats> handshake;
    std::vector<hop_handshake> hops;  // 无 jump 时为空
    std::optional<throughput_stats> throughput_download;
    std::optional<throughput_stats> throughput_upload;
    tuning_options tuning;
};

void print_table(const run_record&);
void print_json(const run_record&);  // 单行 JSON 到 stdout；`--json` 时只走这条

// Helpers used by print_table; prefer print_table / print_json at the client.
void print_handshake(const handshake_stats&, const negotiated_names&);
void print_throughput(const throughput_stats&, direction, const negotiated_names&);

struct channel_transfer;
void print_channel_transfer(std::string_view type, const channel_transfer&);

}  // namespace bench
