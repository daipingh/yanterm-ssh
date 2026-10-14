#include "report.h"
#include "server.h"

#include <yanterm-ssh/crypto/algorithms.hpp>
#include <yanterm-ssh/transport/packet_mode.hpp>

#include <algorithm>
#include <cstdio>
#include <iostream>
#include <locale>
#include <numeric>
#include <ostream>
#include <sstream>
#include <string_view>

namespace bench {
namespace {

std::string cipher_name(const ssh::kex::negotiated& n) {
    using ssh::crypto::cipher_id;
    switch (n.cipher_c2s) {
    case cipher_id::chacha20:
        return "chacha20-poly1305@openssh.com";
    case cipher_id::aes256_gcm:
        return "aes256-gcm@openssh.com";
    case cipher_id::aes128_gcm:
        return "aes128-gcm@openssh.com";
    case cipher_id::aes256_ctr:
        return "aes256-ctr";
    case cipher_id::aes192_ctr:
        return "aes192-ctr";
    case cipher_id::aes128_ctr:
        return "aes128-ctr";
    case cipher_id::aes256_cbc:
        return "aes256-cbc";
    case cipher_id::aes192_cbc:
        return "aes192-cbc";
    case cipher_id::aes128_cbc:
        return "aes128-cbc";
    case cipher_id::sm4_ctr:
        return "sm4-ctr";
    case cipher_id::sm4_cbc:
        return "sm4-cbc";
    }
    return {};
}

std::string mac_name(const ssh::kex::negotiated& n) {
    using ssh::transport::packet_mode;
    if (n.mode_c2s == packet_mode::chacha20_poly1305 || n.mode_c2s == packet_mode::gcm) {
        return {};
    }
    const bool etm = n.mode_c2s == packet_mode::ctr_encrypt_then_mac
                  || n.mode_c2s == packet_mode::cbc_encrypt_then_mac;
    using ssh::crypto::hash_id;
    switch (n.mac_c2s) {
    case hash_id::sha256:
        return etm ? "hmac-sha2-256-etm@openssh.com" : "hmac-sha2-256";
    case hash_id::sha512:
        return etm ? "hmac-sha2-512-etm@openssh.com" : "hmac-sha2-512";
    case hash_id::sha1:
        return "hmac-sha1";
    case hash_id::sha384:
        return {};
    case hash_id::sm3:
        return "hmac-sm3";
    }
    return {};
}

}  // namespace

handshake_stats summarize_handshake(std::vector<double> samples_ms) {
    handshake_stats s{};
    s.samples = static_cast<int>(samples_ms.size());
    if (samples_ms.empty()) return s;
    std::sort(samples_ms.begin(), samples_ms.end());
    s.min_ms = samples_ms.front();
    const auto n = samples_ms.size();
    if (n % 2 == 1) {
        s.median_ms = samples_ms[n / 2];
    } else {
        s.median_ms = 0.5 * (samples_ms[n / 2 - 1] + samples_ms[n / 2]);
    }
    const double sum = std::accumulate(samples_ms.begin(), samples_ms.end(), 0.0);
    s.mean_ms = sum / static_cast<double>(n);
    return s;
}

double mib_per_second(const throughput_stats& st) {
    if (st.seconds <= 0.0) return 0.0;
    return static_cast<double>(st.payload_bytes) / st.seconds / (1024.0 * 1024.0);
}

negotiated_names describe(const ssh::kex::negotiated& n) {
    negotiated_names out;
    out.kex.assign(n.kex_name.begin(), n.kex_name.end());
    out.host_key.assign(n.host_key_name.begin(), n.host_key_name.end());
    out.cipher = cipher_name(n);
    out.mac = mac_name(n);
    return out;
}

namespace {

void print_negotiated(std::ostream& os, const negotiated_names& names) {
    os << "negotiated  kex=" << names.kex
       << "  cipher=" << names.cipher
       << "  mac=" << (names.mac.empty() ? "-" : names.mac)
       << "  host_key=" << names.host_key << '\n';
}

const char* direction_name(direction dir) {
    return dir == direction::upload ? "upload" : "download";
}

void json_string(std::ostream& os, std::string_view s) {
    os << '"';
    for (unsigned char c : s) {
        switch (c) {
        case '"': os << "\\\""; break;
        case '\\': os << "\\\\"; break;
        case '\b': os << "\\b"; break;
        case '\f': os << "\\f"; break;
        case '\n': os << "\\n"; break;
        case '\r': os << "\\r"; break;
        case '\t': os << "\\t"; break;
        default:
            if (c < 0x20) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                os << buf;
            } else {
                os << static_cast<char>(c);
            }
        }
    }
    os << '"';
}

void json_number(std::ostream& os, double v) {
    os << v;
}

}  // namespace

void print_handshake(const handshake_stats& st, const negotiated_names&) {
    std::cout << "handshake  samples=" << st.samples
              << "  min=" << st.min_ms << " ms"
              << "  median=" << st.median_ms << " ms"
              << "  mean=" << st.mean_ms << " ms\n";
}

void print_throughput(const throughput_stats& st, direction dir, const negotiated_names&) {
    std::cout << "throughput " << direction_name(dir)
              << "  bytes=" << st.payload_bytes
              << "  seconds=" << st.seconds
              << "  MiB/s=" << mib_per_second(st) << '\n';
}

void print_table(const run_record& rec) {
    std::cout << "role=" << rec.role << "  peer=" << rec.peer << '\n';
    for (const auto& hop : rec.hops) {
        std::cout << "handshake  " << hop.label
                  << "  samples=" << hop.stats.samples
                  << "  min=" << hop.stats.min_ms << " ms"
                  << "  median=" << hop.stats.median_ms << " ms"
                  << "  mean=" << hop.stats.mean_ms << " ms\n";
    }
    if (rec.handshake) print_handshake(*rec.handshake, rec.algos);
    if (rec.throughput_download) {
        print_throughput(*rec.throughput_download, direction::download, rec.algos);
    }
    if (rec.throughput_upload) {
        print_throughput(*rec.throughput_upload, direction::upload, rec.algos);
    }
    print_negotiated(std::cout, rec.algos);
}

void print_json(const run_record& rec) {
    std::ostringstream os;
    os.imbue(std::locale::classic());
    os << '{';
    os << "\"role\":";
    json_string(os, rec.role);
    os << ",\"peer\":";
    json_string(os, rec.peer);
    os << ",\"algos\":{";
    os << "\"kex\":";
    json_string(os, rec.algos.kex);
    os << ",\"cipher\":";
    json_string(os, rec.algos.cipher);
    os << ",\"mac\":";
    json_string(os, rec.algos.mac);
    os << ",\"host_key\":";
    json_string(os, rec.algos.host_key);
    os << '}';
    os << ",\"handshake\":";
    if (rec.handshake) {
        const auto& h = *rec.handshake;
        os << "{\"samples\":" << h.samples
           << ",\"min_ms\":";
        json_number(os, h.min_ms);
        os << ",\"median_ms\":";
        json_number(os, h.median_ms);
        os << ",\"mean_ms\":";
        json_number(os, h.mean_ms);
        os << '}';
    } else {
        os << "null";
    }
    if (!rec.hops.empty()) {
        os << ",\"hops\":[";
        for (std::size_t i = 0; i < rec.hops.size(); ++i) {
            if (i != 0) os << ',';
            const auto& hop = rec.hops[i];
            os << "{\"label\":";
            json_string(os, hop.label);
            os << ",\"samples\":" << hop.stats.samples
               << ",\"min_ms\":";
            json_number(os, hop.stats.min_ms);
            os << ",\"median_ms\":";
            json_number(os, hop.stats.median_ms);
            os << ",\"mean_ms\":";
            json_number(os, hop.stats.mean_ms);
            os << '}';
        }
        os << ']';
    }
    auto json_throughput = [&](const std::optional<throughput_stats>& st) {
        if (!st) {
            os << "null";
            return;
        }
        os << "{\"payload_bytes\":" << st->payload_bytes
           << ",\"seconds\":";
        json_number(os, st->seconds);
        os << ",\"mib_per_s\":";
        json_number(os, mib_per_second(*st));
        os << '}';
    };
    os << ",\"throughput_download\":";
    json_throughput(rec.throughput_download);
    os << ",\"throughput_upload\":";
    json_throughput(rec.throughput_upload);
    os << ",\"tuning\":{"
       << "\"initial_window\":" << rec.tuning.initial_window
       << ",\"max_packet\":" << rec.tuning.max_packet
       << ",\"rekey_bytes\":" << rec.tuning.rekey_bytes
       << '}';
    os << "}\n";
    std::cout << os.str();
}

void print_channel_transfer(std::string_view type, const channel_transfer& xfer) {
    const auto bytes = std::max(xfer.to_client_bytes, xfer.to_process_bytes);
    const throughput_stats st{bytes, xfer.seconds};
    const char* dir_name =
        xfer.to_process_bytes > xfer.to_client_bytes ? "upload" : "download";
    std::cerr << "channel " << type
              << " direction=" << dir_name
              << " to_client=" << xfer.to_client_bytes
              << " to_process=" << xfer.to_process_bytes
              << " seconds=" << xfer.seconds
              << " MiB/s=" << mib_per_second(st) << std::endl;
}

}  // namespace bench
