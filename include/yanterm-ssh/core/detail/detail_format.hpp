#pragma once

#include <yanterm-ssh/detail/config.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>

namespace yanterm::ssh::core::detail {

inline constexpr std::size_t peer_text_limit = 1024;
inline constexpr std::size_t failure_detail_limit = 4096;
inline constexpr std::string_view failure_detail_truncation_mark = "...[truncated]";

// Indices match connection::phase.
inline constexpr std::string_view phase_names[] = {
    "version",
    "wait_kexinit",
    "wait_kex_msg",
    "await_host_key",
    "wait_newkeys",
    "established",
    "dead",
};

[[nodiscard]] inline constexpr std::string_view phase_name(std::uint8_t phase) noexcept {
    constexpr auto n = sizeof(phase_names) / sizeof(phase_names[0]);
    if (phase >= n) return "unknown";
    return phase_names[phase];
}

[[nodiscard]] inline std::string escape_peer_text(std::string_view in) {
    if (in.size() > peer_text_limit) in = in.substr(0, peer_text_limit);
    std::string out;
    out.reserve(in.size());
    static constexpr char hex[] = "0123456789abcdef";
    for (unsigned char c : in) {
        if (c == '\\' || c == '"') {
            out.push_back('\\');
            out.push_back(static_cast<char>(c));
        } else if (c >= 0x20 && c <= 0x7e) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('\\');
            out.push_back('x');
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 0x0f]);
        }
    }
    return out;
}

[[nodiscard]] inline std::string clip_failure_detail(std::string detail) {
    if (detail.size() <= failure_detail_limit) return detail;
    detail.resize(failure_detail_limit - failure_detail_truncation_mark.size());
    detail.append(failure_detail_truncation_mark);
    return detail;
}

inline void append_quoted_field(std::string& out, std::string_view key, std::string_view value,
                                bool peer) {
    if (!out.empty()) out.push_back(' ');
    out.append(key);
    out += "=\"";
    out.append(peer ? escape_peer_text(value) : value);
    out += '"';
}

[[nodiscard]] inline std::string format_phase_detail(std::uint8_t phase) {
    std::string s{"phase="};
    s.append(phase_name(phase));
    return s;
}

[[nodiscard]] inline std::string format_unexpected_message(std::uint8_t msg, std::uint8_t phase) {
    std::string s{"msg="};
    s.append(std::to_string(msg));
    s.push_back(' ');
    s.append(format_phase_detail(phase));
    return s;
}

[[nodiscard]] inline std::string format_kex_handler(std::string_view kex, std::string_view stage,
                                                    bool rekey) {
    std::string s{"kex="};
    s.append(kex);
    s.append(" stage=");
    s.append(stage);
    s.append(" rekey=");
    s.push_back(rekey ? '1' : '0');
    return s;
}

[[nodiscard]] inline std::string format_transport_io(std::string_view direction, std::error_code ec) {
    std::string out{"transport "};
    out.append(direction);
    out.append(" failed: ");
    out.append(ec.category().name());
    out.push_back(':');
    out.append(std::to_string(ec.value()));
    out.push_back(' ');
    out.append(ec.message());
    return clip_failure_detail(std::move(out));
}

}  // namespace yanterm::ssh::core::detail
