#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/crypto/provider.hpp>
#include <yanterm-ssh/keys/public_key.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace yanterm::ssh::keys {

enum class host_marker : std::uint8_t { none, revoked, cert_authority };
enum class host_key_match : std::uint8_t { none, found, revoked };

struct known_host_line {
    std::string raw;                  // 不含行尾换行；serialize 时补 `\n`
    host_marker marker = host_marker::none;
    std::string pattern;              // 仅密钥行
    std::optional<public_key> key;    // nullopt = 不透明行（注释/空行/未知类型/坏行）
    std::string comment;              // 仅密钥行
};

class known_hosts {
public:
    static std::error_code parse(std::string_view text, known_hosts& out);
    std::string serialize() const;    // 按原序：有 raw 写 raw，否则从字段重建
    host_key_match match(crypto::provider p,
                         std::string_view hostname,
                         std::uint16_t port,
                         const public_key& key) const;
    void append(known_host_line line);
    std::size_t erase_matching(crypto::provider p,
                               std::string_view hostname,
                               std::uint16_t port,
                               const public_key& key);
    std::span<const known_host_line> lines() const noexcept;

private:
    std::vector<known_host_line> lines_;
};

namespace detail {

[[nodiscard]] std::string host_with_port_form(std::string_view hostname,
                                              std::uint16_t port);

[[nodiscard]] bool match_glob(std::string_view s, std::string_view pat) noexcept;

[[nodiscard]] bool hashed_host_eq(crypto::provider p, std::string_view host_form,
                                  std::string_view item);

[[nodiscard]] bool host_pattern_matches(crypto::provider p, std::string_view pattern,
                                        std::string_view host_form);

[[nodiscard]] inline bool blobs_equal(const public_key& a, const public_key& b) noexcept {
    const auto xa = a.blob();
    const auto xb = b.blob();
    return xa.size() == xb.size() && std::equal(xa.begin(), xa.end(), xb.begin());
}

[[nodiscard]] bool line_key_hit(crypto::provider p, const known_host_line& line,
                                std::string_view hostname, std::uint16_t port,
                                const public_key& key);

std::string reconstruct_line(const known_host_line& line);

void parse_one_line(std::string_view line, std::vector<known_host_line>& out);

}  // namespace detail

inline std::span<const known_host_line> known_hosts::lines() const noexcept { return lines_; }

}  // namespace yanterm::ssh::keys

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/keys/impl/known_hosts.ipp>
#endif
