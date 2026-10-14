#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/keys/public_key.hpp>

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace yanterm::ssh::keys {

struct authorized_key_line {
    std::string raw;                  // 不含行尾换行
    std::string options;              // 不透明；无选项或非密钥行则为空
    std::optional<public_key> key;    // nullopt = 不透明行
    std::string comment;
};

class authorized_keys {
public:
    static std::error_code parse(std::string_view text, authorized_keys& out);
    std::string serialize() const;    // 按原序往返，含不透明行
    std::span<const authorized_key_line> lines() const noexcept;

private:
    std::vector<authorized_key_line> lines_;
};

namespace detail {

[[nodiscard]] inline bool is_known_authorized_key_type(std::string_view tok) noexcept {
    return tok == "ssh-ed25519" || tok == "ecdsa-sha2-nistp256" ||
           tok == "ecdsa-sha2-nistp384" || tok == "ecdsa-sha2-nistp521" || tok == "ssh-rsa";
}

// Locate a known type token outside double quotes. `\"` does not end a quote.
// On success, `type_off` is the start of that token in `s`, and `options` is
// the unquoted prefix with trailing ASCII whitespace stripped.
[[nodiscard]] bool find_authorized_key_type(std::string_view s, std::size_t& type_off,
                                            std::string_view& options) noexcept;

std::string reconstruct_authorized_line(const authorized_key_line& line);

void parse_one_authorized_line(std::string_view line, std::vector<authorized_key_line>& out);

}  // namespace detail

inline std::span<const authorized_key_line> authorized_keys::lines() const noexcept {
    return lines_;
}

}  // namespace yanterm::ssh::keys

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/keys/impl/authorized_keys.ipp>
#endif
