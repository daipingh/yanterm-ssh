#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/core/types.hpp>

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

namespace yanterm::ssh::core::detail {

using ::yanterm::ssh::core::role;

// RFC 4253 section 4.2: the identification line including its terminator
// (CR LF or bare LF) must not exceed 255 bytes.
inline constexpr std::size_t max_identification_line = 255;

class version_exchange {
public:
    version_exchange(role r, std::string_view software);

    // RFC 4253 §4.2: units are whole lines. A line without its terminator is not
    // consumed at all; the caller keeps it and presents it again later. The core
    // therefore retains no partial identification bytes.
    std::error_code feed(std::span<const std::byte> in, std::size_t& accepted);

    [[nodiscard]] std::span<const std::byte> outgoing() const noexcept;
    [[nodiscard]] std::string_view local_identification() const noexcept { return local_; }
    [[nodiscard]] bool done() const noexcept { return done_; }
    [[nodiscard]] std::string_view peer_identification() const noexcept { return peer_; }

private:
    static bool valid_software(std::string_view s) noexcept;
    std::error_code finish_line(std::string_view line);

    role role_;
    std::string local_;
    std::string peer_;
    mutable std::string wire_;
    bool done_ = false;
};

}  // namespace yanterm::ssh::core::detail

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/core/detail/impl/version_exchange.ipp>
#endif
