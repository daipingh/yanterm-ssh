#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/core/config.hpp>
#include <yanterm-ssh/kex/detail/tables.hpp>
#include <yanterm-ssh/kex/algorithms.hpp>
#include <yanterm-ssh/core/types.hpp>
#include <yanterm-ssh/wire/detail/messages.hpp>
#include <yanterm-ssh/crypto/provider.hpp>

#include <cstddef>
#include <span>
#include <string_view>
#include <system_error>
#include <vector>

namespace yanterm::ssh::core::detail {

class local_algorithms {
public:
    local_algorithms(crypto::provider p, const ::yanterm::ssh::core::config& cfg,
                     ::yanterm::ssh::core::role r,
                     bool advertise_ext_info = true,
                     bool advertise_strict_kex = true,
                     std::span<const std::string_view> host_key_allowlist = {});
    [[nodiscard]] kex::detail::algorithm_names names() const noexcept;

private:
    std::vector<std::string_view> kex_;
    std::vector<std::string_view> host_key_;
    std::vector<std::string_view> cipher_;
    std::vector<std::string_view> mac_;
    std::vector<std::string_view> compression_;
};

[[nodiscard]] std::size_t usable_name_count(
    std::span<const std::string_view> names) noexcept;

std::error_code negotiate(crypto::provider p, ::yanterm::ssh::core::role r,
                          const wire::detail::kexinit& client,
                          const wire::detail::kexinit& server,
                          ::yanterm::ssh::kex::negotiated& out);

}  // namespace yanterm::ssh::core::detail

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/core/detail/impl/kex_negotiation.ipp>
#endif
