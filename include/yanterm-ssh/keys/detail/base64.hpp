#pragma once

#include <yanterm-ssh/detail/config.hpp>

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yanterm::ssh::keys::detail {

std::string base64_encode(std::span<const std::byte> in, bool pad = true);

bool base64_decode(std::string_view in, std::vector<std::byte>& out);

}  // namespace yanterm::ssh::keys::detail

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/keys/detail/impl/base64.ipp>
#endif
