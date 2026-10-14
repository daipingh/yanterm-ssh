#pragma once

#include <yanterm-ssh/detail/config.hpp>

#include <cstdint>

namespace yanterm::ssh::core {

enum class role : std::uint8_t { client, server };

enum class host_key_verdict : std::uint8_t { accept, reject };

}  // namespace yanterm::ssh::core
