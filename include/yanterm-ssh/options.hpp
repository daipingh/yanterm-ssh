#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/core/types.hpp>
#include <yanterm-ssh/keys/private_key.hpp>
#include <yanterm-ssh/version.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace yanterm::ssh {

// session_options::max_pending_requests == 0 is clamped to this.
inline constexpr std::uint32_t default_max_pending_requests = 32;

struct session_options {
    std::string software{default_software()};
    std::uint64_t rekey_bytes = 1ull << 30;
    std::uint64_t rekey_packets = 1ull << 31;
    std::string preferred_kex{};
    std::string preferred_host_key{};
    std::string preferred_cipher{};
    std::string preferred_mac{};
    bool advertise_ext_info = true;
    bool advertise_strict_kex = true;
    std::uint32_t initial_window = 2u * 1024u * 1024u;
    std::uint32_t max_channel_packet = 32768;
    std::uint32_t max_channels = 256;
    std::uint32_t max_pending_requests = default_max_pending_requests;
    std::size_t max_output_bytes = 256u * 1024u;
    std::function<void(bool always_display, std::string_view text, std::string_view language)>
        on_debug;
};

struct client_options : session_options {
    std::function<void(std::string_view text, std::string_view language)> on_banner;
};

struct server_options : session_options {
    std::vector<keys::private_key> host_keys;
    std::string auth_banner;
    std::string auth_banner_language;
    std::string accepted_publickey_algorithms{};
};

}  // namespace yanterm::ssh
