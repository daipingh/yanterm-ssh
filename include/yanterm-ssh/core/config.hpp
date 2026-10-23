#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/core/types.hpp>
#include <yanterm-ssh/version.hpp>

#include <cstdint>
#include <string_view>

namespace yanterm::ssh::core {

// The local role is passed to connection() separately, not stored here, so a
// single config can be shared by both sides in tests.
struct config {
    std::string_view software = default_software();
    std::uint64_t rekey_bytes = 1ull << 30;  // Task 17
    std::uint64_t rekey_packets = 1ull << 31;

    // RFC 4251 name-list. Empty = modern built-in set (provider-filtered).
    // Non-empty = whole-class replace; unknown names skipped; no trim / +/-/^.
    std::string_view preferred_kex{};
    std::string_view preferred_host_key{};
    std::string_view preferred_cipher{};
    std::string_view preferred_mac{};

    // Protocol markers appended to the kex name-list on the first KEXINIT.
    // Tests disable these to exercise non-strict / no-EXT_INFO peers.
    bool advertise_ext_info = true;
    bool advertise_strict_kex = true;

    // Connection-layer limits. The facade / application sets these when
    // constructing `connection`; there is no setter afterwards.
    std::uint32_t initial_window = 2u * 1024u * 1024u;
    std::uint32_t max_channel_packet = 32768;
    std::uint32_t max_channels = 256;

    // Server: copied by the engine at construction. Empty text does not send
    // USERAUTH_BANNER. The client role ignores these views.
    std::string_view auth_banner{};
    std::string_view auth_banner_language{};

    // Server userauth "publickey" signature algorithm name-list (RFC 8308 §3.1,
    // RFC 4252 §7). Empty = built-in host_key_table entries supported by the
    // provider except "ssh-rsa". Non-empty = whole-class replace (provider-filtered).
    // Resolved at construction; ignored by the client role.
    std::string_view accepted_publickey_algorithms{};
};

}  // namespace yanterm::ssh::core
