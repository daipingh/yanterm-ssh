#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <cstdint>

namespace yanterm::ssh::wire {

// RFC 4253 section 12, RFC 4252 section 6, RFC 4254 section 9, RFC 8308 section 2.3.
enum class msg : std::uint8_t {
    disconnect      = 1,
    ignore          = 2,
    unimplemented   = 3,
    debug           = 4,
    service_request = 5,
    service_accept  = 6,
    ext_info        = 7,
    newcompress     = 8,

    kexinit         = 20,
    newkeys         = 21,

    // 30..49 are key exchange method specific and are reused across methods.
    // Which struct parses them is decided by the negotiated KEX algorithm,
    // never by the number alone.
    kexdh_init      = 30,
    kexdh_reply     = 31,
    kex_ecdh_init   = 30,
    kex_ecdh_reply  = 31,

    userauth_request = 50,
    userauth_failure = 51,
    userauth_success = 52,
    userauth_banner  = 53,

    // Method-specific (RFC 4252 §7, RFC 4256 §3.2). Same numbers, current method decides.
    userauth_pk_ok            = 60,
    userauth_passwd_changereq = 60,
    userauth_info_request     = 60,
    userauth_info_response    = 61,

    global_request  = 80,
    request_success = 81,
    request_failure = 82,

    channel_open              = 90,
    channel_open_confirmation = 91,
    channel_open_failure      = 92,
    channel_window_adjust     = 93,
    channel_data              = 94,
    channel_extended_data     = 95,
    channel_eof               = 96,
    channel_close             = 97,
    channel_request           = 98,
    channel_success           = 99,
    channel_failure           = 100,
};

// RFC 4253 section 11.1.
enum class disconnect_reason : std::uint32_t {
    host_not_allowed_to_connect     = 1,
    protocol_error                  = 2,
    key_exchange_failed             = 3,
    reserved                        = 4,
    mac_error                       = 5,
    compression_error               = 6,
    service_not_available           = 7,
    protocol_version_not_supported  = 8,
    host_key_not_verifiable         = 9,
    connection_lost                 = 10,
    by_application                  = 11,
    too_many_connections            = 12,
    auth_cancelled_by_user          = 13,
    no_more_auth_methods_available  = 14,
    illegal_user_name               = 15,
};

}  // namespace yanterm::ssh::wire
