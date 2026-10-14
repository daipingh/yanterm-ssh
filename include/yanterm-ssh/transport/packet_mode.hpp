#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <cstdint>

namespace yanterm::ssh::transport {

enum class packet_mode : std::uint8_t {
    plaintext,
    ctr_encrypt_and_mac,
    ctr_encrypt_then_mac,
    cbc_encrypt_and_mac,
    cbc_encrypt_then_mac,
    gcm,
    chacha20_poly1305,
};

}  // namespace yanterm::ssh::transport
