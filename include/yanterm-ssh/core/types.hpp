#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/crypto/algorithms.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace yanterm::ssh::core {

enum class role : std::uint8_t { client, server };

enum class host_key_verdict : std::uint8_t { accept, reject };

// What connection::auth_publickey_sign_request chose for a publickey signature.
// `algorithm` is a static literal; `public_blob` views the blob passed to that
// call.
struct publickey_sign_request {
    std::string_view algorithm;
    crypto::sig_id sig{};
    std::span<const std::byte> public_blob;
};

}  // namespace yanterm::ssh::core
