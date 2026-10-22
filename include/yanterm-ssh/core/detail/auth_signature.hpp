#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/crypto/algorithms.hpp>
#include <yanterm-ssh/crypto/provider.hpp>
#include <yanterm-ssh/wire/types.hpp>

#include <cstddef>
#include <span>
#include <string_view>
#include <system_error>

namespace yanterm::ssh::core::detail {

void write_publickey_signed_data(
    wire::writer& w,
    std::span<const std::byte> session_id,
    std::string_view user,
    std::string_view service,
    std::string_view alg,
    std::span<const std::byte> blob);

// Appends the SSH signature blob (string algorithm, string signature).
std::error_code sign_publickey_data(crypto::provider p, const crypto::private_key_material& priv,
                                    std::string_view algorithm, crypto::sig_id sig,
                                    std::span<const std::byte> data, wire::writer& sig_blob);

std::error_code verify_userauth_publickey(crypto::provider p, std::span<const std::byte> session_id,
                                          std::string_view user, std::string_view service,
                                          std::string_view alg, std::span<const std::byte> blob,
                                          std::span<const std::byte> signature);

}  // namespace yanterm::ssh::core::detail

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/core/detail/impl/auth_signature.ipp>
#endif
