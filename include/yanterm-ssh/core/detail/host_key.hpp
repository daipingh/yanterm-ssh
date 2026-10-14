#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/wire/types.hpp>
#include <yanterm-ssh/crypto/algorithms.hpp>
#include <yanterm-ssh/crypto/provider.hpp>

#include <span>
#include <string_view>
#include <system_error>

namespace yanterm::ssh::core::detail {

// A parsed SSH host key blob. Borrows from the blob it was parsed out of.
struct host_key_view {
    std::string_view algorithm_name;  // as it appeared in the blob
    crypto::sig_id algorithm{};
    crypto::public_key_material material;
    std::span<const std::byte> blob;  // the original K_S, needed for the exchange hash
};

[[nodiscard]] inline bool key_compatible_with_sig(const host_key_view& key,
                                                  crypto::sig_id sig) noexcept {
    if (key.algorithm_name == "ssh-rsa") return crypto::is_rsa_sig(sig);
    if (crypto::is_sm2_sig(key.algorithm) && crypto::is_sm2_sig(sig)) return true;
    return key.algorithm == sig;
}

std::error_code parse_host_key(std::span<const std::byte> blob, host_key_view& out);

std::error_code verify_signature(crypto::provider p, const host_key_view& key,
                                 std::string_view expected_algorithm,
                                 std::span<const std::byte> signature_blob,
                                 std::span<const std::byte> message,
                                 crypto::sig_id* detected = nullptr);

std::error_code encode_host_key(const crypto::public_key_material& key, wire::writer& out);

std::error_code encode_signature(std::string_view algorithm_name,
                                 std::span<const std::byte> raw_signature, wire::writer& out);

}  // namespace yanterm::ssh::core::detail

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/core/detail/impl/host_key.ipp>
#endif
