#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/core/detail/packet.hpp>
#include <yanterm-ssh/kex/algorithms.hpp>
#include <yanterm-ssh/core/types.hpp>
#include <yanterm-ssh/crypto/algorithms.hpp>
#include <yanterm-ssh/crypto/provider.hpp>

#include <cstddef>
#include <span>
#include <system_error>

namespace yanterm::ssh::core::detail {

[[nodiscard]] inline bool letter_ok(char letter) noexcept {
    return letter >= 'A' && letter <= 'F';
}

// RFC 4253 section 7.2 key derivation.
// `letter` is one of 'A'..'F'. `out` may be longer than one hash output, in
// which case the extension rule below applies.
//
// `shared_secret_mpint` must already be the SSH encoding of K as written by
// key_exchange::write_shared_secret: an mpint (4-byte length prefix plus
// payload, including any leading 0x00 pad), or a string for
// mlkem768x25519-sha256. Do not pass the raw value.
std::error_code derive_key(crypto::provider p, crypto::hash_id h,
                            std::span<const std::byte> shared_secret_mpint,
                            std::span<const std::byte> exchange_hash,
                            char letter,
                            std::span<const std::byte> session_id,
                            std::span<std::byte> out);

[[nodiscard]] std::error_code load_direction(
    crypto::provider p, crypto::hash_id kdf_hash, packet_mode mode, crypto::cipher_id cipher,
    crypto::hash_id mac_hash, std::span<const std::byte> shared_secret_mpint,
    std::span<const std::byte> exchange_hash, std::span<const std::byte> session_id, char iv_letter,
    char key_letter, char mac_letter, direction_state& st, bool aead_encrypt);

// Builds both directions from a completed key exchange.
std::error_code make_direction_states(crypto::provider p, const ::yanterm::ssh::kex::negotiated& n,
                                       std::span<const std::byte> shared_secret_mpint,
                                       std::span<const std::byte> exchange_hash,
                                       std::span<const std::byte> session_id,
                                       ::yanterm::ssh::core::role r,
                                       direction_state& outbound,
                                       direction_state& inbound);

}  // namespace yanterm::ssh::core::detail

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/core/detail/impl/kdf.ipp>
#endif
