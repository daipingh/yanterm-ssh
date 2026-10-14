#pragma once

#include <yanterm-ssh/keys/fingerprint.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/keys/impl/fingerprint.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/keys/detail/base64.hpp>

#include <array>

namespace yanterm::ssh::keys {

YANTERM_SSH_INLINE std::string fingerprint_sha256(crypto::provider p, const public_key& key) {
    std::array<std::byte, 32> h{};
    if (!p.hash(crypto::hash_id::sha256, key.blob(), h)) return {};
    return "SHA256:" + detail::base64_encode(h, /*pad=*/false);
}

}  // namespace yanterm::ssh::keys
