#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/crypto/provider.hpp>
#include <yanterm-ssh/keys/public_key.hpp>

#include <string>

namespace yanterm::ssh::keys {

std::string fingerprint_sha256(crypto::provider p, const public_key& key);

}  // namespace yanterm::ssh::keys

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/keys/impl/fingerprint.ipp>
#endif
