#pragma once

// Optional blocking file I/O for keys: read a private-key file, check that
// POSIX group/other bits are clear, and atomically replace a file (tmp +
// fsync + rename). This header is opt-in. Including it performs synchronous
// syscalls on the calling thread; it is not part of the sans-IO core. In
// yanterm-ssh-static it remains an opt-in API compiled into a separate object.

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/crypto/provider.hpp>
#include <yanterm-ssh/keys/private_key.hpp>

#include <cstddef>
#include <span>
#include <system_error>
#include <vector>

namespace yanterm::ssh::keys::io {

std::error_code read_file(const char* path, std::vector<std::byte>& out);
std::error_code check_private_key_permissions(const char* path);
std::error_code atomic_write(const char* path, std::span<const std::byte> data);
std::error_code load_private_key(const char* path, crypto::provider p,
                                 std::span<const std::byte> passphrase,
                                 private_key& out);

}  // namespace yanterm::ssh::keys::io

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/keys/impl/io.ipp>
#endif
