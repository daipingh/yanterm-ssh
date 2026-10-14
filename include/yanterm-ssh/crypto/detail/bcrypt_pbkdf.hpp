#pragma once

// Header-only port of OpenBSD lib/libutil/bcrypt_pbkdf.c (Ted Unangst).
// Copyright (c) 2013 Ted Unangst <tedu@openbsd.org>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/crypto/provider.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace yanterm::ssh::crypto::detail {

inline constexpr std::string_view bcrypt_magic = "OxychromaticBlowfishSwatDynamite";

void bcrypt_hash(std::span<std::byte, 32> out,
                 std::span<const std::byte> shapass,
                 std::span<const std::byte> shasalt);

bool bcrypt_pbkdf(provider p, std::span<const std::byte> password,
                  std::span<const std::byte> salt, std::uint32_t rounds,
                  std::span<std::byte> out) noexcept;

}  // namespace yanterm::ssh::crypto::detail

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/crypto/detail/impl/bcrypt_pbkdf.ipp>
#endif
