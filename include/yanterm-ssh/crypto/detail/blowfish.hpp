#pragma once

// Header-only port of OpenBSD sys/crypto/blowfish (Niels Provos).
// Copyright 1997 Niels Provos <provos@physnet.uni-hamburg.de>
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. The name of the author may not be used to endorse or promote products
//    derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
// IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <yanterm-ssh/detail/config.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

namespace yanterm::ssh::crypto::detail {

inline constexpr int blowfish_n = 16;

struct blowfish_ctx {
    std::uint32_t S[4][256];
    std::uint32_t P[blowfish_n + 2];
};

[[nodiscard]] std::uint32_t blowfish_f(const blowfish_ctx& ctx, std::uint32_t x) noexcept;

void blowfish_encipher(blowfish_ctx& ctx, std::uint32_t& xl, std::uint32_t& xr) noexcept;

[[nodiscard]] std::uint32_t blowfish_stream2word(std::span<const std::byte> data,
                                                 std::size_t& current) noexcept;

void blowfish_initstate(blowfish_ctx& ctx) noexcept;

void blowfish_expand0state(blowfish_ctx& ctx, std::span<const std::byte> key) noexcept;

// C++ argument order is (key, data). OpenBSD C is Blowfish_expandstate(c, data, key).
void blowfish_expandstate(blowfish_ctx& ctx,
                          std::span<const std::byte> key,
                          std::span<const std::byte> data) noexcept;

}  // namespace yanterm::ssh::crypto::detail

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/crypto/detail/impl/blowfish.ipp>
#endif
