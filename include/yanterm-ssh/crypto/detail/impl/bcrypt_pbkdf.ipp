#pragma once

#include <yanterm-ssh/crypto/detail/bcrypt_pbkdf.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/crypto/detail/impl/bcrypt_pbkdf.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/crypto/detail/blowfish.hpp>

#include <array>
#include <cstring>
#include <memory>
#include <new>
#include <utility>

namespace yanterm::ssh::crypto::detail {

YANTERM_SSH_INLINE void bcrypt_hash(std::span<std::byte, 32> out,
                        std::span<const std::byte> shapass,   // 64
                        std::span<const std::byte> shasalt) { // 64
    blowfish_ctx ctx{};
    blowfish_initstate(ctx);
    blowfish_expandstate(ctx, shapass, shasalt);
    for (int i = 0; i < 64; ++i) {
        blowfish_expand0state(ctx, shasalt);
        blowfish_expand0state(ctx, shapass);
    }
    std::array<std::byte, 32> block{};
    std::memcpy(block.data(), bcrypt_magic.data(), 32);
    for (std::size_t i = 0; i < 32; i += 8) {
        std::uint32_t l = (std::to_integer<std::uint32_t>(block[i+0]) << 24)
                        | (std::to_integer<std::uint32_t>(block[i+1]) << 16)
                        | (std::to_integer<std::uint32_t>(block[i+2]) << 8)
                        |  std::to_integer<std::uint32_t>(block[i+3]);
        std::uint32_t r = (std::to_integer<std::uint32_t>(block[i+4]) << 24)
                        | (std::to_integer<std::uint32_t>(block[i+5]) << 16)
                        | (std::to_integer<std::uint32_t>(block[i+6]) << 8)
                        |  std::to_integer<std::uint32_t>(block[i+7]);
        for (int j = 0; j < 64; ++j) blowfish_encipher(ctx, l, r);
        block[i+0] = std::byte((l >> 24) & 0xff);
        block[i+1] = std::byte((l >> 16) & 0xff);
        block[i+2] = std::byte((l >> 8) & 0xff);
        block[i+3] = std::byte(l & 0xff);
        block[i+4] = std::byte((r >> 24) & 0xff);
        block[i+5] = std::byte((r >> 16) & 0xff);
        block[i+6] = std::byte((r >> 8) & 0xff);
        block[i+7] = std::byte(r & 0xff);
    }
    // OpenBSD output is little-endian per 4-byte word
    for (std::size_t i = 0; i < 32; i += 4) {
        std::swap(block[i+0], block[i+3]);
        std::swap(block[i+1], block[i+2]);
    }
    std::memcpy(out.data(), block.data(), 32);
    secure_zero(std::span{block});
    secure_zero(std::as_writable_bytes(std::span{&ctx, 1}));
}

YANTERM_SSH_INLINE bool bcrypt_pbkdf(provider p,
                         std::span<const std::byte> password,
                         std::span<const std::byte> salt,
                         std::uint32_t rounds,
                         std::span<std::byte> out) noexcept {
    if (!p || rounds < 1 || password.empty() || salt.empty() || out.empty()) return false;
    if (salt.size() > (1u << 20) || out.size() > 1024) return false;

    std::array<std::byte, 64> shapass{};
    if (!p.hash(hash_id::sha512, password, shapass)) return false;

    const std::size_t keylen = out.size();
    const std::size_t nblocks = (keylen + 31u) / 32u;
    std::array<std::byte, 1024> key{};

    std::unique_ptr<std::byte[]> salt_cnt{new (std::nothrow) std::byte[salt.size() + 4]};
    if (!salt_cnt) {
        secure_zero(shapass);
        return false;
    }
    std::memcpy(salt_cnt.get(), salt.data(), salt.size());

    for (std::size_t block = 1; block <= nblocks; ++block) {
        salt_cnt[salt.size() + 0] = std::byte((block >> 24) & 0xff);
        salt_cnt[salt.size() + 1] = std::byte((block >> 16) & 0xff);
        salt_cnt[salt.size() + 2] = std::byte((block >> 8) & 0xff);
        salt_cnt[salt.size() + 3] = std::byte(block & 0xff);
        std::array<std::byte, 64> shasalt{};
        if (!p.hash(hash_id::sha512,
                    std::span<const std::byte>{salt_cnt.get(), salt.size() + 4},
                    shasalt)) {
            secure_zero(shapass);
            secure_zero(std::span{key}.first(nblocks * 32u));
            secure_zero(std::span<std::byte>{salt_cnt.get(), salt.size() + 4});
            return false;
        }

        std::array<std::byte, 32> tmp{};
        bcrypt_hash(tmp, shapass, shasalt);
        std::array<std::byte, 32> acc = tmp;
        for (std::uint32_t i = 2; i <= rounds; ++i) {
            if (!p.hash(hash_id::sha512, tmp, shasalt)) {
                secure_zero(shapass);
                secure_zero(tmp);
                secure_zero(acc);
                secure_zero(std::span{key}.first(nblocks * 32u));
                secure_zero(std::span<std::byte>{salt_cnt.get(), salt.size() + 4});
                return false;
            }
            bcrypt_hash(tmp, shapass, shasalt);
            for (std::size_t j = 0; j < 32; ++j) acc[j] ^= tmp[j];
        }
        // Stripe across blocks (OpenBSD)
        for (std::size_t i = 0; i < 32; ++i) {
            key[i * nblocks + (block - 1)] = acc[i];
        }
        secure_zero(tmp);
        secure_zero(acc);
        secure_zero(shasalt);
    }
    std::memcpy(out.data(), key.data(), keylen);
    secure_zero(shapass);
    secure_zero(std::span{key}.first(nblocks * 32u));
    secure_zero(std::span<std::byte>{salt_cnt.get(), salt.size() + 4});
    return true;
}

}  // namespace yanterm::ssh::crypto::detail
