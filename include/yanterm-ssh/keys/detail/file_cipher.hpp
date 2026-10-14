#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/crypto/algorithms.hpp>
#include <yanterm-ssh/crypto/provider.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <system_error>
#include <vector>

namespace yanterm::ssh::keys::detail {

struct file_cipher {
    std::string_view name;
    crypto::cipher_id id{};
    std::size_t key_len = 0, iv_len = 0, tag_len = 0, block = 8;
    enum class kind { none, ctr, cbc, gcm, chacha_file } k{};
};

inline constexpr file_cipher file_ciphers[] = {
    {"none", {}, 0, 0, 0, 8, file_cipher::kind::none},
    {"aes128-ctr", crypto::cipher_id::aes128_ctr, 16, 16, 0, 16, file_cipher::kind::ctr},
    {"aes192-ctr", crypto::cipher_id::aes192_ctr, 24, 16, 0, 16, file_cipher::kind::ctr},
    {"aes256-ctr", crypto::cipher_id::aes256_ctr, 32, 16, 0, 16, file_cipher::kind::ctr},
    {"aes128-cbc", crypto::cipher_id::aes128_cbc, 16, 16, 0, 16, file_cipher::kind::cbc},
    {"aes192-cbc", crypto::cipher_id::aes192_cbc, 24, 16, 0, 16, file_cipher::kind::cbc},
    {"aes256-cbc", crypto::cipher_id::aes256_cbc, 32, 16, 0, 16, file_cipher::kind::cbc},
    {"aes128-gcm@openssh.com", crypto::cipher_id::aes128_gcm, 16, 12, 16, 16,
     file_cipher::kind::gcm},
    {"aes256-gcm@openssh.com", crypto::cipher_id::aes256_gcm, 32, 12, 16, 16,
     file_cipher::kind::gcm},
    {"chacha20-poly1305@openssh.com", crypto::cipher_id::chacha20, 64, 0, 16, 8,
     file_cipher::kind::chacha_file},
};

[[nodiscard]] inline const file_cipher* find_file_cipher(std::string_view name) noexcept {
    for (const auto& e : file_ciphers) {
        if (e.name == name) return &e;
    }
    return nullptr;
}

namespace file_cipher_impl {

inline bool split_key_iv(const file_cipher& c, std::span<const std::byte> key_iv,
                         std::span<const std::byte>& key, std::span<const std::byte>& iv) noexcept {
    if (key_iv.size() != c.key_len + c.iv_len) return false;
    key = key_iv.first(c.key_len);
    iv = key_iv.subspan(c.key_len, c.iv_len);
    return true;
}

// OpenSSH / EVP_chacha20: counter(4, LE) || 4×00 || seqnr(8, BE). File uses seqnr=0.
inline void make_chacha_file_iv(std::array<std::byte, 16>& iv, std::uint32_t counter) noexcept {
    iv[0] = static_cast<std::byte>(counter & 0xffu);
    iv[1] = static_cast<std::byte>((counter >> 8) & 0xffu);
    iv[2] = static_cast<std::byte>((counter >> 16) & 0xffu);
    iv[3] = static_cast<std::byte>((counter >> 24) & 0xffu);
    for (std::size_t i = 4; i < 16; ++i) iv[i] = std::byte{0};
}

std::error_code chacha_file_crypt(crypto::provider p, std::span<const std::byte> key64,
                                  std::span<const std::byte> in, std::span<std::byte> out,
                                  std::span<std::byte, 16> tag, bool encrypt);

}  // namespace file_cipher_impl

std::error_code seal(crypto::provider p, const file_cipher& c,
                     std::span<const std::byte> key_iv, std::span<const std::byte> plain,
                     std::vector<std::byte>& cipher_and_tag);

std::error_code open(crypto::provider p, const file_cipher& c,
                     std::span<const std::byte> key_iv,
                     std::span<const std::byte> cipher_and_tag, std::vector<std::byte>& plain);

}  // namespace yanterm::ssh::keys::detail

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/keys/detail/impl/file_cipher.ipp>
#endif
