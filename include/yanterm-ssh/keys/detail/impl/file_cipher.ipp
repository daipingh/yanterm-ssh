#pragma once

#include <yanterm-ssh/keys/detail/file_cipher.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/keys/detail/impl/file_cipher.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/detail/error.hpp>

#include <algorithm>

namespace yanterm::ssh::keys::detail {

namespace file_cipher_impl {

YANTERM_SSH_INLINE std::error_code chacha_file_crypt(crypto::provider p, std::span<const std::byte> key64,
                                         std::span<const std::byte> in, std::span<std::byte> out,
                                         std::span<std::byte, 16> tag, bool encrypt) {
    if (key64.size() != 64 || out.size() < in.size()) {
        return code::invalid_format;
    }
    // K1(32) || K2(32); aadlen=0 so K1 is unused.
    const auto k2 = key64.subspan(32, 32);

    std::array<std::byte, 16> iv{};
    make_chacha_file_iv(iv, /*counter=*/0);
    auto poly_stream = p.new_cipher(crypto::cipher_id::chacha20, k2, true);
    if (!poly_stream || !poly_stream.set_iv(iv)) {
        return code::cipher_failure;
    }
    std::array<std::byte, 32> zeros{};
    std::array<std::byte, 32> poly_key{};
    if (!poly_stream.update(zeros, poly_key)) {
        crypto::secure_zero(poly_key);
        return code::cipher_failure;
    }

    make_chacha_file_iv(iv, /*counter=*/1);
    auto payload = p.new_cipher(crypto::cipher_id::chacha20, k2, true);
    if (!payload || !payload.set_iv(iv)) {
        crypto::secure_zero(poly_key);
        return code::cipher_failure;
    }

    if (encrypt) {
        if (!payload.update(in, out.first(in.size()))) {
            crypto::secure_zero(poly_key);
            return code::cipher_failure;
        }
        if (!p.poly1305(poly_key, out.first(in.size()), tag)) {
            crypto::secure_zero(poly_key);
            return code::mac_failure;
        }
        crypto::secure_zero(poly_key);
        return {};
    }

    std::array<std::byte, 16> expect{};
    if (!p.poly1305(poly_key, in, expect)) {
        crypto::secure_zero(poly_key);
        return code::mac_failure;
    }
    crypto::secure_zero(poly_key);
    if (!p.constant_time_eq(expect, tag)) {
        return code::decrypt_failure;
    }
    if (!payload.update(in, out.first(in.size()))) {
        return code::cipher_failure;
    }
    return {};
}

}  // namespace file_cipher_impl

YANTERM_SSH_INLINE std::error_code seal(crypto::provider p, const file_cipher& c,
                            std::span<const std::byte> key_iv, std::span<const std::byte> plain,
                            std::vector<std::byte>& cipher_and_tag) {
    if (!p) return code::crypto_backend_failure;
    std::span<const std::byte> key;
    std::span<const std::byte> iv;
    if (!file_cipher_impl::split_key_iv(c, key_iv, key, iv)) {
        return code::invalid_format;
    }

    switch (c.k) {
    case file_cipher::kind::none:
        cipher_and_tag.assign(plain.begin(), plain.end());
        return {};
    case file_cipher::kind::ctr: {
        auto stream = p.new_cipher(c.id, key, true);
        if (!stream || !stream.set_iv(iv)) return code::cipher_failure;
        cipher_and_tag.resize(plain.size());
        if (!stream.update(plain, cipher_and_tag)) {
            return code::cipher_failure;
        }
        return {};
    }
    case file_cipher::kind::cbc: {
        if (c.block == 0 || plain.size() % c.block != 0) {
            return code::invalid_format;
        }
        cipher_and_tag.resize(plain.size());
        if (!p.cbc_crypt(c.id, true, key, iv, plain, cipher_and_tag)) {
            return code::cipher_failure;
        }
        return {};
    }
    case file_cipher::kind::gcm: {
        auto aead = p.new_aead(c.id, key, true);
        if (!aead) return code::aead_failure;
        cipher_and_tag.resize(plain.size() + c.tag_len);
        auto ct = std::span{cipher_and_tag}.first(plain.size());
        auto tag = std::span{cipher_and_tag}.subspan(plain.size(), c.tag_len);
        if (!aead.begin(iv, {})) {
            return code::aead_failure;
        }
        if (!aead.update(plain, ct)) {
            return code::aead_failure;
        }
        if (!aead.final(tag)) {
            return code::crypto_backend_failure;
        }
        return {};
    }
    case file_cipher::kind::chacha_file: {
        cipher_and_tag.resize(plain.size() + c.tag_len);
        auto ct = std::span{cipher_and_tag}.first(plain.size());
        auto tag = std::span<std::byte, 16>{cipher_and_tag.data() + plain.size(), 16};
        return file_cipher_impl::chacha_file_crypt(p, key, plain, ct, tag, true);
    }
    }
    return code::unsupported_algorithm;
}

YANTERM_SSH_INLINE std::error_code open(crypto::provider p, const file_cipher& c,
                            std::span<const std::byte> key_iv,
                            std::span<const std::byte> cipher_and_tag, std::vector<std::byte>& plain) {
    if (!p) return code::crypto_backend_failure;
    std::span<const std::byte> key;
    std::span<const std::byte> iv;
    if (!file_cipher_impl::split_key_iv(c, key_iv, key, iv)) {
        return code::invalid_format;
    }
    if (cipher_and_tag.size() < c.tag_len) return code::invalid_format;
    const std::size_t body_len = cipher_and_tag.size() - c.tag_len;
    if (c.block != 0 && body_len % c.block != 0) return code::invalid_format;

    switch (c.k) {
    case file_cipher::kind::none:
        plain.assign(cipher_and_tag.begin(), cipher_and_tag.end());
        return {};
    case file_cipher::kind::ctr: {
        auto stream = p.new_cipher(c.id, key, true);
        if (!stream || !stream.set_iv(iv)) return code::cipher_failure;
        plain.resize(cipher_and_tag.size());
        if (!stream.update(cipher_and_tag, plain)) {
            return code::cipher_failure;
        }
        return {};
    }
    case file_cipher::kind::cbc: {
        plain.resize(cipher_and_tag.size());
        if (!p.cbc_crypt(c.id, false, key, iv, cipher_and_tag, plain)) {
            return code::cipher_failure;
        }
        return {};
    }
    case file_cipher::kind::gcm: {
        auto aead = p.new_aead(c.id, key, false);
        if (!aead) return code::aead_failure;
        const auto ct = cipher_and_tag.first(body_len);
        std::array<std::byte, 16> tag{};
        const auto tag_src = cipher_and_tag.subspan(body_len, c.tag_len);
        std::copy(tag_src.begin(), tag_src.end(), tag.begin());
        plain.resize(body_len);
        if (!aead.begin(iv, {})) {
            crypto::secure_zero(std::span{plain});
            plain.clear();
            return code::aead_failure;
        }
        if (!aead.update(ct, plain)) {
            crypto::secure_zero(std::span{plain});
            plain.clear();
            return code::aead_failure;
        }
        if (!aead.final(tag)) {
            crypto::secure_zero(std::span{plain});
            plain.clear();
            return code::decrypt_failure;
        }
        return {};
    }
    case file_cipher::kind::chacha_file: {
        const auto ct = cipher_and_tag.first(body_len);
        auto tag_src = cipher_and_tag.subspan(body_len, 16);
        std::array<std::byte, 16> tag{};
        std::copy(tag_src.begin(), tag_src.end(), tag.begin());
        plain.resize(body_len);
        const auto ec = file_cipher_impl::chacha_file_crypt(p, key, ct, plain, tag, false);
        if (ec) plain.clear();
        return ec;
    }
    }
    return code::unsupported_algorithm;
}

}  // namespace yanterm::ssh::keys::detail
