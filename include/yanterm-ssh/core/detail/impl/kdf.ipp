#pragma once

#include <yanterm-ssh/core/detail/kdf.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/core/detail/impl/kdf.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/detail/error.hpp>
#include <yanterm-ssh/crypto/secure_buffer.hpp>

#include <algorithm>

namespace yanterm::ssh::core::detail {

YANTERM_SSH_INLINE std::error_code derive_key(crypto::provider p, crypto::hash_id h,
                                  std::span<const std::byte> shared_secret_mpint,
                                  std::span<const std::byte> exchange_hash,
                                  char letter,
                                  std::span<const std::byte> session_id,
                                  std::span<std::byte> out) {
    if (!p) return code::crypto_backend_failure;
    if (!letter_ok(letter)) return code::invalid_format;
    const std::size_t digest = crypto::hash_output_size(h);
    if (digest == 0) return code::unsupported_algorithm;
    if (out.empty()) return {};

    crypto::hash_ctx ctx = p.new_hash(h);
    if (!ctx) return code::hash_failure;

    crypto::secure_bytes block(digest);
    crypto::secure_bytes so_far;
    so_far.reserve(digest * ((out.size() + digest - 1) / digest));

    // K1 = HASH(K ‖ H ‖ letter ‖ session_id)
    ctx.update(shared_secret_mpint);
    ctx.update(exchange_hash);
    const std::byte letter_b{static_cast<std::byte>(letter)};
    ctx.update(std::span{&letter_b, 1});
    ctx.update(session_id);
    if (!ctx.final_into(block.span())) return code::hash_failure;
    so_far.assign(block.span());

    std::size_t filled = 0;
    const auto take = [&](std::span<const std::byte> src) {
        const std::size_t n = (std::min)(src.size(), out.size() - filled);
        std::copy_n(src.begin(), n, out.begin() + static_cast<std::ptrdiff_t>(filled));
        filled += n;
    };
    take(block.span());
    if (filled == out.size()) return {};

    // Ki = HASH(K ‖ H ‖ K1 ‖ … ‖ K{i-1})
    while (filled < out.size()) {
        ctx.update(shared_secret_mpint);
        ctx.update(exchange_hash);
        ctx.update(so_far.span());
        if (!ctx.final_into(block.span())) return code::hash_failure;
        so_far.append(block.span());
        take(block.span());
    }
    return {};
}

[[nodiscard]] YANTERM_SSH_INLINE std::error_code load_direction(
    crypto::provider p, crypto::hash_id kdf_hash, packet_mode mode, crypto::cipher_id cipher,
    crypto::hash_id mac_hash, std::span<const std::byte> shared_secret_mpint,
    std::span<const std::byte> exchange_hash, std::span<const std::byte> session_id, char iv_letter,
    char key_letter, char mac_letter, direction_state& st, bool aead_encrypt) {
    st = direction_state{};
    st.mode = mode;
    st.sequence_number = 0;

    switch (mode) {
    case packet_mode::ctr_encrypt_and_mac:
    case packet_mode::ctr_encrypt_then_mac:
    case packet_mode::cbc_encrypt_and_mac:
    case packet_mode::cbc_encrypt_then_mac: {
        const std::size_t key_len = crypto::cipher_key_size(cipher);
        const std::size_t iv_len = 16;
        const std::size_t mac_len = crypto::hash_output_size(mac_hash);
        if (key_len == 0 || mac_len == 0) return code::unsupported_algorithm;

        crypto::secure_bytes key(key_len);
        crypto::secure_bytes iv(iv_len);
        crypto::secure_bytes mac_key(mac_len);
        if (auto ec = derive_key(p, kdf_hash, shared_secret_mpint, exchange_hash, key_letter,
                                 session_id, key.span())) {
            return ec;
        }
        if (auto ec = derive_key(p, kdf_hash, shared_secret_mpint, exchange_hash, iv_letter,
                                 session_id, iv.span())) {
            return ec;
        }
        if (auto ec = derive_key(p, kdf_hash, shared_secret_mpint, exchange_hash, mac_letter,
                                 session_id, mac_key.span())) {
            return ec;
        }

        st.block_size = crypto::cipher_block_size(cipher);
        st.mac_length = mac_len;
        const bool cbc = mode == packet_mode::cbc_encrypt_and_mac
                      || mode == packet_mode::cbc_encrypt_then_mac;
        const bool encrypt = cbc ? aead_encrypt : true;
        st.cipher = p.new_cipher(cipher, key.span(), encrypt);
        if (!st.cipher) return code::cipher_failure;
        if (!st.cipher.set_iv(iv.span())) return code::cipher_failure;
        st.mac = p.new_hmac(mac_hash, mac_key.span());
        if (!st.mac) return code::hash_failure;
        return {};
    }
    case packet_mode::gcm: {
        const std::size_t key_len = crypto::cipher_key_size(cipher);
        if (key_len == 0) return code::unsupported_algorithm;
        crypto::secure_bytes key(key_len);
        crypto::secure_array<12> iv;
        if (auto ec = derive_key(p, kdf_hash, shared_secret_mpint, exchange_hash, key_letter,
                                 session_id, key.span())) {
            return ec;
        }
        if (auto ec = derive_key(p, kdf_hash, shared_secret_mpint, exchange_hash, iv_letter,
                                 session_id, iv.span())) {
            return ec;
        }
        st.block_size = crypto::cipher_block_size(cipher);
        st.mac_length = 16;
        std::copy(iv.span().begin(), iv.span().end(), st.iv.begin());
        st.aead = p.new_aead(cipher, key.span(), aead_encrypt);
        if (!st.aead) return code::aead_failure;
        return {};
    }
    case packet_mode::chacha20_poly1305: {
        crypto::secure_array<64> key;
        if (auto ec = derive_key(p, kdf_hash, shared_secret_mpint, exchange_hash, key_letter,
                                 session_id, key.span())) {
            return ec;
        }
        st.block_size = 8;
        st.mac_length = 16;
        const auto k2 = key.span().first(32);
        const auto k1 = key.span().subspan(32, 32);
        st.cipher = p.new_cipher(crypto::cipher_id::chacha20, k2, true);
        st.length_cipher = p.new_cipher(crypto::cipher_id::chacha20, k1, true);
        if (!st.cipher || !st.length_cipher) return code::cipher_failure;
        return {};
    }
    case packet_mode::plaintext:
        return code::invalid_state;
    }
    return code::invalid_state;
}

YANTERM_SSH_INLINE std::error_code make_direction_states(crypto::provider p, const ::yanterm::ssh::kex::negotiated& n,
                                             std::span<const std::byte> shared_secret_mpint,
                                             std::span<const std::byte> exchange_hash,
                                             std::span<const std::byte> session_id,
                                             ::yanterm::ssh::core::role r,
                                             direction_state& outbound,
                                             direction_state& inbound) {
    if (!p) return code::crypto_backend_failure;

    direction_state c2s;
    direction_state s2c;
    if (auto ec = load_direction(p, n.exchange_hash, n.mode_c2s, n.cipher_c2s, n.mac_c2s,
                                         shared_secret_mpint, exchange_hash, session_id, 'A', 'C',
                                         'E', c2s, r == ::yanterm::ssh::core::role::client)) {
        return ec;
    }
    if (auto ec = load_direction(p, n.exchange_hash, n.mode_s2c, n.cipher_s2c, n.mac_s2c,
                                         shared_secret_mpint, exchange_hash, session_id, 'B', 'D',
                                         'F', s2c, r == ::yanterm::ssh::core::role::server)) {
        return ec;
    }

    if (r == ::yanterm::ssh::core::role::client) {
        outbound = std::move(c2s);
        inbound = std::move(s2c);
    } else {
        outbound = std::move(s2c);
        inbound = std::move(c2s);
    }
    return {};
}

}  // namespace yanterm::ssh::core::detail
