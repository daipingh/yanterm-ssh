#pragma once

#include <yanterm-ssh/core/detail/kex_exchange.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/core/detail/impl/kex_exchange.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/wire/detail/messages.hpp>
#include <yanterm-ssh/kex/detail/tables.hpp>
#include <yanterm-ssh/detail/error.hpp>

#include <yanterm-ssh/crypto/secure_buffer.hpp>

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>

namespace yanterm::ssh::core::detail {

// RFC 10042 section 2.1: C_INIT = C_PK2 || C_PK1, S_REPLY = S_CT2 || S_PK1.
inline constexpr std::size_t mlkem768x25519_pq_public =
    crypto::kem_public_size(crypto::kem_id::mlkem768);
inline constexpr std::size_t mlkem768x25519_pq_ciphertext =
    crypto::kem_ciphertext_size(crypto::kem_id::mlkem768);
inline constexpr std::size_t mlkem768x25519_cl_public =
    crypto::kex_public_size(crypto::kex_id::curve25519);
inline constexpr std::size_t mlkem768x25519_init_size =
    mlkem768x25519_pq_public + mlkem768x25519_cl_public;
inline constexpr std::size_t mlkem768x25519_reply_size =
    mlkem768x25519_pq_ciphertext + mlkem768x25519_cl_public;

YANTERM_SSH_INLINE key_exchange::~key_exchange() { consume_shared_secret(); }

YANTERM_SSH_INLINE void key_exchange::consume_shared_secret() noexcept {
    secret_.wipe();
    kex_.reset();
    kem_.reset();
}

YANTERM_SSH_INLINE std::size_t key_exchange::peer_public_size() const noexcept {
    if (is_hybrid()) {
        return r_ == ::yanterm::ssh::core::role::client ? mlkem768x25519_reply_size
                                                         : mlkem768x25519_init_size;
    }
    return crypto::kex_public_size(n_.kex);
}

[[nodiscard]] YANTERM_SSH_INLINE crypto::kex_id kex_backend_id(crypto::kex_id id,
                                                               ::yanterm::ssh::core::role r) noexcept {
    if (id == crypto::kex_id::sm2_kap && r == ::yanterm::ssh::core::role::server) {
        return crypto::kex_id::sm2_kap_server;
    }
    return id;
}

YANTERM_SSH_INLINE std::error_code key_exchange::start(wire::writer& out) {
    if (r_ != ::yanterm::ssh::core::role::client) return code::invalid_state;
    if (!p_) return code::crypto_backend_failure;
    if (started_) return code::invalid_state;

    if (is_hybrid()) {
        if (auto ec = start_hybrid()) return ec;
    } else {
        kex_ = p_.new_kex(kex_backend_id(n_.kex, r_));
        if (!kex_) return code::kex_failure;

        local_public_.assign(crypto::kex_public_size(n_.kex), std::byte{0});
        std::size_t len = 0;
        if (!kex_.public_value(local_public_, len) || len != local_public_.size()) {
            return code::kex_failure;
        }
    }

    if (kex::detail::uses_ecdh_messages(n_.kex)) {
        wire::detail::kex_ecdh_init msg;
        msg.client_public = local_public_;
        msg.encode(out);
    } else {
        wire::detail::kexdh_init msg;
        msg.e = local_public_;
        msg.encode(out);
    }
    started_ = true;
    return {};
}

YANTERM_SSH_INLINE std::error_code key_exchange::accept_reply(
    const exchange_context& ctx, std::span<const std::byte> reply_payload,
    host_key_view& host_key, std::span<const std::byte>& hash) {
    if (r_ != ::yanterm::ssh::core::role::client) return code::invalid_state;
    if (!started_ || !kex_) return code::invalid_state;
    if (!p_) return code::crypto_backend_failure;

    std::span<const std::byte> ks;
    std::span<const std::byte> server_public;
    std::span<const std::byte> signature;

    if (kex::detail::uses_ecdh_messages(n_.kex)) {
        wire::reader r{reply_payload};
        wire::detail::kex_ecdh_reply msg;
        if (!msg.decode(r) || !r.empty()) {
            return code::invalid_kex_reply;
        }
        if (msg.server_public.size() != peer_public_size()) {
            return code::invalid_kex_reply;
        }
        ks = msg.host_key;
        server_public = msg.server_public;
        signature = msg.signature;
    } else {
        wire::reader r{reply_payload};
        wire::detail::kexdh_reply msg;
        if (!msg.decode(r) || !r.empty()) {
            return code::invalid_kex_reply;
        }
        if (msg.f.empty()) return code::invalid_kex_reply;
        ks = msg.host_key;
        server_public = msg.f;
        signature = msg.signature;
    }

    if (auto ec = parse_host_key(ks, host_key)) return ec;

    if (auto ec = is_hybrid() ? agree_hybrid_reply(server_public)
                              : agree_with_peer(server_public)) {
        return ec;
    }

    if (auto ec = compute_hash(ctx, ks, local_public_, server_public)) return ec;

    if (auto ec = verify_signature(p_, host_key, n_.host_key_name, signature, hash_,
                                   &host_sig_id_)) {
        return ec;
    }

    hash = hash_;
    return {};
}

YANTERM_SSH_INLINE std::error_code key_exchange::accept_init(
    const exchange_context& ctx, std::span<const std::byte> init_payload,
    std::span<const std::byte> host_key_blob, crypto::signing_key& signer, wire::writer& out,
    std::span<const std::byte>& hash) {
    if (r_ != ::yanterm::ssh::core::role::server) return code::invalid_state;
    if (!p_) return code::crypto_backend_failure;
    if (!signer) return code::sign_failure;
    if (started_) return code::invalid_state;

    std::span<const std::byte> client_public;
    if (kex::detail::uses_ecdh_messages(n_.kex)) {
        wire::reader r{init_payload};
        wire::detail::kex_ecdh_init msg;
        if (!msg.decode(r) || !r.empty()) {
            return code::invalid_kex_reply;
        }
        if (msg.client_public.size() != peer_public_size()) {
            return code::invalid_kex_reply;
        }
        client_public = msg.client_public;
    } else {
        wire::reader r{init_payload};
        wire::detail::kexdh_init msg;
        if (!msg.decode(r) || !r.empty()) {
            return code::invalid_kex_reply;
        }
        if (msg.e.empty()) return code::invalid_kex_reply;
        client_public = msg.e;
    }

    // Keep a stable copy: peer spans borrow from the caller's init buffer,
    // but we also need local_public_ owned before encoding the reply.
    peer_public_.assign(client_public.begin(), client_public.end());

    if (is_hybrid()) {
        if (auto ec = accept_hybrid_init()) return ec;
    } else {
        kex_ = p_.new_kex(kex_backend_id(n_.kex, r_));
        if (!kex_) return code::kex_failure;

        local_public_.assign(crypto::kex_public_size(n_.kex), std::byte{0});
        std::size_t len = 0;
        if (!kex_.public_value(local_public_, len) || len != local_public_.size()) {
            return code::kex_failure;
        }

        if (auto ec = agree_with_peer(peer_public_)) return ec;
    }

    if (auto ec = compute_hash(ctx, host_key_blob, peer_public_, local_public_)) return ec;

    std::array<std::byte, crypto::max_signature_size> raw_sig{};
    std::size_t sig_len = 0;
    if (!signer.sign(hash_, raw_sig, sig_len)) {
        return code::sign_failure;
    }

    wire::writer sig_w;
    if (auto ec = encode_signature(
            n_.host_key_name, std::span<const std::byte>{raw_sig}.first(sig_len), sig_w)) {
        return ec;
    }

    if (kex::detail::uses_ecdh_messages(n_.kex)) {
        wire::detail::kex_ecdh_reply msg;
        msg.host_key = host_key_blob;
        msg.server_public = local_public_;
        msg.signature = sig_w.data();
        msg.encode(out);
    } else {
        wire::detail::kexdh_reply msg;
        msg.host_key = host_key_blob;
        msg.f = local_public_;
        msg.signature = sig_w.data();
        msg.encode(out);
    }

    started_ = true;
    hash = hash_;
    return {};
}

YANTERM_SSH_INLINE std::error_code key_exchange::start_hybrid() {
    kem_ = p_.new_kem(crypto::kem_id::mlkem768);
    if (!kem_) return code::kex_failure;
    kex_ = p_.new_kex(crypto::kex_id::curve25519);
    if (!kex_) return code::kex_failure;

    local_public_.assign(mlkem768x25519_init_size, std::byte{0});
    const std::span<std::byte> out{local_public_};
    std::size_t len = 0;
    if (!kem_.public_key(out.first(mlkem768x25519_pq_public), len)
        || len != mlkem768x25519_pq_public) {
        return code::kex_failure;
    }
    if (!kex_.public_value(out.subspan(mlkem768x25519_pq_public), len)
        || len != mlkem768x25519_cl_public) {
        return code::kex_failure;
    }
    return {};
}

YANTERM_SSH_INLINE std::error_code key_exchange::accept_hybrid_init() {
    assert(peer_public_.size() == mlkem768x25519_init_size);
    const std::span<const std::byte> c_init{peer_public_};

    local_public_.assign(mlkem768x25519_reply_size, std::byte{0});
    const std::span<std::byte> out{local_public_};

    constexpr std::size_t pq_secret = crypto::kem_secret_size(crypto::kem_id::mlkem768);
    crypto::secure_bytes k_pq(pq_secret);
    std::size_t ct_len = 0;
    std::size_t ss_len = 0;
    if (!p_.encapsulate(crypto::kem_id::mlkem768, c_init.first(mlkem768x25519_pq_public),
                        out.first(mlkem768x25519_pq_ciphertext), ct_len, k_pq.span(), ss_len)
        || ct_len != mlkem768x25519_pq_ciphertext || ss_len != pq_secret) {
        return code::invalid_kex_reply;
    }

    kex_ = p_.new_kex(crypto::kex_id::curve25519);
    if (!kex_) return code::kex_failure;
    std::size_t len = 0;
    if (!kex_.public_value(out.subspan(mlkem768x25519_pq_ciphertext), len)
        || len != mlkem768x25519_cl_public) {
        return code::kex_failure;
    }

    crypto::secure_bytes k_cl(crypto::kex_secret_size(crypto::kex_id::curve25519));
    if (!kex_.agree(c_init.subspan(mlkem768x25519_pq_public), k_cl.span(), len)
        || len != k_cl.size()) {
        return code::weak_shared_secret;
    }
    return combine_hybrid_secret(k_pq.span(), k_cl.span());
}

YANTERM_SSH_INLINE std::error_code key_exchange::agree_hybrid_reply(
    std::span<const std::byte> server_reply) {
    assert(server_reply.size() == mlkem768x25519_reply_size);

    constexpr std::size_t pq_secret = crypto::kem_secret_size(crypto::kem_id::mlkem768);
    crypto::secure_bytes k_pq(pq_secret);
    std::size_t len = 0;
    const bool decapsulated =
        kem_.decapsulate(server_reply.first(mlkem768x25519_pq_ciphertext), k_pq.span(), len)
        && len == pq_secret;
    kem_.reset();
    if (!decapsulated) return code::kex_failure;

    crypto::secure_bytes k_cl(crypto::kex_secret_size(crypto::kex_id::curve25519));
    if (!kex_.agree(server_reply.subspan(mlkem768x25519_pq_ciphertext), k_cl.span(), len)
        || len != k_cl.size()) {
        return code::weak_shared_secret;
    }
    return combine_hybrid_secret(k_pq.span(), k_cl.span());
}

// RFC 10042 section 2.4: K = HASH(K_PQ || K_CL), with K_CL the 32-byte X25519
// output taken as is rather than as a canonical mpint.
YANTERM_SSH_INLINE std::error_code key_exchange::combine_hybrid_secret(
    std::span<const std::byte> k_pq, std::span<const std::byte> k_cl) {
    crypto::secure_bytes joined(k_pq.size() + k_cl.size());
    const std::span<std::byte> buf = joined.span();
    std::copy(k_pq.begin(), k_pq.end(), buf.begin());
    std::copy(k_cl.begin(), k_cl.end(), buf.subspan(k_pq.size()).begin());
    crypto::secure_bytes k(crypto::hash_output_size(n_.exchange_hash));
    if (!p_.hash(n_.exchange_hash, joined.span(), k.span())) return code::hash_failure;
    secret_.assign(k.span());
    return {};
}

YANTERM_SSH_INLINE void key_exchange::write_shared_secret(wire::writer& out) const {
    if (is_hybrid()) {
        out.write_string(secret_.span());
    } else {
        out.write_mpint(secret_.span());
    }
}

YANTERM_SSH_INLINE std::size_t key_exchange::shared_secret_encoded_size() const noexcept {
    return is_hybrid() ? wire::encoded_string_size(secret_.size())
                       : wire::encoded_mpint_size(secret_.span());
}

YANTERM_SSH_INLINE void key_exchange::store_shared_secret(std::span<const std::byte> raw) {
    std::size_t begin = 0;
    while (begin < raw.size() && raw[begin] == std::byte{0}) ++begin;
    secret_.assign(raw.subspan(begin));
}

YANTERM_SSH_INLINE std::error_code key_exchange::agree_with_peer(std::span<const std::byte> peer) {
    crypto::secure_bytes raw(crypto::kex_secret_size(n_.kex));
    std::size_t len = 0;
    if (!kex_.agree(peer, raw.span(), len)) {
        if (n_.kex == crypto::kex_id::curve25519
            && peer.size() == crypto::kex_public_size(n_.kex)) {
            return code::weak_shared_secret;
        }
        return code::invalid_kex_reply;
    }
    store_shared_secret(raw.span().first(len));
    return {};
}

YANTERM_SSH_INLINE std::error_code key_exchange::compute_hash(const exchange_context& ctx,
                                                              std::span<const std::byte> ks,
                                                              std::span<const std::byte> client_pub,
                                                              std::span<const std::byte> server_pub) {
    std::size_t hashed_bytes = wire::encoded_string_size(ctx.v_c.size())
                             + wire::encoded_string_size(ctx.v_s.size())
                             + wire::encoded_string_size(ctx.i_c.size())
                             + wire::encoded_string_size(ctx.i_s.size())
                             + wire::encoded_string_size(ks.size());
    if (kex::detail::uses_ecdh_messages(n_.kex)) {
        hashed_bytes += wire::encoded_string_size(client_pub.size());
        hashed_bytes += wire::encoded_string_size(server_pub.size());
    } else {
        hashed_bytes += wire::encoded_mpint_size(client_pub);
        hashed_bytes += wire::encoded_mpint_size(server_pub);
    }
    hashed_bytes += shared_secret_encoded_size();

    struct wiping_writer {
        wire::writer w;
        ~wiping_writer() {
            auto held = w.take();
            crypto::secure_zero(std::span<std::byte>{held});
        }
    } enc;
    enc.w.reserve(hashed_bytes);
    enc.w.write_string(ctx.v_c);
    enc.w.write_string(ctx.v_s);
    enc.w.write_string(ctx.i_c);
    enc.w.write_string(ctx.i_s);
    enc.w.write_string(ks);
    if (kex::detail::uses_ecdh_messages(n_.kex)) {
        enc.w.write_string(client_pub);
        enc.w.write_string(server_pub);
    } else {
        enc.w.write_mpint(client_pub);
        enc.w.write_mpint(server_pub);
    }
    // Binding J: K enters H in the same encoding the key derivation uses.
    write_shared_secret(enc.w);
    assert(enc.w.size() <= hashed_bytes);

    hash_.assign(crypto::hash_output_size(n_.exchange_hash), std::byte{0});
    const bool hashed = p_.hash(n_.exchange_hash, enc.w.data(), hash_);
    if (!hashed) return code::hash_failure;
    return {};
}

}  // namespace yanterm::ssh::core::detail
