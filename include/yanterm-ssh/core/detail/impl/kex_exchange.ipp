#pragma once

#include <yanterm-ssh/core/detail/kex_exchange.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/core/detail/impl/kex_exchange.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/wire/detail/messages.hpp>
#include <yanterm-ssh/kex/detail/tables.hpp>
#include <yanterm-ssh/detail/error.hpp>

#include <yanterm-ssh/crypto/secure_buffer.hpp>

#include <array>
#include <cassert>

namespace yanterm::ssh::core::detail {

YANTERM_SSH_INLINE key_exchange::~key_exchange() { consume_shared_secret(); }

YANTERM_SSH_INLINE void key_exchange::consume_shared_secret() noexcept {
    secret_.wipe();
    kex_.reset();
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

    kex_ = p_.new_kex(kex_backend_id(n_.kex, r_));
    if (!kex_) return code::kex_failure;

    local_public_.assign(crypto::kex_public_size(n_.kex), std::byte{0});
    std::size_t len = 0;
    if (!kex_.public_value(local_public_, len) || len != local_public_.size()) {
        return code::kex_failure;
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
        if (msg.server_public.size() != crypto::kex_public_size(n_.kex)) {
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

    if (auto ec = agree_with_peer(server_public)) return ec;

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
        if (msg.client_public.size() != crypto::kex_public_size(n_.kex)) {
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

    kex_ = p_.new_kex(kex_backend_id(n_.kex, r_));
    if (!kex_) return code::kex_failure;

    local_public_.assign(crypto::kex_public_size(n_.kex), std::byte{0});
    std::size_t len = 0;
    if (!kex_.public_value(local_public_, len) || len != local_public_.size()) {
        return code::kex_failure;
    }

    if (auto ec = agree_with_peer(peer_public_)) return ec;

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
    hashed_bytes += wire::encoded_mpint_size(secret_.span());

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
    // Binding J: K enters H as a canonical SSH mpint.
    enc.w.write_mpint(secret_.span());
    assert(enc.w.size() <= hashed_bytes);

    hash_.assign(crypto::hash_output_size(n_.exchange_hash), std::byte{0});
    const bool hashed = p_.hash(n_.exchange_hash, enc.w.data(), hash_);
    if (!hashed) return code::hash_failure;
    return {};
}

}  // namespace yanterm::ssh::core::detail
