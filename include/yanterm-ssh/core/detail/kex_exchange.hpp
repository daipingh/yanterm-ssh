#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/kex/algorithms.hpp>
#include <yanterm-ssh/core/detail/host_key.hpp>
#include <yanterm-ssh/core/types.hpp>
#include <yanterm-ssh/wire/types.hpp>
#include <yanterm-ssh/crypto/algorithms.hpp>
#include <yanterm-ssh/crypto/provider.hpp>
#include <yanterm-ssh/crypto/secure_buffer.hpp>

#include <cstddef>
#include <span>
#include <string_view>
#include <system_error>
#include <vector>

namespace yanterm::ssh::core::detail {

// Inputs to the exchange hash that are fixed before the method-specific
// exchange begins.
struct exchange_context {
    std::string_view v_c;            // client identification, no CR LF
    std::string_view v_s;            // server identification, no CR LF
    std::span<const std::byte> i_c;  // the client's KEXINIT payload
    std::span<const std::byte> i_s;  // the server's KEXINIT payload
};

class key_exchange {
public:
    key_exchange(crypto::provider p, const ::yanterm::ssh::kex::negotiated& n,
                 ::yanterm::ssh::core::role r)
        : p_{p}, n_{n}, r_{r}, host_sig_id_{n.host_key} {}

    ~key_exchange();

    key_exchange(const key_exchange&) = delete;
    key_exchange& operator=(const key_exchange&) = delete;
    key_exchange(key_exchange&&) noexcept = default;
    key_exchange& operator=(key_exchange&&) noexcept = default;

    // Overwrites K and drops the ephemeral agreement. Safe to call more than
    // once. Hash H is left in place until destruction.
    void consume_shared_secret() noexcept;

    // Client: produces SSH_MSG_KEX_ECDH_INIT or SSH_MSG_KEXDH_INIT.
    std::error_code start(wire::writer& out);

    // Client: consumes the server's reply, verifies the host key signature, and
    // fills `hash` with H and `host_key` with the parsed K_S.
    std::error_code accept_reply(const exchange_context& ctx,
                                 std::span<const std::byte> reply_payload,
                                 host_key_view& host_key,
                                 std::span<const std::byte>& hash);

    // Server: consumes the client's init and emits the reply, signing H.
    std::error_code accept_init(const exchange_context& ctx,
                                std::span<const std::byte> init_payload,
                                std::span<const std::byte> host_key_blob,
                                crypto::signing_key& signer,
                                wire::writer& out,
                                std::span<const std::byte>& hash);

    // The shared secret K. Its SSH encoding, used for both H and the key
    // derivation, comes from write_shared_secret.
    [[nodiscard]] std::span<const std::byte> shared_secret() const noexcept {
        return secret_.span();
    }

    // Appends K as an mpint, or as a string for mlkem768x25519-sha256
    // (RFC 10042 section 2.5).
    void write_shared_secret(wire::writer& out) const;
    [[nodiscard]] std::size_t shared_secret_encoded_size() const noexcept;

    [[nodiscard]] crypto::sig_id host_sig_id() const noexcept { return host_sig_id_; }

private:
    [[nodiscard]] bool is_hybrid() const noexcept {
        return n_.kex == crypto::kex_id::mlkem768x25519;
    }
    [[nodiscard]] std::size_t peer_public_size() const noexcept;

    std::error_code start_hybrid();
    std::error_code accept_hybrid_init();
    std::error_code agree_hybrid_reply(std::span<const std::byte> server_reply);
    std::error_code combine_hybrid_secret(std::span<const std::byte> k_pq,
                                          std::span<const std::byte> k_cl);

    void store_shared_secret(std::span<const std::byte> raw);

    std::error_code agree_with_peer(std::span<const std::byte> peer);

    std::error_code compute_hash(const exchange_context& ctx, std::span<const std::byte> ks,
                                 std::span<const std::byte> client_pub,
                                 std::span<const std::byte> server_pub);

    crypto::provider p_;
    ::yanterm::ssh::kex::negotiated n_;
    ::yanterm::ssh::core::role r_;
    crypto::kex_agreement kex_;
    crypto::kem_keypair kem_;
    std::vector<std::byte> local_public_;
    std::vector<std::byte> peer_public_;
    crypto::secure_bytes secret_;
    std::vector<std::byte> hash_;
    crypto::sig_id host_sig_id_{};
    bool started_ = false;
};

}  // namespace yanterm::ssh::core::detail

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/core/detail/impl/kex_exchange.ipp>
#endif
