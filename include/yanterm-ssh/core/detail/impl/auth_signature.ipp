#pragma once

#include <yanterm-ssh/core/detail/auth_signature.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/core/detail/impl/auth_signature.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/auth/types.hpp>
#include <yanterm-ssh/core/detail/host_key.hpp>
#include <yanterm-ssh/detail/error.hpp>
#include <yanterm-ssh/kex/detail/tables.hpp>
#include <yanterm-ssh/wire/message_ids.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace yanterm::ssh::core::detail {

YANTERM_SSH_INLINE void write_publickey_signed_data(
    wire::writer& w,
    std::span<const std::byte> session_id,
    std::string_view user,
    std::string_view service,
    std::string_view alg,
    std::span<const std::byte> blob) {
    w.write_string(session_id);
    w.write_byte(static_cast<std::uint8_t>(wire::msg::userauth_request));
    w.write_string(user);
    w.write_string(service);
    w.write_string(auth::method_publickey);
    w.write_bool(true);
    w.write_string(alg);
    w.write_string(blob);
}

YANTERM_SSH_INLINE std::error_code sign_userauth_publickey(
    crypto::provider p, std::span<const std::byte> session_id, std::string_view user,
    std::span<const std::byte> public_blob, const crypto::private_key_material& priv,
    std::string_view server_sig_algs, bool allow_ssh_rsa, crypto::sig_id sm2_encoding,
    std::string& alg_out, std::vector<std::byte>& sig_out) {
    host_key_view key;
    if (auto ec = parse_host_key(public_blob, key)) return ec;
    const auto alg = pick_userauth_sig_alg(key.algorithm_name, server_sig_algs, allow_ssh_rsa);
    if (alg.empty()) return code::unsupported_algorithm;
    const auto* entry = kex::detail::find_host_key(alg);
    if (entry == nullptr) return code::unsupported_algorithm;
    crypto::private_key_material signing = priv;
    signing.algorithm = entry->id;
    if (crypto::is_sm2_sig(entry->id)) {
        signing.algorithm = (sm2_encoding == crypto::sig_id::sm2_ecdsa)
                                ? crypto::sig_id::sm2_ecdsa
                                : crypto::sig_id::sm2_za;
    }
    wire::writer data_w;
    write_publickey_signed_data(data_w, session_id, user, auth::service_connection, alg,
                                public_blob);
    if (!p) return code::crypto_backend_failure;
    auto sk = p.new_signing_key(signing);
    if (!sk) return code::sign_failure;
    std::array<std::byte, crypto::max_signature_size> raw{};
    std::size_t len = 0;
    if (!sk.sign(data_w.data(), raw, len) || len == 0) {
        return code::sign_failure;
    }
    wire::writer sig_w;
    if (auto ec = encode_signature(alg, std::span{raw}.first(len), sig_w)) return ec;
    alg_out.assign(alg.begin(), alg.end());
    sig_out.assign(sig_w.data().begin(), sig_w.data().end());
    return {};
}

YANTERM_SSH_INLINE std::error_code verify_userauth_publickey(
    crypto::provider p, std::span<const std::byte> session_id, std::string_view user,
    std::string_view service, std::string_view alg, std::span<const std::byte> blob,
    std::span<const std::byte> signature) {
    host_key_view key;
    if (auto ec = parse_host_key(blob, key)) return ec;
    wire::writer data_w;
    write_publickey_signed_data(data_w, session_id, user, service, alg, blob);
    return verify_signature(p, key, alg, signature, data_w.data());
}

}  // namespace yanterm::ssh::core::detail
