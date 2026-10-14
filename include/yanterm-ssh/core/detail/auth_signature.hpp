#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/crypto/provider.hpp>
#include <yanterm-ssh/wire/types.hpp>

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace yanterm::ssh::core::detail {

[[nodiscard]] inline std::string_view pick_userauth_sig_alg(
    std::string_view blob_alg, std::string_view server_sig_algs, bool allow_ssh_rsa) noexcept {
    if (blob_alg == "ssh-rsa") {
        wire::name_list algs{server_sig_algs};
        if (algs.contains("rsa-sha2-256")) return "rsa-sha2-256";
        if (algs.contains("rsa-sha2-512")) return "rsa-sha2-512";
        if (server_sig_algs.empty()) return "rsa-sha2-256";
        if (allow_ssh_rsa && algs.contains("ssh-rsa")) return "ssh-rsa";
        return {};
    }
    return blob_alg;
}

void write_publickey_signed_data(
    wire::writer& w,
    std::span<const std::byte> session_id,
    std::string_view user,
    std::string_view service,
    std::string_view alg,
    std::span<const std::byte> blob);

std::error_code sign_userauth_publickey(crypto::provider p, std::span<const std::byte> session_id,
                                        std::string_view user, std::span<const std::byte> public_blob,
                                        const crypto::private_key_material& priv,
                                        std::string_view server_sig_algs, bool allow_ssh_rsa,
                                        crypto::sig_id sm2_encoding,
                                        std::string& alg_out, std::vector<std::byte>& sig_out);

std::error_code verify_userauth_publickey(crypto::provider p, std::span<const std::byte> session_id,
                                          std::string_view user, std::string_view service,
                                          std::string_view alg, std::span<const std::byte> blob,
                                          std::span<const std::byte> signature);

}  // namespace yanterm::ssh::core::detail

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/core/detail/impl/auth_signature.ipp>
#endif
