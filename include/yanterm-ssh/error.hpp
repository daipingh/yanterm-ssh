#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <string>
#include <system_error>
#include <type_traits>

namespace yanterm::ssh {

enum class errc : int {
    malformed_input = 1,
    protocol_violation,
    security_violation,
    negotiation_failed,
    unsupported_algorithm,
    crypto_backend_failure,
    transport_failed,
    invalid_state,
    too_many_channels,
    session_closed,
    peer_disconnected,
    host_key_rejected,
    request_denied,
    passphrase_required,
    incorrect_passphrase,
    unsupported_key_format,
    insecure_permissions,
};

[[nodiscard]] const std::error_category& condition_category() noexcept;
[[nodiscard]] const std::error_category& error_category() noexcept;
[[nodiscard]] std::error_condition make_error_condition(errc e) noexcept;

namespace detail {

class ssh_condition_category final : public std::error_category {
public:
    [[nodiscard]] const char* name() const noexcept override { return "yanterm-ssh.errc"; }

    [[nodiscard]] std::string message(int value) const override;
    [[nodiscard]] bool equivalent(const std::error_code& code, int cond) const noexcept override;
};

}  // namespace detail

inline const std::error_category& condition_category() noexcept {
    static const detail::ssh_condition_category instance;
    return instance;
}

inline std::error_condition make_error_condition(errc e) noexcept {
    return {static_cast<int>(e), condition_category()};
}

inline std::string detail::ssh_condition_category::message(int value) const {
    switch (static_cast<errc>(value)) {
    case errc::malformed_input:        return "malformed input";
    case errc::protocol_violation:     return "protocol violation";
    case errc::security_violation:     return "security violation";
    case errc::negotiation_failed:     return "negotiation failed";
    case errc::unsupported_algorithm:  return "unsupported algorithm";
    case errc::crypto_backend_failure: return "crypto backend failure";
    case errc::transport_failed:       return "transport failed";
    case errc::invalid_state:          return "invalid state";
    case errc::too_many_channels:      return "too many channels";
    case errc::session_closed:         return "session closed";
    case errc::peer_disconnected:      return "peer disconnected";
    case errc::host_key_rejected:      return "host key rejected";
    case errc::request_denied:         return "request denied";
    case errc::passphrase_required:    return "passphrase required";
    case errc::incorrect_passphrase:   return "incorrect passphrase";
    case errc::unsupported_key_format: return "unsupported key format";
    case errc::insecure_permissions:   return "insecure permissions";
    }
    return "unknown yanterm-ssh error condition";
}

inline bool detail::ssh_condition_category::equivalent(const std::error_code& code,
                                                       int cond) const noexcept {
    const auto mapped = code.default_error_condition();
    if (cond == static_cast<int>(errc::transport_failed)) {
        return static_cast<bool>(code) && mapped.category() != condition_category();
    }
    return mapped == make_error_condition(static_cast<errc>(cond));
}

}  // namespace yanterm::ssh

template <>
struct std::is_error_condition_enum<yanterm::ssh::errc> : std::true_type {};
