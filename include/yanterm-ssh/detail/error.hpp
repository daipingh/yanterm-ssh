#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/error.hpp>

#include <string>
#include <system_error>
#include <type_traits>

namespace yanterm::ssh {
namespace detail {

enum class code : int {
    truncated_input = 1,
    invalid_format,
    string_too_long,
    invalid_mpint,
    invalid_name_list,
    version_line_too_long,
    unsupported_protocol_version,
    missing_version_banner,
    packet_too_large,
    invalid_packet_length,
    invalid_padding,
    invalid_kex_reply,
    invalid_host_key,

    unexpected_message,
    channel_window_exceeded,
    unsupported_service,

    mac_mismatch,
    decrypt_failure,
    signature_verification_failed,
    host_key_changed,
    strict_kex_violation,
    weak_shared_secret,

    no_common_kex_algorithm,
    no_common_host_key_algorithm,
    no_common_cipher,
    no_common_mac,
    no_common_compression,

    unsupported_algorithm,
    empty_algorithm_list,

    crypto_backend_failure,
    random_failure,
    hash_failure,
    cipher_failure,
    aead_failure,
    mac_failure,
    kex_failure,
    sign_failure,
    keygen_failure,

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

class ssh_error_category final : public std::error_category {
public:
    [[nodiscard]] const char* name() const noexcept override { return "yanterm-ssh"; }

    [[nodiscard]] std::string message(int value) const override {
        switch (static_cast<code>(value)) {
        case code::truncated_input:               return "input ended in the middle of a field";
        case code::invalid_format:                return "malformed encoding";
        case code::string_too_long:               return "string length exceeds the configured limit";
        case code::invalid_mpint:                 return "mpint is negative or not canonically encoded";
        case code::invalid_name_list:             return "name-list contains an empty or non-US-ASCII name";
        case code::version_line_too_long:         return "identification line exceeds 255 bytes";
        case code::unsupported_protocol_version:  return "peer does not speak SSH 2.0";
        case code::missing_version_banner:        return "peer sent no SSH identification string";
        case code::packet_too_large:              return "binary packet exceeds the maximum accepted size";
        case code::invalid_packet_length:         return "binary packet length is not a valid multiple";
        case code::invalid_padding:               return "binary packet padding length is out of range";
        case code::mac_mismatch:                  return "message authentication code mismatch";
        case code::decrypt_failure:               return "packet decryption or AEAD authentication failed";
        case code::no_common_kex_algorithm:       return "no common key exchange algorithm";
        case code::no_common_host_key_algorithm:  return "no common host key algorithm";
        case code::no_common_cipher:              return "no common encryption algorithm";
        case code::no_common_mac:                 return "no common message authentication algorithm";
        case code::no_common_compression:         return "no common compression algorithm";
        case code::invalid_host_key:              return "host key blob is malformed";
        case code::signature_verification_failed: return "host key signature verification failed";
        case code::host_key_rejected:             return "host key was rejected by the application";
        case code::host_key_changed:              return "peer presented a different host key during rekey";
        case code::invalid_kex_reply:             return "key exchange reply is malformed";
        case code::weak_shared_secret:            return "key agreement produced an all-zero shared secret";
        case code::strict_kex_violation:          return "peer violated strict key exchange rules";
        case code::unexpected_message:            return "message is not allowed in the current state";
        case code::peer_disconnected:             return "peer sent SSH_MSG_DISCONNECT";
        case code::invalid_state:                 return "operation is not valid in the current state";
        case code::unsupported_algorithm:         return "crypto provider does not support this algorithm";
        case code::unsupported_key_format:        return "key format is not supported";
        case code::passphrase_required:           return "private key is encrypted and no passphrase was given";
        case code::incorrect_passphrase:          return "private key passphrase is incorrect";
        case code::insecure_permissions:          return "private key file permissions are too open";
        case code::unsupported_service:           return "service name is not ssh-userauth";
        case code::channel_window_exceeded:       return "channel window exceeded";
        case code::too_many_channels:             return "too many simultaneous channels";
        case code::session_closed:                return "session is closed";
        case code::empty_algorithm_list:          return "algorithm list is empty after filtering";
        case code::request_denied:                return "peer denied the request";
        case code::crypto_backend_failure:        return "crypto backend reported an internal failure";
        case code::random_failure:                return "random number generation failed";
        case code::hash_failure:                  return "hash primitive failed";
        case code::cipher_failure:                return "cipher primitive failed";
        case code::aead_failure:                  return "AEAD primitive failed";
        case code::mac_failure:                   return "MAC computation failed";
        case code::kex_failure:                   return "key exchange primitive failed";
        case code::sign_failure:                  return "signing primitive failed";
        case code::keygen_failure:                return "key generation failed";
        }
        return "unknown yanterm-ssh error";
    }

    [[nodiscard]] std::error_condition default_error_condition(int ev) const noexcept override {
        switch (static_cast<code>(ev)) {
        case code::truncated_input:
        case code::invalid_format:
        case code::string_too_long:
        case code::invalid_mpint:
        case code::invalid_name_list:
        case code::version_line_too_long:
        case code::unsupported_protocol_version:
        case code::missing_version_banner:
        case code::packet_too_large:
        case code::invalid_packet_length:
        case code::invalid_padding:
        case code::invalid_kex_reply:
        case code::invalid_host_key:
            return make_error_condition(errc::malformed_input);
        case code::unexpected_message:
        case code::channel_window_exceeded:
        case code::unsupported_service:
            return make_error_condition(errc::protocol_violation);
        case code::mac_mismatch:
        case code::decrypt_failure:
        case code::signature_verification_failed:
        case code::host_key_changed:
        case code::strict_kex_violation:
        case code::weak_shared_secret:
            return make_error_condition(errc::security_violation);
        case code::no_common_kex_algorithm:
        case code::no_common_host_key_algorithm:
        case code::no_common_cipher:
        case code::no_common_mac:
        case code::no_common_compression:
            return make_error_condition(errc::negotiation_failed);
        case code::unsupported_algorithm:
        case code::empty_algorithm_list:
            return make_error_condition(errc::unsupported_algorithm);
        case code::crypto_backend_failure:
        case code::random_failure:
        case code::hash_failure:
        case code::cipher_failure:
        case code::aead_failure:
        case code::mac_failure:
        case code::kex_failure:
        case code::sign_failure:
        case code::keygen_failure:
            return make_error_condition(errc::crypto_backend_failure);
        case code::invalid_state:
            return make_error_condition(errc::invalid_state);
        case code::too_many_channels:
            return make_error_condition(errc::too_many_channels);
        case code::session_closed:
            return make_error_condition(errc::session_closed);
        case code::peer_disconnected:
            return make_error_condition(errc::peer_disconnected);
        case code::host_key_rejected:
            return make_error_condition(errc::host_key_rejected);
        case code::request_denied:
            return make_error_condition(errc::request_denied);
        case code::passphrase_required:
            return make_error_condition(errc::passphrase_required);
        case code::incorrect_passphrase:
            return make_error_condition(errc::incorrect_passphrase);
        case code::unsupported_key_format:
            return make_error_condition(errc::unsupported_key_format);
        case code::insecure_permissions:
            return make_error_condition(errc::insecure_permissions);
        }
        return std::error_condition(ev, *this);
    }
};

inline std::error_code make_error_code(code e) noexcept {
    return {static_cast<int>(e), ::yanterm::ssh::error_category()};
}

}  // namespace detail

inline const std::error_category& error_category() noexcept {
    static const detail::ssh_error_category instance;
    return instance;
}

using detail::code;
using detail::make_error_code;

}  // namespace yanterm::ssh

template <>
struct std::is_error_code_enum<yanterm::ssh::detail::code> : std::true_type {};
