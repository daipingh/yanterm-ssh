#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/detail/error.hpp>
#include <yanterm-ssh/version.hpp>

#include <auv/error.hpp>

#include <cerrno>
#include <string>
#include <system_error>

using namespace yanterm::ssh;

TEST_CASE("errc converts to error_condition implicitly", "[error]") {
    std::error_condition cond = errc::negotiation_failed;
    REQUIRE(cond == errc::negotiation_failed);
    REQUIRE(cond.category() == condition_category());
}

TEST_CASE("foreign I/O failures compare equal to transport_failed", "[error]") {
    REQUIRE(std::error_code(EIO, std::system_category()) == errc::transport_failed);
    REQUIRE(auv::make_error_code(auv::errc::eof) == errc::transport_failed);
    REQUIRE(std::make_error_code(std::errc::connection_reset) == errc::transport_failed);
}

TEST_CASE("each detail::code maps to the specified errc", "[error]") {
    struct row {
        code fine;
        errc domain;
    };
    static constexpr row kMap[] = {
        {code::truncated_input, errc::malformed_input},
        {code::invalid_format, errc::malformed_input},
        {code::string_too_long, errc::malformed_input},
        {code::invalid_mpint, errc::malformed_input},
        {code::invalid_name_list, errc::malformed_input},
        {code::version_line_too_long, errc::malformed_input},
        {code::unsupported_protocol_version, errc::malformed_input},
        {code::missing_version_banner, errc::malformed_input},
        {code::packet_too_large, errc::malformed_input},
        {code::invalid_packet_length, errc::malformed_input},
        {code::invalid_padding, errc::malformed_input},
        {code::invalid_kex_reply, errc::malformed_input},
        {code::invalid_host_key, errc::malformed_input},

        {code::unexpected_message, errc::protocol_violation},
        {code::channel_window_exceeded, errc::protocol_violation},
        {code::unsupported_service, errc::protocol_violation},

        {code::mac_mismatch, errc::security_violation},
        {code::decrypt_failure, errc::security_violation},
        {code::signature_verification_failed, errc::security_violation},
        {code::host_key_changed, errc::security_violation},
        {code::strict_kex_violation, errc::security_violation},
        {code::weak_shared_secret, errc::security_violation},

        {code::no_common_kex_algorithm, errc::negotiation_failed},
        {code::no_common_host_key_algorithm, errc::negotiation_failed},
        {code::no_common_cipher, errc::negotiation_failed},
        {code::no_common_mac, errc::negotiation_failed},
        {code::no_common_compression, errc::negotiation_failed},

        {code::unsupported_algorithm, errc::unsupported_algorithm},
        {code::empty_algorithm_list, errc::unsupported_algorithm},

        {code::crypto_backend_failure, errc::crypto_backend_failure},
        {code::random_failure, errc::crypto_backend_failure},
        {code::hash_failure, errc::crypto_backend_failure},
        {code::cipher_failure, errc::crypto_backend_failure},
        {code::aead_failure, errc::crypto_backend_failure},
        {code::mac_failure, errc::crypto_backend_failure},
        {code::kex_failure, errc::crypto_backend_failure},
        {code::sign_failure, errc::crypto_backend_failure},
        {code::keygen_failure, errc::crypto_backend_failure},

        {code::invalid_state, errc::invalid_state},
        {code::too_many_channels, errc::too_many_channels},
        {code::session_closed, errc::session_closed},
        {code::peer_disconnected, errc::peer_disconnected},
        {code::host_key_rejected, errc::host_key_rejected},
        {code::request_denied, errc::request_denied},
        {code::passphrase_required, errc::passphrase_required},
        {code::incorrect_passphrase, errc::incorrect_passphrase},
        {code::unsupported_key_format, errc::unsupported_key_format},
        {code::insecure_permissions, errc::insecure_permissions},
    };

    for (row r : kMap) {
        const std::error_code ec = r.fine;
        CAPTURE(ec.message());
        REQUIRE(ec == r.domain);
        REQUIRE_FALSE(ec == errc::transport_failed);
    }
}

TEST_CASE("version macros and string agree", "[version]") {
    const std::string expected = std::to_string(YANTERM_SSH_VERSION_MAJOR) + '.'
                               + std::to_string(YANTERM_SSH_VERSION_MINOR) + '.'
                               + std::to_string(YANTERM_SSH_VERSION_PATCH);
    REQUIRE(std::string(version_string()) == expected);
}
