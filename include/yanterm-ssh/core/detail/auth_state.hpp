#pragma once

#include <yanterm-ssh/auth/types.hpp>
#include <yanterm-ssh/crypto/secure_buffer.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace yanterm::ssh::core::detail {

enum class auth_phase : std::uint8_t {
    idle, wait_service_accept, ready, wait_userauth_reply, wait_app, wait_info_response, authenticated
};

struct auth_state {
    auth_phase phase = auth_phase::idle;
    bool publickey_query = false;
    bool pk_has_signature = false;
    bool have_app_failure = false;
    bool auth_ticket_open = false;
    bool kbdint_ticket_open = false;
    std::uint64_t auth_seq = 0;
    std::uint64_t kbdint_seq = 0;
    std::uint32_t expected_info_count = 0;
    std::string user, service, method, methods, last_failure_methods;
    std::string banner, banner_language;
    crypto::secure_string password;
    std::string pk_alg;
    std::vector<std::byte> pk_blob, pk_signature;
    std::string kbdint_language, kbdint_submethods_raw;
    std::vector<std::string> kbdint_submethods;
    std::vector<auth::kbdint_prompt> info_prompts;
    auth::auth_result result{};

    [[nodiscard]] bool waiting_verdict() const noexcept { return phase == auth_phase::wait_app; }
    [[nodiscard]] bool authenticated() const noexcept { return phase == auth_phase::authenticated; }
    void clear_pk_fields() noexcept;
    void wipe_secrets() noexcept;
};

inline void auth_state::clear_pk_fields() noexcept {
    pk_has_signature = false;
    pk_alg.clear();
    pk_blob.clear();
    pk_signature.clear();
}

inline void auth_state::wipe_secrets() noexcept {
    password.wipe();
}

}  // namespace yanterm::ssh::core::detail
