#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/auth/types.hpp>
#include <yanterm-ssh/channels/types.hpp>
#include <yanterm-ssh/core/handler.hpp>
#include <yanterm-ssh/core/types.hpp>
#include <yanterm-ssh/wire/message_ids.hpp>
#include <yanterm-ssh/crypto/provider.hpp>
#include <yanterm-ssh/crypto/secure_buffer.hpp>
#include <yanterm-ssh/keys/fingerprint.hpp>
#include <yanterm-ssh/keys/public_key.hpp>

#include <corral/Task.h>

#include <cstddef>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <vector>

namespace yanterm::ssh {

using disconnect_reason = wire::disconnect_reason;
using auth_result = auth::auth_result;
using auth_verdict = auth::auth_verdict;
using verdict_kind = auth::verdict_kind;
using kbdint_prompt = auth::kbdint_prompt;
using channel_id = channels::channel_id;
using channel_open_reason = channels::channel_open_reason;
using channel_type = channels::channel_type;
using pty_spec = channels::pty_spec;
using x11_req_spec = channels::x11_req_spec;
using window_size = channels::window_size;
using exit_signal = channels::exit_signal;

struct disconnect_info {
    disconnect_reason reason{};
    std::string description;
    std::string language;
};

class host_key_view {
public:
    host_key_view(keys::public_key key, crypto::provider provider)
        : key_{std::move(key)}, provider_{provider} {}

    [[nodiscard]] const keys::public_key& key() const noexcept { return key_; }
    [[nodiscard]] std::string fingerprint() const {
        return keys::fingerprint_sha256(provider_, key_);
    }

private:
    keys::public_key key_;
    crypto::provider provider_{};
};

class session;
struct session_impl;  // completed in session.hpp as the session pimpl

class auth_request {
public:
    [[nodiscard]] std::string_view user() const noexcept { return user_; }
    [[nodiscard]] std::string_view service() const noexcept { return service_; }
    [[nodiscard]] std::string_view method() const noexcept { return method_; }
    [[nodiscard]] bool has_signature() const noexcept { return has_signature_; }
    [[nodiscard]] std::string_view algorithm() const noexcept { return algorithm_; }
    [[nodiscard]] std::span<const std::byte> public_blob() const noexcept {
        return public_blob_;
    }
    [[nodiscard]] std::string_view password() const noexcept { return password_.view(); }

    corral::Task<std::tuple<std::error_code, std::vector<crypto::secure_string>>> challenge(
        std::string_view name, std::string_view instruction, std::span<const kbdint_prompt> prompts);
    corral::Task<std::tuple<std::error_code, crypto::secure_string>> challenge(
        std::string_view prompt, bool echo = true, std::string_view name = {},
        std::string_view instruction = {});

private:
    friend class session;
    friend class server_session;
    friend struct session_impl;

    session_impl* impl_ = nullptr;
    core::auth_ticket ticket_{};
    std::string user_;
    std::string service_;
    std::string method_;
    bool has_signature_ = false;
    std::string algorithm_;
    std::vector<std::byte> public_blob_;
    crypto::secure_string password_;
};

}  // namespace yanterm::ssh
