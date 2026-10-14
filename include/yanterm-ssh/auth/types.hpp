#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yanterm::ssh::auth {

inline constexpr std::string_view service_userauth = "ssh-userauth";
inline constexpr std::string_view service_connection = "ssh-connection";
inline constexpr std::string_view method_none = "none";
inline constexpr std::string_view method_password = "password";
inline constexpr std::string_view method_publickey = "publickey";
inline constexpr std::string_view method_kbdint = "keyboard-interactive";

enum class method : std::uint8_t {
    none, password, publickey, keyboard_interactive, unknown
};

[[nodiscard]] inline method parse_method(std::string_view n) noexcept {
    if (n == method_none) return method::none;
    if (n == method_password) return method::password;
    if (n == method_publickey) return method::publickey;
    if (n == method_kbdint) return method::keyboard_interactive;
    return method::unknown;
}

[[nodiscard]] inline std::string_view method_name(method m) noexcept {
    switch (m) {
    case method::none: return method_none;
    case method::password: return method_password;
    case method::publickey: return method_publickey;
    case method::keyboard_interactive: return method_kbdint;
    case method::unknown: return {};
    }
    return {};
}

struct kbdint_prompt {
    std::string prompt;
    bool echo = true;
};

struct auth_result {
    bool success = false;
    bool partial_success = false;
    bool pk_ok = false;  // client query got USERAUTH_PK_OK; not a FAILURE
    std::string_view methods{};
};

struct auth_request_view {
    std::string_view user;
    std::string_view service;
    std::string_view method;
    bool has_signature = false;
    std::string_view algorithm;
    std::span<const std::byte> public_blob;
    std::string_view password;
    std::string_view submethods;
};

struct info_request_view {
    std::string_view name;
    std::string_view instruction;
    std::string_view language;
    std::span<const kbdint_prompt> prompts;
};

enum class verdict_kind : std::uint8_t { success, failure, info };

struct auth_verdict {
    verdict_kind kind = verdict_kind::failure;
    bool partial_success = false;
    std::string methods;
    std::string info_name;
    std::string info_instruction;
    std::string info_language;
    std::vector<kbdint_prompt> prompts;

    static auth_verdict success() {
        auth_verdict v;
        v.kind = verdict_kind::success;
        return v;
    }
    static auth_verdict failure(std::string_view methods, bool partial = false) {
        auth_verdict v;
        v.kind = verdict_kind::failure;
        v.partial_success = partial;
        v.methods.assign(methods.begin(), methods.end());
        return v;
    }
    static auth_verdict info(std::string_view name, std::string_view instruction,
                             std::span<const kbdint_prompt> prompts,
                             std::string_view language = {}) {
        auth_verdict v;
        v.kind = verdict_kind::info;
        v.info_name.assign(name.begin(), name.end());
        v.info_instruction.assign(instruction.begin(), instruction.end());
        v.info_language.assign(language.begin(), language.end());
        v.prompts.assign(prompts.begin(), prompts.end());
        return v;
    }
};

}  // namespace yanterm::ssh::auth
