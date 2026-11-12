#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/error.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <vector>

namespace yanterm::ssh::agent {

// Library bounds, not RFC 9987 constants. A larger identities count or
// message is rejected before the decoder allocates.
inline constexpr std::uint32_t default_max_message_length = 262144;
inline constexpr std::uint32_t max_identities_count = 1024;

// Wire values from RFC 9987. The length prefix is not part of this byte.
enum class msg : std::uint8_t {
    failure = 5,
    success = 6,
    request_identities = 11,
    identities_answer = 12,
    sign_request = 13,
    sign_response = 14,
    add_identity = 17,
    remove_identity = 18,
    remove_all_identities = 19,
    add_smartcard_key = 20,
    remove_smartcard_key = 21,
    lock = 22,
    unlock = 23,
    add_id_constrained = 25,
    add_smartcard_key_constrained = 26,
    extension = 27,
    extension_failure = 28,
    extension_response = 29,
};

namespace sign_flags {
inline constexpr std::uint32_t rsa_sha2_256 = 2;
inline constexpr std::uint32_t rsa_sha2_512 = 4;
}  // namespace sign_flags

inline constexpr std::string_view session_bind_extension = "session-bind@openssh.com";
inline constexpr std::string_view query_extension = "query";

// RFC 9987 §8.2. These are constraint identifiers, not message numbers.
namespace constrain {
inline constexpr std::uint8_t lifetime = 1;
inline constexpr std::uint8_t confirm = 2;
inline constexpr std::uint8_t extension = 255;
}  // namespace constrain

// Extension details are not self-delimiting. A decoded extension is the last
// constraint, and `details` is every byte after its name.
struct constraint_extension {
    std::string name;
    std::vector<std::byte> details;
};

struct key_constraints {
    std::optional<std::uint32_t> lifetime_seconds;
    bool confirm = false;
    std::vector<constraint_extension> extensions;
};

[[nodiscard]] inline bool constraints_empty(const key_constraints& c) noexcept {
    return !c.lifetime_seconds.has_value() && !c.confirm && c.extensions.empty();
}

// Complete SSH_AGENT_FAILURE or SSH_AGENT_EXTENSION_FAILURE. The numeric
// values are the wire message numbers. Neither value means the peer lacks
// an extension; FAILURE is not a synonym of EXTENSION_FAILURE.
enum class refusal : std::uint8_t {
    failure = 5,
    extension_failure = 28,
};

struct identity_view {
    std::span<const std::byte> key_blob;
    std::string_view comment;
};

struct identity {
    std::vector<std::byte> key_blob;
    std::string comment;
};

struct identity_list {
    std::error_code ec;
    std::vector<identity> identities;
};

struct extension_reply {
    std::error_code ec;
    std::vector<std::byte> payload;
};

struct extension_list {
    std::error_code ec;
    std::vector<std::string> names;
};

[[nodiscard]] const std::error_category& error_category() noexcept;
[[nodiscard]] std::error_code make_error_code(refusal r) noexcept;

namespace detail {

class agent_error_category final : public std::error_category {
public:
    [[nodiscard]] const char* name() const noexcept override { return "yanterm-ssh.agent"; }
    [[nodiscard]] std::string message(int value) const override;
    [[nodiscard]] std::error_condition default_error_condition(int value) const noexcept override;
};

}  // namespace detail

inline const std::error_category& error_category() noexcept {
    static const detail::agent_error_category instance;
    return instance;
}

inline std::error_code make_error_code(refusal r) noexcept {
    return {static_cast<int>(static_cast<std::uint8_t>(r)), error_category()};
}

inline std::string detail::agent_error_category::message(int value) const {
    switch (static_cast<refusal>(static_cast<std::uint8_t>(value))) {
    case refusal::failure:            return "agent failure";
    case refusal::extension_failure:  return "agent extension failure";
    }
    return "unknown agent response";
}

inline std::error_condition detail::agent_error_category::default_error_condition(
    int value) const noexcept {
    switch (static_cast<refusal>(static_cast<std::uint8_t>(value))) {
    case refusal::failure:
    case refusal::extension_failure:
        return make_error_condition(errc::request_denied);
    }
    return {value, *this};
}

}  // namespace yanterm::ssh::agent

template <>
struct std::is_error_code_enum<yanterm::ssh::agent::refusal> : std::true_type {};
