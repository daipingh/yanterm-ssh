#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/agent/types.hpp>
#include <yanterm-ssh/wire/types.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace yanterm::ssh::agent {

// `length` is the big-endian uint32 that follows the SSH agent framing
// rule: it counts the type byte and payload, and not itself. A header
// that is not exactly four bytes yields 0, which fails message_length_ok.
[[nodiscard]] std::uint32_t decode_frame_header(std::span<const std::byte> header) noexcept;
void encode_frame_header(wire::writer& w, std::uint32_t length);

[[nodiscard]] inline bool message_length_ok(std::uint32_t length,
                                            std::uint32_t max_message_length) noexcept {
    return length >= 1 && length <= max_message_length;
}

[[nodiscard]] msg message_type(std::span<const std::byte> payload) noexcept;

void encode_failure(wire::writer& w);
[[nodiscard]] bool decode_failure(std::span<const std::byte> payload) noexcept;
void encode_success(wire::writer& w);
[[nodiscard]] bool decode_success(std::span<const std::byte> payload) noexcept;

void encode_request_identities(wire::writer& w);
[[nodiscard]] bool decode_request_identities(std::span<const std::byte> payload) noexcept;

void encode_identities_answer(wire::writer& w, std::span<const identity_view> identities);
// Views borrow `payload`. `out` is cleared on failure.
[[nodiscard]] bool decode_identities_answer(std::span<const std::byte> payload,
                                            std::vector<identity_view>& out);

void encode_sign_request(wire::writer& w, std::span<const std::byte> key_blob,
                         std::span<const std::byte> data, std::uint32_t flags);
[[nodiscard]] bool decode_sign_request(std::span<const std::byte> payload,
                                       std::span<const std::byte>& key_blob,
                                       std::span<const std::byte>& data,
                                       std::uint32_t& flags) noexcept;

// `signature` is the SSH signature blob carried by SSH_AGENT_SIGN_RESPONSE,
// not the agent frame around it.
void encode_sign_response(wire::writer& w, std::span<const std::byte> signature);
[[nodiscard]] bool decode_sign_response(std::span<const std::byte> payload,
                                        std::span<const std::byte>& signature) noexcept;

// `data` is the extension-specific remainder after the name string.
// It is not wrapped in another SSH string.
void encode_extension(wire::writer& w, std::string_view name, std::span<const std::byte> data);
[[nodiscard]] bool decode_extension(std::span<const std::byte> payload, std::string_view& name,
                                   std::span<const std::byte>& data) noexcept;

void encode_extension_failure(wire::writer& w);
[[nodiscard]] bool decode_extension_failure(std::span<const std::byte> payload) noexcept;

void encode_extension_response(wire::writer& w, std::string_view name,
                               std::span<const std::byte> data);
[[nodiscard]] bool decode_extension_response(std::span<const std::byte> payload,
                                             std::string_view& name,
                                             std::span<const std::byte>& data) noexcept;

// `names` is cleared on failure. More than max_identities_count names is rejected.
[[nodiscard]] bool decode_query_response(std::span<const std::byte> payload,
                                         std::vector<std::string>& names);

// `key` is the RFC 9987 key type string followed by the key data, with no
// extra length of its own. An empty `constraints` selects ADD_IDENTITY;
// otherwise ADD_ID_CONSTRAINED.
void encode_add_identity(wire::writer& w, std::span<const std::byte> key,
                         std::string_view comment, const key_constraints& constraints = {});
// `key` and `comment` borrow `payload`. Unknown key types and unknown
// constraint types fail. An extension constraint ends the message.
[[nodiscard]] bool decode_add_identity(std::span<const std::byte> payload,
                                       std::span<const std::byte>& key,
                                       std::string_view& comment,
                                       key_constraints& constraints);

void encode_remove_identity(wire::writer& w, std::span<const std::byte> key_blob);
[[nodiscard]] bool decode_remove_identity(std::span<const std::byte> payload,
                                          std::span<const std::byte>& key_blob) noexcept;

void encode_remove_all_identities(wire::writer& w);
[[nodiscard]] bool decode_remove_all_identities(std::span<const std::byte> payload) noexcept;

void encode_add_smartcard_key(wire::writer& w, std::string_view token_id,
                              std::string_view pin, const key_constraints& constraints = {});
[[nodiscard]] bool decode_add_smartcard_key(std::span<const std::byte> payload,
                                            std::string_view& token_id, std::string_view& pin,
                                            key_constraints& constraints);

void encode_remove_smartcard_key(wire::writer& w, std::string_view token_id,
                                 std::string_view pin);
[[nodiscard]] bool decode_remove_smartcard_key(std::span<const std::byte> payload,
                                               std::string_view& token_id,
                                               std::string_view& pin) noexcept;

void encode_lock(wire::writer& w, std::string_view passphrase);
[[nodiscard]] bool decode_lock(std::span<const std::byte> payload,
                               std::string_view& passphrase) noexcept;

void encode_unlock(wire::writer& w, std::string_view passphrase);
[[nodiscard]] bool decode_unlock(std::span<const std::byte> payload,
                                 std::string_view& passphrase) noexcept;

// OpenSSH PROTOCOL.agent session-bind. `signature` is the server's initial
// key-exchange signature over the session identifier. It does not sign this
// message, and `is_forwarding` is not covered by that signature.
void encode_session_bind(wire::writer& w, std::span<const std::byte> host_key,
                         std::span<const std::byte> session_id,
                         std::span<const std::byte> signature, bool is_forwarding);
[[nodiscard]] bool decode_session_bind(std::span<const std::byte> payload,
                                       std::span<const std::byte>& host_key,
                                       std::span<const std::byte>& session_id,
                                       std::span<const std::byte>& signature,
                                       bool& is_forwarding) noexcept;

}  // namespace yanterm::ssh::agent

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/agent/impl/packets.ipp>
#endif
