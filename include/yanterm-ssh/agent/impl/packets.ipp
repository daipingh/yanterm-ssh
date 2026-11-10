#pragma once

#include <yanterm-ssh/agent/packets.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/agent/impl/packets.ipp is an implementation file, not a public header."
#endif

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace yanterm::ssh::agent {
namespace detail {

YANTERM_SSH_INLINE bool read_exact_type(wire::reader& r, msg expected) noexcept {
    std::uint8_t type = 0;
    return r.read_byte(type) && type == static_cast<std::uint8_t>(expected) && r.empty();
}

YANTERM_SSH_INLINE void write_type(wire::writer& w, msg type) {
    w.write_byte(static_cast<std::uint8_t>(type));
}

// Smallest identities entry: an empty key blob and an empty comment.
inline constexpr std::size_t min_identity_bytes = 8;

YANTERM_SSH_INLINE bool skip_strings(wire::reader& r, int count) noexcept {
    for (int i = 0; i < count; ++i) {
        std::span<const std::byte> ignored;
        if (!r.read_string(ignored)) return false;
    }
    return true;
}

// Fields that follow the key type string. -1 is a type whose comment cannot
// be located.
YANTERM_SSH_INLINE int key_value_strings(std::string_view type) noexcept {
    if (type == "ssh-dss") return 5;
    if (type == "ssh-ed25519" || type == "ssh-ed448") return 2;
    if (type == "ssh-rsa") return 6;
    if (type.size() >= 11 && type.substr(0, 11) == "ecdsa-sha2-") return 3;
    return -1;
}

YANTERM_SSH_INLINE void write_constraints(wire::writer& w, const key_constraints& constraints) {
    if (constraints.lifetime_seconds) {
        w.write_byte(constrain::lifetime);
        w.write_uint32(*constraints.lifetime_seconds);
    }
    if (constraints.confirm) w.write_byte(constrain::confirm);
    for (const auto& ext : constraints.extensions) {
        w.write_byte(constrain::extension);
        w.write_string(ext.name);
        w.write_bytes(ext.details);
    }
}

// An extension constraint consumes the rest of `r`.
YANTERM_SSH_INLINE bool read_constraints(wire::reader& r, key_constraints& out) {
    out = {};
    bool saw_lifetime = false;
    bool saw_confirm = false;
    while (!r.empty()) {
        std::uint8_t ctype = 0;
        if (!r.read_byte(ctype)) return false;
        if (ctype == constrain::lifetime) {
            if (saw_lifetime) return false;
            std::uint32_t seconds = 0;
            if (!r.read_uint32(seconds)) return false;
            out.lifetime_seconds = seconds;
            saw_lifetime = true;
        } else if (ctype == constrain::confirm) {
            if (saw_confirm) return false;
            out.confirm = true;
            saw_confirm = true;
        } else if (ctype == constrain::extension) {
            std::string_view name;
            if (!r.read_string(name)) return false;
            const auto details = r.remaining();
            out.extensions.push_back(constraint_extension{
                std::string{name},
                std::vector<std::byte>(details.begin(), details.end()),
            });
            return r.ok();
        } else {
            return false;
        }
    }
    return r.ok();
}

}  // namespace detail

YANTERM_SSH_INLINE std::uint32_t decode_frame_header(std::span<const std::byte> header) noexcept {
    if (header.size() != 4) return 0;
    return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(header[0])) << 24)
        | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(header[1])) << 16)
        | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(header[2])) << 8)
        | static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(header[3]));
}

YANTERM_SSH_INLINE void encode_frame_header(wire::writer& w, std::uint32_t length) {
    w.write_uint32(length);
}

YANTERM_SSH_INLINE msg message_type(std::span<const std::byte> payload) noexcept {
    if (payload.empty()) return static_cast<msg>(0);
    return static_cast<msg>(std::to_integer<std::uint8_t>(payload[0]));
}

YANTERM_SSH_INLINE void encode_failure(wire::writer& w) { detail::write_type(w, msg::failure); }

YANTERM_SSH_INLINE bool decode_failure(std::span<const std::byte> payload) noexcept {
    wire::reader r{payload};
    return detail::read_exact_type(r, msg::failure);
}

YANTERM_SSH_INLINE void encode_success(wire::writer& w) { detail::write_type(w, msg::success); }

YANTERM_SSH_INLINE bool decode_success(std::span<const std::byte> payload) noexcept {
    wire::reader r{payload};
    return detail::read_exact_type(r, msg::success);
}

YANTERM_SSH_INLINE void encode_request_identities(wire::writer& w) {
    detail::write_type(w, msg::request_identities);
}

YANTERM_SSH_INLINE bool decode_request_identities(std::span<const std::byte> payload) noexcept {
    wire::reader r{payload};
    return detail::read_exact_type(r, msg::request_identities);
}

YANTERM_SSH_INLINE void encode_identities_answer(wire::writer& w,
                                                 std::span<const identity_view> identities) {
    detail::write_type(w, msg::identities_answer);
    w.write_uint32(static_cast<std::uint32_t>(identities.size()));
    for (const auto& id : identities) {
        w.write_string(id.key_blob);
        w.write_string(id.comment);
    }
}

YANTERM_SSH_INLINE bool decode_identities_answer(std::span<const std::byte> payload,
                                                 std::vector<identity_view>& out) {
    out.clear();
    wire::reader r{payload};
    std::uint8_t type = 0;
    std::uint32_t nkeys = 0;
    if (!r.read_byte(type) || type != static_cast<std::uint8_t>(msg::identities_answer)
        || !r.read_uint32(nkeys)) {
        return false;
    }
    if (nkeys > max_identities_count) return false;
    if (nkeys > r.remaining().size() / detail::min_identity_bytes) return false;
    out.reserve(nkeys);
    for (std::uint32_t i = 0; i < nkeys; ++i) {
        identity_view id;
        if (!r.read_string(id.key_blob) || !r.read_string(id.comment)) {
            out.clear();
            return false;
        }
        out.push_back(id);
    }
    if (!r.ok() || !r.empty()) {
        out.clear();
        return false;
    }
    return true;
}

YANTERM_SSH_INLINE void encode_sign_request(wire::writer& w, std::span<const std::byte> key_blob,
                                            std::span<const std::byte> data, std::uint32_t flags) {
    detail::write_type(w, msg::sign_request);
    w.write_string(key_blob);
    w.write_string(data);
    w.write_uint32(flags);
}

YANTERM_SSH_INLINE bool decode_sign_request(std::span<const std::byte> payload,
                                            std::span<const std::byte>& key_blob,
                                            std::span<const std::byte>& data,
                                            std::uint32_t& flags) noexcept {
    wire::reader r{payload};
    std::uint8_t type = 0;
    return r.read_byte(type) && type == static_cast<std::uint8_t>(msg::sign_request)
        && r.read_string(key_blob) && r.read_string(data) && r.read_uint32(flags) && r.empty();
}

YANTERM_SSH_INLINE void encode_sign_response(wire::writer& w,
                                             std::span<const std::byte> signature) {
    detail::write_type(w, msg::sign_response);
    w.write_string(signature);
}

YANTERM_SSH_INLINE bool decode_sign_response(std::span<const std::byte> payload,
                                             std::span<const std::byte>& signature) noexcept {
    wire::reader r{payload};
    std::uint8_t type = 0;
    return r.read_byte(type) && type == static_cast<std::uint8_t>(msg::sign_response)
        && r.read_string(signature) && r.empty();
}

YANTERM_SSH_INLINE void encode_extension(wire::writer& w, std::string_view name,
                                         std::span<const std::byte> data) {
    detail::write_type(w, msg::extension);
    w.write_string(name);
    w.write_bytes(data);
}

YANTERM_SSH_INLINE bool decode_extension(std::span<const std::byte> payload, std::string_view& name,
                                         std::span<const std::byte>& data) noexcept {
    wire::reader r{payload};
    std::uint8_t type = 0;
    if (!r.read_byte(type) || type != static_cast<std::uint8_t>(msg::extension)
        || !r.read_string(name)) {
        return false;
    }
    data = r.remaining();
    return r.ok();
}

YANTERM_SSH_INLINE void encode_extension_failure(wire::writer& w) {
    detail::write_type(w, msg::extension_failure);
}

YANTERM_SSH_INLINE bool decode_extension_failure(std::span<const std::byte> payload) noexcept {
    wire::reader r{payload};
    return detail::read_exact_type(r, msg::extension_failure);
}

YANTERM_SSH_INLINE void encode_extension_response(wire::writer& w, std::string_view name,
                                                  std::span<const std::byte> data) {
    detail::write_type(w, msg::extension_response);
    w.write_string(name);
    w.write_bytes(data);
}

YANTERM_SSH_INLINE bool decode_extension_response(std::span<const std::byte> payload,
                                                  std::string_view& name,
                                                  std::span<const std::byte>& data) noexcept {
    wire::reader r{payload};
    std::uint8_t type = 0;
    if (!r.read_byte(type) || type != static_cast<std::uint8_t>(msg::extension_response)
        || !r.read_string(name)) {
        return false;
    }
    data = r.remaining();
    return r.ok();
}

YANTERM_SSH_INLINE bool decode_query_response(std::span<const std::byte> payload,
                                              std::vector<std::string>& names) {
    names.clear();
    wire::reader r{payload};
    std::uint8_t type = 0;
    std::string_view response_name;
    if (!r.read_byte(type) || type != static_cast<std::uint8_t>(msg::extension_response)
        || !r.read_string(response_name) || response_name != query_extension) {
        return false;
    }
    while (!r.empty()) {
        if (names.size() >= max_identities_count) {
            names.clear();
            return false;
        }
        std::string_view name;
        if (!r.read_string(name)) {
            names.clear();
            return false;
        }
        names.emplace_back(name);
    }
    if (!r.ok()) {
        names.clear();
        return false;
    }
    return true;
}

YANTERM_SSH_INLINE void encode_add_identity(wire::writer& w, std::span<const std::byte> key,
                                            std::string_view comment,
                                            const key_constraints& constraints) {
    detail::write_type(w, constraints_empty(constraints) ? msg::add_identity
                                                         : msg::add_id_constrained);
    w.write_bytes(key);
    w.write_string(comment);
    if (!constraints_empty(constraints)) detail::write_constraints(w, constraints);
}

YANTERM_SSH_INLINE bool decode_add_identity(std::span<const std::byte> payload,
                                            std::span<const std::byte>& key,
                                            std::string_view& comment,
                                            key_constraints& constraints) {
    constraints = {};
    wire::reader r{payload};
    std::uint8_t type = 0;
    if (!r.read_byte(type)
        || (type != static_cast<std::uint8_t>(msg::add_identity)
            && type != static_cast<std::uint8_t>(msg::add_id_constrained))) {
        return false;
    }
    const auto before = r.remaining().size();
    std::string_view key_type;
    if (!r.read_string(key_type)) return false;
    const int values = detail::key_value_strings(key_type);
    if (values < 0 || !detail::skip_strings(r, values)) return false;
    const auto after = r.remaining().size();
    key = payload.subspan(payload.size() - before, before - after);
    if (!r.read_string(comment)) return false;
    if (type == static_cast<std::uint8_t>(msg::add_identity)) {
        return r.empty();
    }
    if (!detail::read_constraints(r, constraints)) {
        constraints = {};
        return false;
    }
    return true;
}

YANTERM_SSH_INLINE void encode_remove_identity(wire::writer& w,
                                               std::span<const std::byte> key_blob) {
    detail::write_type(w, msg::remove_identity);
    w.write_string(key_blob);
}

YANTERM_SSH_INLINE bool decode_remove_identity(std::span<const std::byte> payload,
                                               std::span<const std::byte>& key_blob) noexcept {
    wire::reader r{payload};
    std::uint8_t type = 0;
    return r.read_byte(type) && type == static_cast<std::uint8_t>(msg::remove_identity)
        && r.read_string(key_blob) && r.empty();
}

YANTERM_SSH_INLINE void encode_remove_all_identities(wire::writer& w) {
    detail::write_type(w, msg::remove_all_identities);
}

YANTERM_SSH_INLINE bool decode_remove_all_identities(std::span<const std::byte> payload) noexcept {
    wire::reader r{payload};
    return detail::read_exact_type(r, msg::remove_all_identities);
}

YANTERM_SSH_INLINE void encode_add_smartcard_key(wire::writer& w, std::string_view token_id,
                                                 std::string_view pin,
                                                 const key_constraints& constraints) {
    detail::write_type(w, constraints_empty(constraints) ? msg::add_smartcard_key
                                                         : msg::add_smartcard_key_constrained);
    w.write_string(token_id);
    w.write_string(pin);
    if (!constraints_empty(constraints)) detail::write_constraints(w, constraints);
}

YANTERM_SSH_INLINE bool decode_add_smartcard_key(std::span<const std::byte> payload,
                                                 std::string_view& token_id, std::string_view& pin,
                                                 key_constraints& constraints) {
    constraints = {};
    wire::reader r{payload};
    std::uint8_t type = 0;
    if (!r.read_byte(type)
        || (type != static_cast<std::uint8_t>(msg::add_smartcard_key)
            && type != static_cast<std::uint8_t>(msg::add_smartcard_key_constrained))
        || !r.read_string(token_id) || !r.read_string(pin)) {
        return false;
    }
    if (type == static_cast<std::uint8_t>(msg::add_smartcard_key)) return r.empty();
    if (!detail::read_constraints(r, constraints)) {
        constraints = {};
        return false;
    }
    return true;
}

YANTERM_SSH_INLINE void encode_remove_smartcard_key(wire::writer& w, std::string_view token_id,
                                                    std::string_view pin) {
    detail::write_type(w, msg::remove_smartcard_key);
    w.write_string(token_id);
    w.write_string(pin);
}

YANTERM_SSH_INLINE bool decode_remove_smartcard_key(std::span<const std::byte> payload,
                                                    std::string_view& token_id,
                                                    std::string_view& pin) noexcept {
    wire::reader r{payload};
    std::uint8_t type = 0;
    return r.read_byte(type) && type == static_cast<std::uint8_t>(msg::remove_smartcard_key)
        && r.read_string(token_id) && r.read_string(pin) && r.empty();
}

YANTERM_SSH_INLINE void encode_lock(wire::writer& w, std::string_view passphrase) {
    detail::write_type(w, msg::lock);
    w.write_string(passphrase);
}

YANTERM_SSH_INLINE bool decode_lock(std::span<const std::byte> payload,
                                    std::string_view& passphrase) noexcept {
    wire::reader r{payload};
    std::uint8_t type = 0;
    return r.read_byte(type) && type == static_cast<std::uint8_t>(msg::lock)
        && r.read_string(passphrase) && r.empty();
}

YANTERM_SSH_INLINE void encode_unlock(wire::writer& w, std::string_view passphrase) {
    detail::write_type(w, msg::unlock);
    w.write_string(passphrase);
}

YANTERM_SSH_INLINE bool decode_unlock(std::span<const std::byte> payload,
                                      std::string_view& passphrase) noexcept {
    wire::reader r{payload};
    std::uint8_t type = 0;
    return r.read_byte(type) && type == static_cast<std::uint8_t>(msg::unlock)
        && r.read_string(passphrase) && r.empty();
}

YANTERM_SSH_INLINE void encode_session_bind(wire::writer& w, std::span<const std::byte> host_key,
                                            std::span<const std::byte> session_id,
                                            std::span<const std::byte> signature,
                                            bool is_forwarding) {
    detail::write_type(w, msg::extension);
    w.write_string(session_bind_extension);
    w.write_string(host_key);
    w.write_string(session_id);
    w.write_string(signature);
    w.write_bool(is_forwarding);
}

YANTERM_SSH_INLINE bool decode_session_bind(std::span<const std::byte> payload,
                                            std::span<const std::byte>& host_key,
                                            std::span<const std::byte>& session_id,
                                            std::span<const std::byte>& signature,
                                            bool& is_forwarding) noexcept {
    wire::reader r{payload};
    std::uint8_t type = 0;
    std::string_view name;
    if (!r.read_byte(type) || type != static_cast<std::uint8_t>(msg::extension)
        || !r.read_string(name) || name != session_bind_extension
        || !r.read_string(host_key) || !r.read_string(session_id) || !r.read_string(signature)
        || !r.read_bool(is_forwarding) || !r.empty()) {
        return false;
    }
    return true;
}

}  // namespace yanterm::ssh::agent
