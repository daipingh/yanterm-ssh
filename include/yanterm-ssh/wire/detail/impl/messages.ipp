#pragma once

#include <yanterm-ssh/wire/detail/messages.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/wire/detail/impl/messages.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/detail/error.hpp>

namespace yanterm::ssh::wire::detail {

YANTERM_SSH_INLINE bool expect_id(reader& r, msg expected) noexcept {
    std::uint8_t id = 0;
    if (!r.read_byte(id)) return false;
    if (id != static_cast<std::uint8_t>(expected)) return r.fail(code::invalid_format);
    return true;
}

YANTERM_SSH_INLINE bool kexinit::decode(reader& r) noexcept {
    if (!expect_id(r, msg::kexinit)) return false;
    std::span<const std::byte> c;
    if (!r.read_bytes(c, cookie.size())) return false;
    for (std::size_t i = 0; i < cookie.size(); ++i) cookie[i] = c[i];
    return r.read_name_list(kex_algorithms)
        && r.read_name_list(server_host_key_algorithms)
        && r.read_name_list(encryption_c2s)
        && r.read_name_list(encryption_s2c)
        && r.read_name_list(mac_c2s)
        && r.read_name_list(mac_s2c)
        && r.read_name_list(compression_c2s)
        && r.read_name_list(compression_s2c)
        && r.read_name_list(languages_c2s)
        && r.read_name_list(languages_s2c)
        && r.read_bool(first_kex_packet_follows)
        && r.read_uint32(reserved);
}

YANTERM_SSH_INLINE void kexinit::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::kexinit));
    w.write_bytes(cookie);
    w.write_name_list(out_kex_algorithms);
    w.write_name_list(out_server_host_key_algorithms);
    w.write_name_list(out_encryption_c2s);
    w.write_name_list(out_encryption_s2c);
    w.write_name_list(out_mac_c2s);
    w.write_name_list(out_mac_s2c);
    w.write_name_list(out_compression_c2s);
    w.write_name_list(out_compression_s2c);
    w.write_name_list(out_languages_c2s);
    w.write_name_list(out_languages_s2c);
    w.write_bool(first_kex_packet_follows);
    w.write_uint32(reserved);
}

YANTERM_SSH_INLINE bool disconnect_msg::decode(reader& r) noexcept {
    if (!expect_id(r, msg::disconnect)) return false;
    std::uint32_t code = 0;
    if (!r.read_uint32(code)) return false;
    reason = static_cast<disconnect_reason>(code);
    return r.read_string(description) && r.read_string(language);
}

YANTERM_SSH_INLINE void disconnect_msg::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::disconnect));
    w.write_uint32(static_cast<std::uint32_t>(reason));
    w.write_string(description);
    w.write_string(language);
}

YANTERM_SSH_INLINE bool debug_msg::decode(reader& r) noexcept {
    if (!expect_id(r, msg::debug)) return false;
    return r.read_bool(always_display) && r.read_string(message) && r.read_string(language);
}

YANTERM_SSH_INLINE void debug_msg::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::debug));
    w.write_bool(always_display);
    w.write_string(message);
    w.write_string(language);
}

YANTERM_SSH_INLINE bool ignore_msg::decode(reader& r) noexcept {
    if (!expect_id(r, msg::ignore)) return false;
    return r.read_string(data);
}

YANTERM_SSH_INLINE void ignore_msg::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::ignore));
    w.write_string(data);
}

YANTERM_SSH_INLINE bool unimplemented_msg::decode(reader& r) noexcept {
    if (!expect_id(r, msg::unimplemented)) return false;
    return r.read_uint32(sequence_number);
}

YANTERM_SSH_INLINE void unimplemented_msg::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::unimplemented));
    w.write_uint32(sequence_number);
}

YANTERM_SSH_INLINE bool service_msg::decode(reader& r) noexcept {
    if (!expect_id(r, id)) return false;
    return r.read_string(service_name);
}

YANTERM_SSH_INLINE void service_msg::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(id));
    w.write_string(service_name);
}

YANTERM_SSH_INLINE bool ext_info::decode(reader& r) noexcept {
    if (!expect_id(r, msg::ext_info)) return false;
    if (!r.read_uint32(count)) return false;
    raw_entries = r.remaining();
    // Validate the whole list up front so find() can scan without re-checking.
    reader scan{raw_entries};
    for (std::uint32_t i = 0; i < count; ++i) {
        std::string_view name;
        std::span<const std::byte> value;
        if (!scan.read_string(name) || !scan.read_string(value)) return false;
    }
    std::span<const std::byte> consumed;
    return r.read_bytes(consumed, scan.offset());
}

YANTERM_SSH_INLINE bool ext_info::find(std::string_view name, std::string_view& value) const noexcept {
    reader scan{raw_entries};
    for (std::uint32_t i = 0; i < count; ++i) {
        std::string_view n;
        std::string_view v;
        if (!scan.read_string(n) || !scan.read_string(v)) return false;
        if (n == name) { value = v; return true; }
    }
    return false;
}

YANTERM_SSH_INLINE void ext_info::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::ext_info));
    w.write_uint32(static_cast<std::uint32_t>(entries.size()));
    for (const entry& e : entries) {
        w.write_string(e.name);
        w.write_string(e.value);
    }
}

YANTERM_SSH_INLINE bool kex_ecdh_init::decode(reader& r) noexcept {
    if (!expect_id(r, msg::kex_ecdh_init)) return false;
    return r.read_string(client_public);
}

YANTERM_SSH_INLINE void kex_ecdh_init::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::kex_ecdh_init));
    w.write_string(client_public);
}

YANTERM_SSH_INLINE bool kex_ecdh_reply::decode(reader& r) noexcept {
    if (!expect_id(r, msg::kex_ecdh_reply)) return false;
    return r.read_string(host_key) && r.read_string(server_public) && r.read_string(signature);
}

YANTERM_SSH_INLINE void kex_ecdh_reply::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::kex_ecdh_reply));
    w.write_string(host_key);
    w.write_string(server_public);
    w.write_string(signature);
}

YANTERM_SSH_INLINE bool kexdh_init::decode(reader& r) noexcept {
    if (!expect_id(r, msg::kexdh_init)) return false;
    return r.read_mpint(e);
}

YANTERM_SSH_INLINE void kexdh_init::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::kexdh_init));
    w.write_mpint(e);
}

YANTERM_SSH_INLINE bool kexdh_reply::decode(reader& r) noexcept {
    if (!expect_id(r, msg::kexdh_reply)) return false;
    return r.read_string(host_key) && r.read_mpint(f) && r.read_string(signature);
}

YANTERM_SSH_INLINE void kexdh_reply::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::kexdh_reply));
    w.write_string(host_key);
    w.write_mpint(f);
    w.write_string(signature);
}

YANTERM_SSH_INLINE bool read_userauth_request_head(reader& r, std::string_view expected_method,
                                       std::string_view& user,
                                       std::string_view& service) noexcept {
    if (!expect_id(r, msg::userauth_request)) return false;
    std::string_view method;
    if (!r.read_string(user) || !r.read_string(service) || !r.read_string(method)) return false;
    if (method != expected_method) return r.fail(code::invalid_format);
    return true;
}

YANTERM_SSH_INLINE void write_userauth_request_head(writer& w, std::string_view user,
                                        std::string_view service,
                                        std::string_view method) {
    w.write_byte(static_cast<std::uint8_t>(msg::userauth_request));
    w.write_string(user);
    w.write_string(service);
    w.write_string(method);
}

YANTERM_SSH_INLINE bool userauth_request_none::decode(reader& r) noexcept {
    return read_userauth_request_head(r, "none", user, service);
}

YANTERM_SSH_INLINE void userauth_request_none::encode(writer& w) const {
    write_userauth_request_head(w, user, service, "none");
}

YANTERM_SSH_INLINE bool userauth_request_password::decode(reader& r) noexcept {
    if (!read_userauth_request_head(r, "password", user, service)) return false;
    if (!r.read_bool(change_password) || !r.read_string(password)) return false;
    if (change_password) return r.read_string(new_password);
    return true;
}

YANTERM_SSH_INLINE void userauth_request_password::encode(writer& w) const {
    write_userauth_request_head(w, user, service, "password");
    w.write_bool(false);  // change_password always false in M3 encode
    w.write_string(password);
}

YANTERM_SSH_INLINE bool userauth_request_publickey::decode(reader& r) noexcept {
    if (!read_userauth_request_head(r, "publickey", user, service)) return false;
    if (!r.read_bool(has_signature) || !r.read_string(algorithm) || !r.read_string(blob)) {
        return false;
    }
    if (has_signature) return r.read_string(signature);
    return true;
}

YANTERM_SSH_INLINE void userauth_request_publickey::encode(writer& w) const {
    write_userauth_request_head(w, user, service, "publickey");
    w.write_bool(has_signature);
    w.write_string(algorithm);
    w.write_string(blob);
    if (has_signature) w.write_string(signature);
}

YANTERM_SSH_INLINE bool userauth_request_kbdint::decode(reader& r) noexcept {
    if (!read_userauth_request_head(r, "keyboard-interactive", user, service)) {
        return false;
    }
    return r.read_string(language) && r.read_name_list(submethods);
}

YANTERM_SSH_INLINE void userauth_request_kbdint::encode(writer& w) const {
    write_userauth_request_head(w, user, service, "keyboard-interactive");
    w.write_string(language);
    w.write_name_list(out_submethods);
}

YANTERM_SSH_INLINE bool userauth_failure::decode(reader& r) noexcept {
    if (!expect_id(r, msg::userauth_failure)) return false;
    return r.read_name_list(methods) && r.read_bool(partial_success);
}

YANTERM_SSH_INLINE void userauth_failure::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::userauth_failure));
    w.write_name_list(out_methods);
    w.write_bool(partial_success);
}

YANTERM_SSH_INLINE bool userauth_success::decode(reader& r) noexcept {
    return expect_id(r, msg::userauth_success);
}

YANTERM_SSH_INLINE void userauth_success::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::userauth_success));
}

YANTERM_SSH_INLINE bool userauth_banner::decode(reader& r) noexcept {
    if (!expect_id(r, msg::userauth_banner)) return false;
    return r.read_string(message) && r.read_string(language);
}

YANTERM_SSH_INLINE void userauth_banner::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::userauth_banner));
    w.write_string(message);
    w.write_string(language);
}

YANTERM_SSH_INLINE bool userauth_pk_ok::decode(reader& r) noexcept {
    if (!expect_id(r, msg::userauth_pk_ok)) return false;
    return r.read_string(algorithm) && r.read_string(blob);
}

YANTERM_SSH_INLINE void userauth_pk_ok::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::userauth_pk_ok));
    w.write_string(algorithm);
    w.write_string(blob);
}

YANTERM_SSH_INLINE bool userauth_info_request::decode(reader& r) noexcept {
    if (!expect_id(r, msg::userauth_info_request)) return false;
    if (!r.read_string(name) || !r.read_string(instruction) || !r.read_string(language)
        || !r.read_uint32(num_prompts)) {
        return false;
    }
    prompts_raw = r.remaining();
    reader scan{prompts_raw};
    for (std::uint32_t i = 0; i < num_prompts; ++i) {
        std::string_view prompt;
        bool echo = false;
        if (!scan.read_string(prompt) || !scan.read_bool(echo)) return false;
    }
    std::span<const std::byte> consumed;
    return r.read_bytes(consumed, scan.offset());
}

YANTERM_SSH_INLINE bool userauth_info_request::prompt_at(std::uint32_t i, std::string_view& prompt, bool& echo) const noexcept {
    reader scan{prompts_raw};
    for (std::uint32_t n = 0; n < num_prompts; ++n) {
        std::string_view p;
        bool e = false;
        if (!scan.read_string(p) || !scan.read_bool(e)) return false;
        if (n == i) {
            prompt = p;
            echo = e;
            return true;
        }
    }
    return false;
}

YANTERM_SSH_INLINE void userauth_info_request::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::userauth_info_request));
    w.write_string(name);
    w.write_string(instruction);
    w.write_string(language);
    w.write_uint32(static_cast<std::uint32_t>(prompts.size()));
    for (const userauth_info_prompt& p : prompts) {
        w.write_string(p.prompt);
        w.write_bool(p.echo);
    }
}

YANTERM_SSH_INLINE bool userauth_info_response::decode(reader& r) noexcept {
    if (!expect_id(r, msg::userauth_info_response)) return false;
    if (!r.read_uint32(num_responses)) return false;
    responses_raw = r.remaining();
    reader scan{responses_raw};
    for (std::uint32_t i = 0; i < num_responses; ++i) {
        std::string_view response;
        if (!scan.read_string(response)) return false;
    }
    std::span<const std::byte> consumed;
    return r.read_bytes(consumed, scan.offset());
}

YANTERM_SSH_INLINE bool userauth_info_response::response_at(std::uint32_t i, std::string_view& out) const noexcept {
    reader scan{responses_raw};
    for (std::uint32_t n = 0; n < num_responses; ++n) {
        std::string_view v;
        if (!scan.read_string(v)) return false;
        if (n == i) {
            out = v;
            return true;
        }
    }
    return false;
}

YANTERM_SSH_INLINE void userauth_info_response::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::userauth_info_response));
    w.write_uint32(static_cast<std::uint32_t>(responses.size()));
    for (std::string_view v : responses) w.write_string(v);
}

YANTERM_SSH_INLINE void channel_open::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::channel_open));
    w.write_string(type);
    w.write_uint32(sender);
    w.write_uint32(window);
    w.write_uint32(max_packet);
    w.write_bytes(extra);
}

YANTERM_SSH_INLINE bool channel_open::decode(reader& r) noexcept {
    if (!expect_id(r, msg::channel_open)) return false;
    if (!r.read_string(type) || !r.read_uint32(sender) || !r.read_uint32(window)
        || !r.read_uint32(max_packet)) {
        return false;
    }
    extra = r.remaining();
    std::span<const std::byte> rest;
    return r.read_bytes(rest, extra.size());
}

YANTERM_SSH_INLINE void channel_open_confirmation::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::channel_open_confirmation));
    w.write_uint32(recipient);
    w.write_uint32(sender);
    w.write_uint32(window);
    w.write_uint32(max_packet);
    w.write_bytes(extra);
}

YANTERM_SSH_INLINE bool channel_open_confirmation::decode(reader& r) noexcept {
    if (!expect_id(r, msg::channel_open_confirmation)) return false;
    if (!r.read_uint32(recipient) || !r.read_uint32(sender) || !r.read_uint32(window)
        || !r.read_uint32(max_packet)) {
        return false;
    }
    extra = r.remaining();
    std::span<const std::byte> rest;
    return r.read_bytes(rest, extra.size());
}

YANTERM_SSH_INLINE void channel_open_failure::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::channel_open_failure));
    w.write_uint32(recipient);
    w.write_uint32(reason);
    w.write_string(description);
    w.write_string(language);
}

YANTERM_SSH_INLINE bool channel_open_failure::decode(reader& r) noexcept {
    if (!expect_id(r, msg::channel_open_failure)) return false;
    return r.read_uint32(recipient) && r.read_uint32(reason) && r.read_string(description)
        && r.read_string(language);
}

YANTERM_SSH_INLINE void channel_window_adjust::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::channel_window_adjust));
    w.write_uint32(recipient);
    w.write_uint32(bytes);
}

YANTERM_SSH_INLINE bool channel_window_adjust::decode(reader& r) noexcept {
    if (!expect_id(r, msg::channel_window_adjust)) return false;
    return r.read_uint32(recipient) && r.read_uint32(bytes);
}

YANTERM_SSH_INLINE void channel_data::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::channel_data));
    w.write_uint32(recipient);
    w.write_string(data);
}

YANTERM_SSH_INLINE bool channel_data::decode(reader& r) noexcept {
    if (!expect_id(r, msg::channel_data)) return false;
    return r.read_uint32(recipient) && r.read_string(data);
}

YANTERM_SSH_INLINE void channel_extended_data::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::channel_extended_data));
    w.write_uint32(recipient);
    w.write_uint32(data_type);
    w.write_string(data);
}

YANTERM_SSH_INLINE bool channel_extended_data::decode(reader& r) noexcept {
    if (!expect_id(r, msg::channel_extended_data)) return false;
    return r.read_uint32(recipient) && r.read_uint32(data_type) && r.read_string(data);
}

YANTERM_SSH_INLINE void channel_eof_msg::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::channel_eof));
    w.write_uint32(recipient);
}

YANTERM_SSH_INLINE bool channel_eof_msg::decode(reader& r) noexcept {
    if (!expect_id(r, msg::channel_eof)) return false;
    return r.read_uint32(recipient);
}

YANTERM_SSH_INLINE void channel_close_msg::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::channel_close));
    w.write_uint32(recipient);
}

YANTERM_SSH_INLINE bool channel_close_msg::decode(reader& r) noexcept {
    if (!expect_id(r, msg::channel_close)) return false;
    return r.read_uint32(recipient);
}

YANTERM_SSH_INLINE void channel_success_msg::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::channel_success));
    w.write_uint32(recipient);
}

YANTERM_SSH_INLINE bool channel_success_msg::decode(reader& r) noexcept {
    if (!expect_id(r, msg::channel_success)) return false;
    return r.read_uint32(recipient);
}

YANTERM_SSH_INLINE void channel_failure_msg::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::channel_failure));
    w.write_uint32(recipient);
}

YANTERM_SSH_INLINE bool channel_failure_msg::decode(reader& r) noexcept {
    if (!expect_id(r, msg::channel_failure)) return false;
    return r.read_uint32(recipient);
}

YANTERM_SSH_INLINE void channel_request::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::channel_request));
    w.write_uint32(recipient);
    w.write_string(type);
    w.write_bool(want_reply);
    w.write_bytes(extra);
}

YANTERM_SSH_INLINE bool channel_request::decode(reader& r) noexcept {
    if (!expect_id(r, msg::channel_request)) return false;
    if (!r.read_uint32(recipient) || !r.read_string(type) || !r.read_bool(want_reply)) {
        return false;
    }
    extra = r.remaining();
    std::span<const std::byte> rest;
    return r.read_bytes(rest, extra.size());
}

YANTERM_SSH_INLINE void global_request::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::global_request));
    w.write_string(type);
    w.write_bool(want_reply);
    w.write_bytes(extra);
}

YANTERM_SSH_INLINE bool global_request::decode(reader& r) noexcept {
    if (!expect_id(r, msg::global_request)) return false;
    if (!r.read_string(type) || !r.read_bool(want_reply)) return false;
    extra = r.remaining();
    std::span<const std::byte> rest;
    return r.read_bytes(rest, extra.size());
}

YANTERM_SSH_INLINE void request_success::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::request_success));
    w.write_bytes(extra);
}

YANTERM_SSH_INLINE bool request_success::decode(reader& r) noexcept {
    if (!expect_id(r, msg::request_success)) return false;
    extra = r.remaining();
    std::span<const std::byte> rest;
    return r.read_bytes(rest, extra.size());
}

YANTERM_SSH_INLINE void request_failure::encode(writer& w) const {
    w.write_byte(static_cast<std::uint8_t>(msg::request_failure));
}

YANTERM_SSH_INLINE bool request_failure::decode(reader& r) noexcept {
    return expect_id(r, msg::request_failure);
}

}  // namespace yanterm::ssh::wire::detail
