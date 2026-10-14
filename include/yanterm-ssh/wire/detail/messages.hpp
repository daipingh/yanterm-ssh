#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/wire/message_ids.hpp>
#include <yanterm-ssh/wire/types.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace yanterm::ssh::wire::detail {

bool expect_id(reader& r, msg expected) noexcept;

// SSH_MSG_KEXINIT (RFC 4253 section 7.1).
//
// On decode the name-list members borrow from the reader's buffer. On encode
// they are supplied as spans of string_view; the two representations are kept
// in separate members so a decoded kexinit can be inspected without copying and
// a fresh one can be built without allocating a name_list.
struct kexinit {
    std::array<std::byte, 16> cookie{};

    // Populated by decode().
    name_list kex_algorithms;
    name_list server_host_key_algorithms;
    name_list encryption_c2s;
    name_list encryption_s2c;
    name_list mac_c2s;
    name_list mac_s2c;
    name_list compression_c2s;
    name_list compression_s2c;
    name_list languages_c2s;
    name_list languages_s2c;

    // Consulted by encode(); ignored by decode().
    std::span<const std::string_view> out_kex_algorithms;
    std::span<const std::string_view> out_server_host_key_algorithms;
    std::span<const std::string_view> out_encryption_c2s;
    std::span<const std::string_view> out_encryption_s2c;
    std::span<const std::string_view> out_mac_c2s;
    std::span<const std::string_view> out_mac_s2c;
    std::span<const std::string_view> out_compression_c2s;
    std::span<const std::string_view> out_compression_s2c;
    std::span<const std::string_view> out_languages_c2s;
    std::span<const std::string_view> out_languages_s2c;

    bool first_kex_packet_follows = false;
    std::uint32_t reserved = 0;

    bool decode(reader& r) noexcept;
    void encode(writer& w) const;
};

struct disconnect_msg {
    disconnect_reason reason = disconnect_reason::protocol_error;
    std::string_view description;
    std::string_view language;

    bool decode(reader& r) noexcept;
    void encode(writer& w) const;
};

struct debug_msg {
    bool always_display = false;
    std::string_view message;
    std::string_view language;

    bool decode(reader& r) noexcept;
    void encode(writer& w) const;
};

struct ignore_msg {
    std::span<const std::byte> data;

    bool decode(reader& r) noexcept;
    void encode(writer& w) const;
};

struct unimplemented_msg {
    std::uint32_t sequence_number = 0;

    bool decode(reader& r) noexcept;
    void encode(writer& w) const;
};

// Serves both SSH_MSG_SERVICE_REQUEST and SSH_MSG_SERVICE_ACCEPT; `id` selects
// which, and decode() rejects the other.
struct service_msg {
    msg id = msg::service_request;
    std::string_view service_name;

    bool decode(reader& r) noexcept;
    void encode(writer& w) const;
};

// SSH_MSG_EXT_INFO (RFC 8308 section 2.3).
struct ext_info {
    struct entry {
        std::string_view name;
        std::span<const std::byte> value;
    };

    std::uint32_t count = 0;
    std::span<const std::byte> raw_entries;   // set by decode(), scanned by find()
    std::span<const entry> entries;           // consulted by encode()

    bool decode(reader& r) noexcept;
    [[nodiscard]] bool find(std::string_view name, std::string_view& value) const noexcept;
    void encode(writer& w) const;
};

// SSH_MSG_KEX_ECDH_INIT / REPLY (RFC 5656 section 4, RFC 8731 section 3).
struct kex_ecdh_init {
    std::span<const std::byte> client_public;   // Q_C

    bool decode(reader& r) noexcept;
    void encode(writer& w) const;
};

struct kex_ecdh_reply {
    std::span<const std::byte> host_key;        // K_S
    std::span<const std::byte> server_public;   // Q_S
    std::span<const std::byte> signature;

    bool decode(reader& r) noexcept;
    void encode(writer& w) const;
};

// SSH_MSG_KEXDH_INIT / REPLY (RFC 4253 section 8). `e` and `f` are mpints and
// are exposed as canonical big-endian magnitudes.
struct kexdh_init {
    std::span<const std::byte> e;

    bool decode(reader& r) noexcept;
    void encode(writer& w) const;
};

struct kexdh_reply {
    std::span<const std::byte> host_key;
    std::span<const std::byte> f;
    std::span<const std::byte> signature;

    bool decode(reader& r) noexcept;
    void encode(writer& w) const;
};

bool read_userauth_request_head(reader& r, std::string_view expected_method,
                                std::string_view& user,
                                std::string_view& service) noexcept;

void write_userauth_request_head(writer& w, std::string_view user,
                                 std::string_view service,
                                 std::string_view method);

// SSH_MSG_USERAUTH_REQUEST method "none" (RFC 4252 section 5.2).
struct userauth_request_none {
    std::string_view user;
    std::string_view service = "ssh-connection";

    bool decode(reader& r) noexcept;
    void encode(writer& w) const;
};

// SSH_MSG_USERAUTH_REQUEST method "password" (RFC 4252 section 8).
struct userauth_request_password {
    std::string_view user;
    std::string_view service = "ssh-connection";
    bool change_password = false;
    std::string_view password;
    std::string_view new_password{};

    bool decode(reader& r) noexcept;
    void encode(writer& w) const;
};

// SSH_MSG_USERAUTH_REQUEST method "publickey" (RFC 4252 section 7).
struct userauth_request_publickey {
    std::string_view user;
    std::string_view service = "ssh-connection";
    bool has_signature = false;
    std::string_view algorithm;
    std::span<const std::byte> blob;
    std::span<const std::byte> signature{};

    bool decode(reader& r) noexcept;
    void encode(writer& w) const;
};

// SSH_MSG_USERAUTH_REQUEST method "keyboard-interactive" (RFC 4256 section 3.1).
struct userauth_request_kbdint {
    std::string_view user;
    std::string_view service = "ssh-connection";
    std::string_view language;
    name_list submethods;
    std::span<const std::string_view> out_submethods{};

    bool decode(reader& r) noexcept;
    void encode(writer& w) const;
};

// SSH_MSG_USERAUTH_FAILURE (RFC 4252 section 5.1).
struct userauth_failure {
    name_list methods;
    std::span<const std::string_view> out_methods{};
    bool partial_success = false;

    bool decode(reader& r) noexcept;
    void encode(writer& w) const;
};

// SSH_MSG_USERAUTH_SUCCESS (RFC 4252 section 5.1).
struct userauth_success {
    bool decode(reader& r) noexcept;
    void encode(writer& w) const;
};

// SSH_MSG_USERAUTH_BANNER (RFC 4252 section 5.4).
struct userauth_banner {
    std::string_view message;
    std::string_view language;

    bool decode(reader& r) noexcept;
    void encode(writer& w) const;
};

// SSH_MSG_USERAUTH_PK_OK (RFC 4252 section 7).
struct userauth_pk_ok {
    std::string_view algorithm;
    std::span<const std::byte> blob;

    bool decode(reader& r) noexcept;
    void encode(writer& w) const;
};

struct userauth_info_prompt {
    std::string_view prompt;
    bool echo = true;
};

// SSH_MSG_USERAUTH_INFO_REQUEST (RFC 4256 section 3.2).
struct userauth_info_request {
    std::string_view name;
    std::string_view instruction;
    std::string_view language;
    std::uint32_t num_prompts = 0;
    std::span<const std::byte> prompts_raw;                 // decode
    std::span<const userauth_info_prompt> prompts{};        // encode

    bool decode(reader& r) noexcept;
    [[nodiscard]] bool prompt_at(std::uint32_t i, std::string_view& prompt, bool& echo) const noexcept;
    void encode(writer& w) const;
};

// SSH_MSG_USERAUTH_INFO_RESPONSE (RFC 4256 section 3.4).
struct userauth_info_response {
    std::span<const std::string_view> responses;
    std::uint32_t num_responses = 0;
    std::span<const std::byte> responses_raw;

    bool decode(reader& r) noexcept;
    [[nodiscard]] bool response_at(std::uint32_t i, std::string_view& out) const noexcept;
    void encode(writer& w) const;
};

struct channel_open {
    std::string_view type;
    std::uint32_t sender = 0;
    std::uint32_t window = 0;
    std::uint32_t max_packet = 0;
    std::span<const std::byte> extra{};
    void encode(writer& w) const;
    bool decode(reader& r) noexcept;
};

struct channel_open_confirmation {
    std::uint32_t recipient = 0;
    std::uint32_t sender = 0;
    std::uint32_t window = 0;
    std::uint32_t max_packet = 0;
    std::span<const std::byte> extra{};
    void encode(writer& w) const;
    bool decode(reader& r) noexcept;
};

struct channel_open_failure {
    std::uint32_t recipient = 0;
    std::uint32_t reason = 0;
    std::string_view description;
    std::string_view language;
    void encode(writer& w) const;
    bool decode(reader& r) noexcept;
};

struct channel_window_adjust {
    std::uint32_t recipient = 0;
    std::uint32_t bytes = 0;
    void encode(writer& w) const;
    bool decode(reader& r) noexcept;
};

struct channel_data {
    std::uint32_t recipient = 0;
    std::span<const std::byte> data;
    void encode(writer& w) const;
    bool decode(reader& r) noexcept;
};

struct channel_extended_data {
    std::uint32_t recipient = 0;
    std::uint32_t data_type = 0;
    std::span<const std::byte> data;
    void encode(writer& w) const;
    bool decode(reader& r) noexcept;
};

struct channel_eof_msg {
    std::uint32_t recipient = 0;
    void encode(writer& w) const;
    bool decode(reader& r) noexcept;
};
struct channel_close_msg {
    std::uint32_t recipient = 0;
    void encode(writer& w) const;
    bool decode(reader& r) noexcept;
};
struct channel_success_msg {
    std::uint32_t recipient = 0;
    void encode(writer& w) const;
    bool decode(reader& r) noexcept;
};
struct channel_failure_msg {
    std::uint32_t recipient = 0;
    void encode(writer& w) const;
    bool decode(reader& r) noexcept;
};

struct channel_request {
    std::uint32_t recipient = 0;
    std::string_view type;
    bool want_reply = false;
    std::span<const std::byte> extra{};
    void encode(writer& w) const;
    bool decode(reader& r) noexcept;
};

struct global_request {
    std::string_view type;
    bool want_reply = false;
    std::span<const std::byte> extra{};
    void encode(writer& w) const;
    bool decode(reader& r) noexcept;
};

struct request_success {
    std::span<const std::byte> extra{};  // empty or bound-port uint32
    void encode(writer& w) const;
    bool decode(reader& r) noexcept;
};

struct request_failure {
    void encode(writer& w) const;
    bool decode(reader& r) noexcept;
};

}  // namespace yanterm::ssh::wire::detail

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/wire/detail/impl/messages.ipp>
#endif
