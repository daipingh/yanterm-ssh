#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/auth/types.hpp>
#include <yanterm-ssh/channels/types.hpp>
#include <yanterm-ssh/kex/algorithms.hpp>
#include <yanterm-ssh/wire/message_ids.hpp>

#include <compare>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace yanterm::ssh::core {

class connection;

// Callback views are borrowed and valid only for the duration of the callback.
// The host-key blob, negotiated algorithms, and session id remain valid for the
// session. Callbacks may resolve tickets, start protocol actions, and query the
// connection. They must not call feed() or destroy the connection.
//
// Most callbacks run synchronously inside feed(). Slot-releasing commands may
// synchronously call on_released; connection destruction never calls back.
// For one channel, on_open_result precedes other notifications, on_eof precedes
// on_closed, and on_released is exactly once and last. on_readable is emitted
// only when an extended-data receive queue changes from empty to non-empty.

// Slot handle. seq == 0 is invalid. channel_slots mints a per-connection
// sequence at allocate time so a recycled channel id cannot match a stale ref.
struct channel_ref {
    channels::channel_id index = 0;
    std::uint32_t seq = 0;
    friend bool operator==(channel_ref, channel_ref) = default;
    friend auto operator<=>(channel_ref, channel_ref) = default;
};

class host_key_ticket {
public:
    host_key_ticket() = default;
    friend bool operator==(host_key_ticket, host_key_ticket) = default;
    friend auto operator<=>(host_key_ticket, host_key_ticket) = default;

private:
    friend class connection;
    explicit host_key_ticket(std::uint64_t seq) noexcept : seq_(seq) {}
    std::uint64_t seq_ = 0;
};

class auth_ticket {
public:
    auth_ticket() = default;
    friend bool operator==(auth_ticket, auth_ticket) = default;
    friend auto operator<=>(auth_ticket, auth_ticket) = default;

private:
    friend class connection;
    explicit auth_ticket(std::uint64_t seq) noexcept : seq_(seq) {}
    std::uint64_t seq_ = 0;
};

class kbdint_ticket {
public:
    kbdint_ticket() = default;
    friend bool operator==(kbdint_ticket, kbdint_ticket) = default;
    friend auto operator<=>(kbdint_ticket, kbdint_ticket) = default;

private:
    friend class connection;
    explicit kbdint_ticket(std::uint64_t seq) noexcept : seq_(seq) {}
    std::uint64_t seq_ = 0;
};

class open_ticket {
public:
    open_ticket() = default;
    friend bool operator==(open_ticket, open_ticket) = default;
    friend auto operator<=>(open_ticket, open_ticket) = default;

private:
    friend class connection;
    explicit open_ticket(channel_ref ref) noexcept : ref_(ref) {}
    channel_ref ref_{};
};

class global_request_ticket {
public:
    global_request_ticket() = default;
    friend bool operator==(global_request_ticket, global_request_ticket) = default;
    friend auto operator<=>(global_request_ticket, global_request_ticket) = default;

private:
    friend class connection;
    explicit global_request_ticket(std::uint64_t seq) noexcept : seq_(seq) {}
    std::uint64_t seq_ = 0;
};

// ref_ then seq_ so the 8-byte channel_ref sits on an 8-byte boundary and the
// ticket is 16 bytes with no tail padding.
class channel_request_ticket {
public:
    channel_request_ticket() = default;
    friend bool operator==(channel_request_ticket, channel_request_ticket) = default;
    friend auto operator<=>(channel_request_ticket, channel_request_ticket) = default;

private:
    friend class connection;
    channel_request_ticket(channel_ref ref, std::uint64_t seq) noexcept
        : ref_(ref), seq_(seq) {}
    channel_ref ref_{};
    std::uint64_t seq_ = 0;
};

static_assert(sizeof(channel_request_ticket) == 16);

class handler {
public:
    virtual void on_peer_identification(connection&, std::string_view banner);
    virtual void on_host_key(connection&, host_key_ticket, std::span<const std::byte> blob);
    virtual void on_handshake_done(connection&);
    virtual void on_rekey_done(connection&);
    virtual void on_debug(connection&, bool always_display, std::string_view text,
                          std::string_view language);
    virtual void on_ignore(connection&, std::span<const std::byte> data);
    virtual void on_disconnect(connection&, wire::disconnect_reason reason,
                               std::string_view description, std::string_view language);

    virtual void on_auth_banner(connection&, std::string_view text, std::string_view language);
    virtual void on_auth_result(connection&, const auth::auth_result&);
    virtual void on_kbdint_request(connection&, kbdint_ticket, const auth::info_request_view&);
    virtual void on_auth_request(connection&, auth_ticket, const auth::auth_request_view&);
    virtual void on_kbdint_response(connection&, auth_ticket,
                                    std::span<const std::string_view> responses);

    virtual void on_open_request(connection&, open_ticket,
                                 const channels::open_request_view&);
    virtual void on_open_result(connection&, channel_ref, void* user,
                                const channels::open_result_view&);
    virtual void on_channel_request(connection&, channel_request_ticket, void* user,
                                    const channels::request_view&);
    virtual void on_channel_reply(connection&, channel_ref, void* user, bool success);
    virtual void on_global_request(connection&, global_request_ticket,
                                   const channels::request_view&);
    virtual void on_global_reply(connection&, bool success,
                                 std::span<const std::byte> payload);
    virtual void on_readable(connection&, channel_ref, void* user, std::uint32_t ext_type);
    virtual void on_writable(connection&, channel_ref, void* user);
    virtual void on_eof(connection&, channel_ref, void* user);
    virtual void on_closed(connection&, channel_ref, void* user);
    virtual void on_released(connection&, channel_ref, void* user);

protected:
    ~handler() = default;
};

}  // namespace yanterm::ssh::core
