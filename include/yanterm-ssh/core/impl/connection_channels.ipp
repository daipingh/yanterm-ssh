#pragma once

#include <yanterm-ssh/core/connection.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/core/impl/connection_channels.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/channels/requests.hpp>
#include <yanterm-ssh/wire/detail/messages.hpp>
#include <yanterm-ssh/wire/types.hpp>
#include <yanterm-ssh/detail/error.hpp>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <utility>

namespace yanterm::ssh::core {

YANTERM_SSH_INLINE std::error_code connection::resolve(open_ticket ticket, const channels::channel_open_verdict& v,
                                                       void* user) {
    if (phase_ == phase::dead) return code::invalid_state;
    if (failure_) return code::invalid_state;
    auto* c = slots_.find(ticket.ref_);
    if (!c || !c->inbound_open) return code::invalid_state;
    if (v.accept) {
        if (v.initial_window != 0) c->local_window = v.initial_window;
        if (v.max_packet != 0) c->local_max_packet = v.max_packet;
        c->advertised_window = c->local_window;
        wire::detail::channel_open_confirmation msg;
        msg.recipient = c->remote;
        msg.sender = c->local;
        msg.window = c->local_window;
        msg.max_packet = c->local_max_packet;
        if (auto ec = write_encoded(msg)) {
            fail(ec);
            phase_ = phase::dead;
            return ec;
        }
        c->user_data = user;
        c->inbound_open = false;
        return {};
    }
    wire::detail::channel_open_failure msg;
    msg.recipient = c->remote;
    msg.reason = static_cast<std::uint32_t>(v.reason);
    msg.description = v.description;
    msg.language = {};
    if (auto ec = write_encoded(msg)) {
        fail(ec);
        phase_ = phase::dead;
        return ec;
    }
    release_channel(ticket.ref_);
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::resolve(channel_request_ticket ticket, bool success) {
    if (phase_ == phase::dead) return code::invalid_state;
    if (failure_) return code::invalid_state;
    auto* c = slots_.find(ticket.ref_);
    if (!c) return code::invalid_state;
    if (ticket.seq_ == 0) return {};
    if (ticket.seq_ != c->inbound.head_seq) return code::invalid_state;
    if (!c->sent_close) {
        if (success) {
            wire::detail::channel_success_msg msg;
            msg.recipient = c->remote;
            if (auto ec = write_encoded(msg)) {
                fail(ec);
                phase_ = phase::dead;
                return ec;
            }
        } else {
            wire::detail::channel_failure_msg msg;
            msg.recipient = c->remote;
            if (auto ec = write_encoded(msg)) {
                fail(ec);
                phase_ = phase::dead;
                return ec;
            }
        }
    }
    ++c->inbound.head_seq;
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::resolve(global_request_ticket ticket, bool success,
                                                       std::span<const std::byte> response_payload) {
    if (phase_ == phase::dead) return code::invalid_state;
    if (failure_) return code::invalid_state;
    if (ticket.seq_ == 0) return {};
    if (ticket.seq_ != global_inbound_.head_seq) return code::invalid_state;
    if (success) {
        wire::detail::request_success msg;
        msg.extra = response_payload;
        if (auto ec = write_encoded(msg)) {
            fail(ec);
            phase_ = phase::dead;
            return ec;
        }
    } else {
        wire::detail::request_failure msg;
        if (auto ec = write_encoded(msg)) {
            fail(ec);
            phase_ = phase::dead;
            return ec;
        }
    }
    ++global_inbound_.head_seq;
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::open_channel(const channels::channel_open_spec& spec, void* user,
                                                            channel_ref& out) {
    if (!channels_active()) return code::invalid_state;
    const auto window = spec.initial_window != 0 ? spec.initial_window : cfg_.initial_window;
    const auto max_packet = spec.max_packet != 0 ? spec.max_packet : cfg_.max_channel_packet;
    detail::channel* c = nullptr;
    if (auto ec = slots_.allocate(window, max_packet, c)) return ec;
    c->user_data = user;
    const auto ref = detail::ref_of(*c);
    const auto local = c->local;

    wire::writer extra;
    detail::encode_open_extra(spec, extra);
    wire::detail::channel_open msg;
    msg.type = detail::type_string(spec);
    msg.sender = local;
    msg.window = c->local_window;
    msg.max_packet = c->local_max_packet;
    msg.extra = extra.data();
    if (auto ec = write_encoded(msg)) {
        slots_.erase(local);
        fail(ec);
        phase_ = phase::dead;
        return ec;
    }
    out = ref;
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::abandon_open(channel_ref ch) {
    if (!channels_active()) return code::invalid_state;
    auto* c = slots_.find(ch);
    if (!c) return code::invalid_state;
    if (c->remote_known || c->inbound_open) return code::invalid_state;
    c->abandoned = true;
    c->app_close = true;
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::channel_eof(channel_ref ch) {
    if (!channels_active()) return code::invalid_state;
    auto* c = slots_.find(ch);
    if (!c || !c->remote_known || c->sent_eof || c->sent_close) return code::invalid_state;
    wire::detail::channel_eof_msg msg;
    msg.recipient = c->remote;
    c->sent_eof = true;
    if (auto ec = write_encoded(msg)) {
        fail(ec);
        phase_ = phase::dead;
        return ec;
    }
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::channel_close(channel_ref ch) {
    if (!channels_active()) return code::invalid_state;
    auto* c = slots_.find(ch);
    if (!c) return code::invalid_state;
    c->app_close = true;
    if (!c->sent_close) {
        if (c->remote_known) {
            wire::detail::channel_close_msg msg;
            msg.recipient = c->remote;
            if (auto ec = write_encoded(msg)) {
                fail(ec);
                phase_ = phase::dead;
                return ec;
            }
            c->note_sent_close();
        } else {
            c->abandoned = true;
        }
    }
    if (auto* again = slots_.find(ch); again && again->releasable()) release_channel(ch);
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::channel_write(channel_ref ch,
                              std::span<const std::span<const std::byte>> fragments,
                              std::size_t& accepted) {
    accepted = 0;
    if (!channels_active()) return code::invalid_state;
    return write_channel_fragments(ch, 0, fragments, accepted);
}

YANTERM_SSH_INLINE std::error_code connection::channel_write_extended(channel_ref ch, std::uint32_t ext_type,
                                       std::span<const std::span<const std::byte>> fragments,
                                       std::size_t& accepted) {
    accepted = 0;
    if (!channels_active()) return code::invalid_state;
    if (ext_type != channels::extended_data_stderr) return code::invalid_state;
    return write_channel_fragments(ch, ext_type, fragments, accepted);
}

YANTERM_SSH_INLINE void connection::set_user_data(channel_ref ch, void* user) {
    if (auto* c = slots_.find(ch)) c->user_data = user;
}

YANTERM_SSH_INLINE std::size_t connection::channel_read(channel_ref ch, std::uint32_t ext_type,
                         std::span<std::byte> dst) {
    if (ext_type != 0 && ext_type != channels::extended_data_stderr) return 0;
    if (!authenticated() && !failure_ && phase_ != phase::dead) return 0;
    const bool suppress_adjust = failure_ || phase_ == phase::dead;
    auto* c = slots_.find(ch);
    if (!c) return 0;
    auto& q = (ext_type == 0) ? c->rx_data : c->rx_ext;
    std::size_t copied = 0;
    while (copied < dst.size() && !q.empty()) {
        memory::detail::page_slice& front = q.front();
        const auto n = std::min(front.size(), dst.size() - copied);
        const auto src = front.bytes();
        std::memcpy(dst.data() + copied, src.data(), n);
        copied += n;
        if (n == front.size()) {
            q.pop_front();
        } else {
            front = front.subslice(n, front.size() - n);
        }
    }
    const bool recv_close = c->recv_close;
    const auto remote = c->remote;
    if (copied > 0 && !recv_close) {
        c->pending_adjust += static_cast<std::uint32_t>(copied);
        const auto threshold = (std::max)(1u, c->advertised_window / 2);
        if (c->pending_adjust >= threshold) {
            const auto bytes = c->pending_adjust;
            c->local_window += bytes;
            c->pending_adjust = 0;
            if (!suppress_adjust) {
                wire::detail::channel_window_adjust msg;
                msg.recipient = remote;
                msg.bytes = bytes;
                if (auto ec = write_encoded(msg)) {
                    fail(ec);
                    phase_ = phase::dead;
                }
            }
        }
    }
    if (auto* again = slots_.find(ch); again && again->releasable()) release_channel(ch);
    return copied;
}

YANTERM_SSH_INLINE std::error_code connection::channel_request(channel_ref ch,
                                const channels::channel_request_spec& spec) {
    if (!channels_active()) return code::invalid_state;
    auto* c = slots_.find(ch);
    if (!c || !c->remote_known || c->sent_close || c->recv_close) return code::invalid_state;
    wire::detail::channel_request msg;
    msg.recipient = c->remote;
    msg.type = spec.type;
    msg.want_reply = spec.want_reply;
    msg.extra = spec.payload;
    if (spec.want_reply) ++c->outbound_outstanding;
    if (auto ec = write_encoded(msg)) {
        fail(ec);
        phase_ = phase::dead;
        return ec;
    }
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::request_pty(channel_ref ch, const channels::pty_spec& spec) {
    wire::writer w;
    channels::encode_pty_req(w, spec);
    return channel_request(ch, {"pty-req", w.data(), true});
}

YANTERM_SSH_INLINE std::error_code connection::request_shell(channel_ref ch) {
    return channel_request(ch, {"shell", {}, true});
}

YANTERM_SSH_INLINE std::error_code connection::request_exec(channel_ref ch, std::string_view command) {
    wire::writer w;
    channels::encode_exec(w, command);
    return channel_request(ch, {"exec", w.data(), true});
}

YANTERM_SSH_INLINE std::error_code connection::request_subsystem(channel_ref ch, std::string_view name) {
    wire::writer w;
    channels::encode_subsystem(w, name);
    return channel_request(ch, {"subsystem", w.data(), true});
}

YANTERM_SSH_INLINE std::error_code connection::request_env(channel_ref ch, std::string_view name,
                            std::string_view value) {
    wire::writer w;
    channels::encode_env(w, name, value);
    return channel_request(ch, {"env", w.data(), true});
}

YANTERM_SSH_INLINE std::error_code connection::request_window_change(channel_ref ch, const channels::window_size& size) {
    wire::writer w;
    channels::encode_window_change(w, size);
    return channel_request(ch, {"window-change", w.data(), false});
}

YANTERM_SSH_INLINE std::error_code connection::request_signal(channel_ref ch, std::string_view name) {
    wire::writer w;
    channels::encode_signal(w, name);
    return channel_request(ch, {"signal", w.data(), false});
}

YANTERM_SSH_INLINE std::error_code connection::send_exit_status(channel_ref ch, std::uint32_t status) {
    wire::writer w;
    channels::encode_exit_status(w, status);
    return channel_request(ch, {"exit-status", w.data(), false});
}

YANTERM_SSH_INLINE std::error_code connection::send_exit_signal(channel_ref ch, const channels::exit_signal& sig) {
    wire::writer w;
    channels::encode_exit_signal(w, sig);
    return channel_request(ch, {"exit-signal", w.data(), false});
}

YANTERM_SSH_INLINE std::error_code connection::request_x11(channel_ref ch, const channels::x11_req_spec& spec) {
    wire::writer w;
    channels::encode_x11_req(w, spec);
    return channel_request(ch, {"x11-req", w.data(), true});
}

YANTERM_SSH_INLINE std::error_code connection::send_global_request(std::string_view type, std::span<const std::byte> payload,
                                    bool want_reply) {
    if (!channels_active()) return code::invalid_state;
    wire::detail::global_request msg;
    msg.type = type;
    msg.want_reply = want_reply;
    msg.extra = payload;
    if (want_reply) ++global_outstanding_;
    if (auto ec = write_encoded(msg)) {
        fail(ec);
        phase_ = phase::dead;
        return ec;
    }
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::request_tcpip_forward(std::string_view addr, std::uint32_t port) {
    wire::writer w;
    channels::encode_tcpip_forward(w, addr, port);
    return send_global_request("tcpip-forward", w.data(), true);
}

YANTERM_SSH_INLINE std::error_code connection::cancel_tcpip_forward(std::string_view addr, std::uint32_t port) {
    wire::writer w;
    channels::encode_tcpip_forward(w, addr, port);
    return send_global_request("cancel-tcpip-forward", w.data(), true);
}

YANTERM_SSH_INLINE std::error_code connection::request_streamlocal_forward(std::string_view socket_path) {
    wire::writer w;
    channels::encode_streamlocal_forward(w, socket_path);
    return send_global_request("streamlocal-forward@openssh.com", w.data(), true);
}

YANTERM_SSH_INLINE std::error_code connection::cancel_streamlocal_forward(std::string_view socket_path) {
    wire::writer w;
    channels::encode_streamlocal_forward(w, socket_path);
    return send_global_request("cancel-streamlocal-forward@openssh.com", w.data(), true);
}

YANTERM_SSH_INLINE std::error_code connection::send_ignore(std::span<const std::byte> data) {
    if (failure_) return failure_;
    if (!app_traffic_ok()) return code::invalid_state;
    wire::detail::ignore_msg msg;
    msg.data = data;
    wire::writer payload;
    msg.encode(payload);
    return write_packet(payload.data());
}

YANTERM_SSH_INLINE std::error_code connection::send_debug(bool always_display, std::string_view text) {
    if (failure_) return failure_;
    if (!app_traffic_ok()) return code::invalid_state;
    wire::detail::debug_msg msg;
    msg.always_display = always_display;
    msg.message = text;
    msg.language = {};
    wire::writer payload;
    msg.encode(payload);
    return write_packet(payload.data());
}

YANTERM_SSH_INLINE std::size_t connection::fragment_cursor::peek_size(std::size_t limit) const noexcept {
    std::size_t n = 0;
    std::size_t i = index;
    std::size_t off = offset;
    while (n < limit && i < frags.size()) {
        if (off >= frags[i].size()) {
            ++i;
            off = 0;
            continue;
        }
        const auto take = std::min(frags[i].size() - off, limit - n);
        n += take;
        off += take;
    }
    return n;
}

YANTERM_SSH_INLINE void connection::fragment_cursor::commit(std::size_t n) noexcept {
    consume(n, [](std::span<const std::byte>) {});
}

YANTERM_SSH_INLINE void connection::store_be32_at(std::span<std::byte> hdr, std::size_t off, std::uint32_t v) noexcept {
    detail::store_be32(hdr.subspan(off, 4), v);
}

YANTERM_SSH_INLINE std::error_code connection::write_channel_fragments(channel_ref ch, std::uint32_t ext_type,
                                        std::span<const std::span<const std::byte>> fragments,
                                        std::size_t& accepted) {
    fragment_cursor cur{fragments};
    const std::size_t header = (ext_type == 0) ? 9u : 13u;

    if (cur.peek_size(1) == 0) {
        detail::outbound_data_window win{};
        return channel_begin_write(ch, false, win);
    }

    for (;;) {
        if (cur.peek_size(1) == 0) return {};
        detail::outbound_data_window win{};
        if (auto ec = channel_begin_write(ch, true, win)) return ec;
        if (win.available == 0) return {};

        // max_pl is one full page of SSH payload, always far larger than the channel header.
        const auto max_pl = writer_.max_payload_size(pool_);
        const auto limit = std::min({static_cast<std::size_t>(win.available),
                                     static_cast<std::size_t>(win.max_packet),
                                     max_pl - header});
        const auto n = cur.peek_size(limit);
        if (n == 0) return {};

        std::array<std::byte, 13> hdr{};
        hdr[0] = static_cast<std::byte>(
            ext_type == 0 ? static_cast<std::uint8_t>(wire::msg::channel_data)
                          : static_cast<std::uint8_t>(wire::msg::channel_extended_data));
        store_be32_at(hdr, 1, win.remote);
        if (ext_type == 0) {
            store_be32_at(hdr, 5, static_cast<std::uint32_t>(n));
        } else {
            store_be32_at(hdr, 5, ext_type);
            store_be32_at(hdr, 9, static_cast<std::uint32_t>(n));
        }

        memory::detail::page_slice slice;
        if (auto ec = writer_.write_streamed(
                header + n, pool_, slice, [&](auto&& append) {
                    append(std::span<const std::byte>{hdr.data(), header});
                    cur.copy_prefix(n, [&](std::span<const std::byte> piece) { append(piece); });
                })) {
            fail(ec);
            phase_ = phase::dead;
            return ec;
        }
        if (auto ec = channel_commit_write(ch, static_cast<std::uint32_t>(n))) {
            fail(ec);
            phase_ = phase::dead;
            return ec;
        }
        cur.commit(n);
        commit_encrypted_packet(std::move(slice));
        accepted += n;
    }
}

YANTERM_SSH_INLINE std::error_code connection::on_channel_payload(memory::detail::page_slice& pkt) {
    const auto bytes = pkt.bytes();
    if (bytes.empty()) return code::invalid_format;
    const auto id = static_cast<wire::msg>(std::to_integer<std::uint8_t>(bytes[0]));
    switch (id) {
    case wire::msg::channel_open:
        return on_channel_open(bytes);
    case wire::msg::channel_open_confirmation:
        return on_channel_confirmation(bytes);
    case wire::msg::channel_open_failure:
        return on_channel_failure(bytes);
    case wire::msg::channel_window_adjust:
        return on_channel_window_adjust(bytes);
    case wire::msg::channel_data:
        return on_channel_data(pkt, bytes, /*ext=*/false);
    case wire::msg::channel_extended_data:
        return on_channel_data(pkt, bytes, /*ext=*/true);
    case wire::msg::channel_eof:
        return on_channel_eof(bytes);
    case wire::msg::channel_close:
        return on_channel_close(bytes);
    case wire::msg::channel_request:
        return on_channel_request(bytes);
    case wire::msg::channel_success:
        return on_channel_reply(bytes, true);
    case wire::msg::channel_failure:
        return on_channel_reply(bytes, false);
    case wire::msg::global_request:
        return on_global_request(bytes);
    case wire::msg::request_success:
        return on_global_reply(bytes, true);
    case wire::msg::request_failure:
        return on_global_reply(bytes, false);
    default:
        return code::unexpected_message;
    }
}

YANTERM_SSH_INLINE void connection::release_channel(channel_ref ref) {
    auto* c = slots_.find(ref);
    if (!c) return;
    void* user = c->user_data;
    const auto local = c->local;
    c = nullptr;
    slots_.erase(local);
    notify([&](handler& h, connection& conn) { h.on_released(conn, ref, user); });
}

YANTERM_SSH_INLINE void connection::notify_readable(const detail::channel& c, std::uint32_t ext_type) {
    const auto ref = detail::ref_of(c);
    void* user = c.user_data;
    notify([&](handler& app, connection& conn) { app.on_readable(conn, ref, user, ext_type); });
}

YANTERM_SSH_INLINE detail::channel* connection::find_open_channel(channels::channel_id local) noexcept {
    auto* c = slots_.find(local);
    if (!c || !c->remote_known || c->inbound_open) return nullptr;
    return c;
}

YANTERM_SSH_INLINE void connection::resume_writes() {
    writes_paused_ = false;
    // Index walk: on_writable may recycle slots, so the next id is looked up again.
    for (std::size_t i = 0; i < slots_.size(); ++i) {
        detail::channel* c = slots_.find(static_cast<channels::channel_id>(i));
        if (!c || !c->want_writable) continue;
        if (!can_send_data(*c)) {
            c->want_writable = false;
            continue;
        }
        if (c->remote_window == 0) continue;
        c->want_writable = false;
        const auto ref = detail::ref_of(*c);
        void* user = c->user_data;
        c = nullptr;
        notify([&](handler& app, connection& conn) { app.on_writable(conn, ref, user); });
    }
}

YANTERM_SSH_INLINE bool connection::can_send_data(const detail::channel& c) noexcept {
    return c.remote_known && !c.sent_eof && !c.sent_close && !c.recv_close;
}

YANTERM_SSH_INLINE std::error_code connection::channel_begin_write(channel_ref ref, bool has_data,
                                                                   detail::outbound_data_window& out) {
    auto* c = slots_.find(ref);
    if (!c || !can_send_data(*c)) return code::invalid_state;
    out.remote = c->remote;
    out.max_packet = c->remote_max_packet;
    out.available = writes_paused_ ? 0u : c->remote_window;
    if (has_data && out.available == 0) c->want_writable = true;
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::channel_commit_write(channel_ref ref, std::uint32_t bytes) {
    auto* c = slots_.find(ref);
    if (!c || !can_send_data(*c)) return code::invalid_state;
    if (bytes == 0) return {};
    if (writes_paused_) return code::invalid_state;
    if (bytes > c->remote_window) return code::invalid_state;
    c->remote_window -= bytes;
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::on_channel_open(std::span<const std::byte> bytes) {
    wire::reader r{bytes};
    wire::detail::channel_open msg;
    if (!msg.decode(r)) return code::invalid_format;
    detail::channel* c = nullptr;
    if (auto ec = slots_.allocate(cfg_.initial_window, cfg_.max_channel_packet, c)) {
        wire::detail::channel_open_failure fail_msg;
        fail_msg.recipient = msg.sender;
        fail_msg.reason = static_cast<std::uint32_t>(channels::channel_open_reason::resource_shortage);
        fail_msg.description = {};
        fail_msg.language = {};
        if (auto wec = write_encoded(fail_msg)) return wec;
        return {};
    }
    c->inbound_open = true;
    c->remote = msg.sender;
    c->remote_known = true;
    c->remote_window = msg.window;
    c->remote_max_packet = detail::clamp_remote_max_packet(msg.max_packet);
    const auto ref = detail::ref_of(*c);
    const auto ticket = open_ticket{ref};
    const auto view = detail::make_open_view(msg);
    notify([&](handler& h, connection& conn) { h.on_open_request(conn, ticket, view); });
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::on_channel_confirmation(std::span<const std::byte> bytes) {
    wire::reader r{bytes};
    wire::detail::channel_open_confirmation msg;
    if (!msg.decode(r)) return code::invalid_format;
    auto* c = slots_.find(msg.recipient);
    if (!c || c->remote_known || c->inbound_open) return code::unexpected_message;
    c->remote = msg.sender;
    c->remote_known = true;
    c->remote_window = msg.window;
    c->remote_max_packet = detail::clamp_remote_max_packet(msg.max_packet);
    const auto ref = detail::ref_of(*c);
    void* user = c->user_data;
    if (c->abandoned) {
        wire::detail::channel_close_msg cl;
        cl.recipient = c->remote;
        if (auto ec = write_encoded(cl)) return ec;
        c->note_sent_close();
        c->app_close = true;
        return {};
    }
    channels::open_result_view result{};
    result.success = true;
    result.window = c->remote_window;
    result.max_packet = c->remote_max_packet;
    notify([&](handler& h, connection& conn) { h.on_open_result(conn, ref, user, result); });
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::on_channel_failure(std::span<const std::byte> bytes) {
    wire::reader r{bytes};
    wire::detail::channel_open_failure msg;
    if (!msg.decode(r)) return code::invalid_format;
    auto* c = slots_.find(msg.recipient);
    if (!c || c->remote_known || c->inbound_open) return code::unexpected_message;
    const auto ref = detail::ref_of(*c);
    void* user = c->user_data;
    const bool abandoned = c->abandoned;
    if (!abandoned) {
        channels::open_result_view result{};
        result.success = false;
        result.reason = static_cast<channels::channel_open_reason>(msg.reason);
        result.description = msg.description;
        notify([&](handler& h, connection& conn) { h.on_open_result(conn, ref, user, result); });
    }
    release_channel(ref);
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::on_channel_window_adjust(std::span<const std::byte> bytes) {
    wire::reader r{bytes};
    wire::detail::channel_window_adjust msg;
    if (!msg.decode(r)) return code::invalid_format;
    auto* c = find_open_channel(msg.recipient);
    if (!c) return code::unexpected_message;
    if (c->remote_window + msg.bytes < c->remote_window) return code::channel_window_exceeded;
    c->remote_window += msg.bytes;
    if (!writes_paused_ && c->want_writable && c->remote_window > 0 && can_send_data(*c)) {
        c->want_writable = false;
        const auto ref = detail::ref_of(*c);
        void* user = c->user_data;
        c = nullptr;
        notify([&](handler& h, connection& conn) { h.on_writable(conn, ref, user); });
    }
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::on_channel_data(memory::detail::page_slice& pkt,
                                                               std::span<const std::byte> bytes, bool ext) {
    std::uint32_t recipient = 0;
    std::uint32_t ext_type = 0;
    std::span<const std::byte> data;
    if (!ext) {
        wire::reader r{bytes};
        wire::detail::channel_data msg;
        if (!msg.decode(r)) return code::invalid_format;
        recipient = msg.recipient;
        data = msg.data;
    } else {
        wire::reader r{bytes};
        wire::detail::channel_extended_data msg;
        if (!msg.decode(r)) return code::invalid_format;
        recipient = msg.recipient;
        ext_type = msg.data_type;
        data = msg.data;
    }
    auto* c = find_open_channel(recipient);
    if (!c) return code::unexpected_message;
    if (c->recv_eof || c->recv_close) return code::unexpected_message;
    if (data.size() > c->local_window) return code::channel_window_exceeded;
    if (data.size() > c->local_max_packet) return code::unexpected_message;
    const auto n = static_cast<std::uint32_t>(data.size());
    c->local_window -= n;
    if (ext && ext_type != channels::extended_data_stderr) {
        c->local_window += n;
        wire::detail::channel_window_adjust adj;
        adj.recipient = c->remote;
        adj.bytes = n;
        if (auto ec = write_encoded(adj)) return ec;
        return {};
    }
    const auto off = static_cast<std::size_t>(data.data() - bytes.data());
    auto slice = pkt.subslice(off, data.size());
    const bool was_empty = (ext_type == 0 && !ext) ? c->rx_data.empty() : c->rx_ext.empty();
    if (ext_type == 0 && !ext) {
        c->rx_data.push_back(std::move(slice));
    } else {
        c->rx_ext.push_back(std::move(slice));
    }
    if (was_empty) notify_readable(*c, ext ? ext_type : 0);
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::on_channel_eof(std::span<const std::byte> bytes) {
    wire::reader r{bytes};
    wire::detail::channel_eof_msg msg;
    if (!msg.decode(r)) return code::invalid_format;
    auto* c = find_open_channel(msg.recipient);
    if (!c) return code::unexpected_message;
    if (c->recv_eof) return code::unexpected_message;
    c->recv_eof = true;
    const auto ref = detail::ref_of(*c);
    void* user = c->user_data;
    notify([&](handler& h, connection& conn) { h.on_eof(conn, ref, user); });
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::on_channel_close(std::span<const std::byte> bytes) {
    wire::reader r{bytes};
    wire::detail::channel_close_msg msg;
    if (!msg.decode(r)) return code::invalid_format;
    auto* c = find_open_channel(msg.recipient);
    if (!c) return code::unexpected_message;
    if (c->recv_close) return code::unexpected_message;
    c->recv_close = true;
    const auto ref = detail::ref_of(*c);
    void* user = c->user_data;
    if (!c->sent_close) {
        if (c->remote_known) {
            wire::detail::channel_close_msg cl;
            cl.recipient = c->remote;
            if (auto ec = write_encoded(cl)) return ec;
        }
        c->note_sent_close();
    }
    notify([&](handler& h, connection& conn) { h.on_closed(conn, ref, user); });
    if (auto* again = slots_.find(ref); again && again->releasable()) release_channel(ref);
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::on_channel_request(std::span<const std::byte> bytes) {
    wire::reader r{bytes};
    wire::detail::channel_request msg;
    if (!msg.decode(r)) return code::invalid_format;
    auto* c = find_open_channel(msg.recipient);
    if (!c) return code::unexpected_message;
    std::uint64_t seq = 0;
    if (msg.want_reply) {
        if (c->inbound.next_seq == std::numeric_limits<std::uint64_t>::max()) return code::invalid_state;
        seq = c->inbound.next_seq++;
    }
    const auto ref = detail::ref_of(*c);
    const auto ticket = channel_request_ticket{ref, seq};
    const void* user = c->user_data;
    channels::request_view view{msg.type, msg.extra, msg.want_reply};
    notify([&](handler& h, connection& conn) {
        h.on_channel_request(conn, ticket, const_cast<void*>(user), view);
    });
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::on_channel_reply(std::span<const std::byte> bytes, bool success) {
    std::uint32_t recipient = 0;
    if (success) {
        wire::reader r{bytes};
        wire::detail::channel_success_msg msg;
        if (!msg.decode(r)) return code::invalid_format;
        recipient = msg.recipient;
    } else {
        wire::reader r{bytes};
        wire::detail::channel_failure_msg msg;
        if (!msg.decode(r)) return code::invalid_format;
        recipient = msg.recipient;
    }
    auto* c = find_open_channel(recipient);
    if (!c) return code::unexpected_message;
    if (c->outbound_outstanding == 0) return code::unexpected_message;
    --c->outbound_outstanding;
    const auto ref = detail::ref_of(*c);
    void* user = c->user_data;
    notify([&](handler& h, connection& conn) { h.on_channel_reply(conn, ref, user, success); });
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::on_global_request(std::span<const std::byte> bytes) {
    wire::reader r{bytes};
    wire::detail::global_request msg;
    if (!msg.decode(r)) return code::invalid_format;
    std::uint64_t seq = 0;
    if (msg.want_reply) {
        if (global_inbound_.next_seq == std::numeric_limits<std::uint64_t>::max()) return code::invalid_state;
        seq = global_inbound_.next_seq++;
    }
    const auto ticket = global_request_ticket{seq};
    channels::request_view view{msg.type, msg.extra, msg.want_reply};
    notify([&](handler& h, connection& conn) { h.on_global_request(conn, ticket, view); });
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::on_global_reply(std::span<const std::byte> bytes, bool success) {
    std::span<const std::byte> extra;
    if (success) {
        wire::reader r{bytes};
        wire::detail::request_success msg;
        if (!msg.decode(r)) return code::invalid_format;
        extra = msg.extra;
    } else {
        wire::reader r{bytes};
        wire::detail::request_failure msg;
        if (!msg.decode(r)) return code::invalid_format;
    }
    if (global_outstanding_ == 0) return code::unexpected_message;
    --global_outstanding_;
    notify([&](handler& h, connection& conn) { h.on_global_reply(conn, success, extra); });
    return {};
}

}  // namespace yanterm::ssh::core
