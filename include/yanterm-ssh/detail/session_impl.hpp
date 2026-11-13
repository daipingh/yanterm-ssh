#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/core/config.hpp>
#include <yanterm-ssh/core/connection.hpp>
#include <yanterm-ssh/core/types.hpp>
#include <yanterm-ssh/core/detail/detail_format.hpp>
#include <yanterm-ssh/detail/error.hpp>
#include <yanterm-ssh/detail/intrusive_list.hpp>
#include <yanterm-ssh/crypto/secure_buffer.hpp>
#include <yanterm-ssh/facade_types.hpp>
#include <yanterm-ssh/options.hpp>

#include <auv/error.hpp>
#include <auv/stream.hpp>
#include <corral/Event.h>
#include <corral/Nursery.h>
#include <corral/ParkingLot.h>
#include <corral/Task.h>
#include <corral/utility.h>
#include <corral/wait.h>

#include <array>
#include <cassert>
#include <concepts>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace yanterm::ssh {

namespace detail {

template <class P>
concept wire_payload =
    std::convertible_to<P, std::span<const std::byte>> || std::invocable<P&, wire::writer&>;

// Synchronous: a wire::writer used by an encoder stays in this frame and is
// destroyed before the caller reaches a coroutine suspend point.
template <wire_payload Payload, class Submit>
std::error_code submit_payload(Payload& payload, Submit&& submit) {
    if constexpr (std::convertible_to<Payload, std::span<const std::byte>>) {
        return submit(std::span<const std::byte>{payload});
    } else {
        wire::writer w;
        payload(w);
        return submit(w.data());
    }
}

}  // namespace detail

struct session_impl : core::handler {
    session_impl(core::role r, auv::stream stream, crypto::provider provider,
                 session_options o, std::pmr::memory_resource* mr,
                 std::string auth_banner = {},
                 std::string auth_banner_language = {},
                 std::string accepted_publickey_algorithms = {},
                 std::function<void(std::string_view, std::string_view)> on_banner = {});

    void latch(std::error_code ec, std::string detail = {});
    // Copies core_.failure() into the facade. Call immediately after any core
    // operation that may have failed, before unparking waiters.
    void note_core_failure() {
        if (latch_ || !core_.failure()) return;
        latch(core_.failure(), std::string(core_.failure_detail()));
    }
    // One waiter list for both pumps: output was queued, or a stalled read may proceed.
    void wake_pumps() noexcept { pump_lot_.unparkAll(); }
    
    [[nodiscard]] bool closed() const noexcept { return bool(latch_); }
    [[nodiscard]] bool inbound_queue_full() const noexcept;
    // Sends DISCONNECT and latches session_closed unless already latched.
    void close_locally(disconnect_reason reason, std::string_view description);
    // serve()'s result: a by_application close from either side is not an error.
    [[nodiscard]] std::error_code close_status() const noexcept;
    auth_result take_auth_response();

    static constexpr std::size_t output_batch = 8;
    std::size_t next_output(std::array<auv::buffer, output_batch>& bufs, std::size_t& bytes) const;
    bool feed_buffered(std::size_t& accepted);
    bool input_read(std::error_code ec, std::size_t n);
    // Runs steps beside the read pump and a write pump. The read pump never
    // finishes on its own, so a closed session does not cancel steps; steps
    // finishing cancels the read pump, then the write pump drains and exits.
    // The write pump is started first, so steps always observe writing_.
    // steps() must return a non-void awaitable; that value is the phase result.
    // Not a coroutine: the stop flag lives in the awaitable chain.
    template <class Steps>
    auto run_phase(Steps&& steps);
    corral::Task<void> read_pump();
    // `stop` becomes true once steps have returned. Empty output then ends the pump.
    corral::Task<void> write_pump(const bool& stop);
    corral::Task<std::tuple<std::error_code, auth_result>> wait_auth_response();
    void release_auth_stage() noexcept;
    void on_peer_identification(core::connection&, std::string_view) override {}
    void on_host_key(core::connection&, core::host_key_ticket,
                     std::span<const std::byte>) override;
    void on_handshake_done(core::connection&) override;
    void on_rekey_done(core::connection&) override;
    void on_debug(core::connection&, bool, std::string_view, std::string_view) override;
    void on_ignore(core::connection&, std::span<const std::byte>) override {}
    void on_disconnect(core::connection&, wire::disconnect_reason, std::string_view,
                       std::string_view) override;
    void on_auth_banner(core::connection&, std::string_view text,
                        std::string_view language) override;
    void on_auth_result(core::connection&, const auth::auth_result& result) override;
    void on_kbdint_request(core::connection&, core::kbdint_ticket ticket,
                           const auth::info_request_view& request) override;
    void on_auth_request(core::connection&, core::auth_ticket ticket,
                         const auth::auth_request_view& request) override;
    void on_kbdint_response(core::connection&, core::auth_ticket ticket,
                            std::span<const std::string_view> responses) override;
    void on_open_request(core::connection&, core::open_ticket ticket,
                         const channels::open_request_view& request) override;
    void on_open_result(core::connection&, core::channel_ref ref, void* user,
                        const channels::open_result_view& result) override;
    void on_channel_request(core::connection&, core::channel_request_ticket ticket, void* user,
                            const channels::request_view& request) override;
    void on_channel_reply(core::connection&, core::channel_ref ref, void* user, bool success) override;
    void on_global_request(core::connection&, core::global_request_ticket ticket,
                           const channels::request_view& request) override;
    void on_global_reply(core::connection&, bool success, std::span<const std::byte> payload) override;
    void on_readable(core::connection&, core::channel_ref ref, void* user, std::uint32_t ext_type) override;
    void on_writable(core::connection&, core::channel_ref ref, void* user) override;
    void on_eof(core::connection&, core::channel_ref ref, void* user) override;
    void on_closed(core::connection&, core::channel_ref ref, void* user) override;
    void on_released(core::connection&, core::channel_ref ref, void* user) override;

    std::string software_;
    std::string preferred_kex_;
    std::string preferred_host_key_;
    std::string preferred_cipher_;
    std::string preferred_mac_;
    std::size_t max_output_bytes_ = 256u * 1024u;
    std::pmr::memory_resource* mr_ = nullptr;
    crypto::provider provider_{};
    auv::stream stream_;
    core::connection core_;

    // Unread bytes survive between self-driven steps and into serve()'s pumps.
    // The page is held only while such bytes remain.
    struct recv_buffer {
        static constexpr std::size_t capacity = memory::default_page_size;
        std::byte* data = nullptr;
        std::size_t off = 0;
        std::size_t end = 0;

        [[nodiscard]] bool empty() const noexcept { return off == end; }
        void release(std::pmr::memory_resource* mr) noexcept;
        void compact(std::pmr::memory_resource* mr) noexcept;
        auv::buffer space(std::pmr::memory_resource* mr);
    };
    static_assert(recv_buffer::capacity > 4 + core::detail::max_packet_length + 64,
                  "the receive buffer must hold one whole SSH binary packet");
    recv_buffer in_;

    bool serving_ = false;
    bool reading_ = false;
    bool writing_ = false;
    // Peer DISCONNECT or a failed transport write: nothing further may be sent.
    bool output_closed_ = false;
    bool local_close_ = false;
    std::uint32_t max_pending_requests_ = default_max_pending_requests;
    std::error_code latch_{};
    std::string latch_detail_;
    disconnect_info disc_{};
    bool have_disc_ = false;
    // Core delivered something the current phase's steps are waiting for.
    corral::ParkingLot inbound_lot_;
    // Output was queued, or a read blocked on a stall may continue.
    corral::ParkingLot pump_lot_;
    // A write finished or the write pump exited. Channel backpressure and disconnect wait here.
    corral::ParkingLot written_lot_;
    corral::ParkingLot rekey_lot_;
    std::uint64_t rekey_gen_ = 0;
    corral::Event closed_ev_;
    std::function<void(bool always_display, std::string_view text, std::string_view language)>
        on_debug_;
    bool hs_done_ = false;
    struct reply_waiter : detail::intrusive_list_item<reply_waiter> {
        std::uint64_t seq = 0;
        bool done = false;
        bool success = false;
        bool from_reply = false;
        std::vector<std::byte> payload;
        corral::Event ready;
    };

    struct pending_host_verify {
        core::host_key_ticket ticket{};
        keys::public_key key;
    };
    struct pending_auth_response {
        auth_result result{};
    };
    struct pending_auth_request {
        core::auth_ticket ticket{};
        std::string user;
        std::string service;
        std::string method;
        bool has_signature = false;
        std::string algorithm;
        std::vector<std::byte> public_blob;
        crypto::secure_string password;
    };
    struct pending_info_request {
        core::kbdint_ticket ticket{};
        std::string name;
        std::string instruction;
        std::vector<kbdint_prompt> prompts;
    };
    struct pending_info_response {
        std::vector<crypto::secure_string> responses;
    };
    struct auth_stage {
        std::optional<pending_host_verify> pending_verify;
        std::optional<pending_auth_response> pending_auth_resp;
        std::optional<pending_auth_request> pending_auth_req;
        std::optional<pending_info_request> pending_info_req;
        std::optional<pending_info_response> pending_info_resp;
        std::string last_auth_methods;
        std::function<void(std::string_view, std::string_view)> on_banner;
        bool client_auth_outstanding = false;
        bool auth_callback_live = false;
        bool challenge_outstanding = false;
    };
    std::unique_ptr<auth_stage> auth_;

    struct pending_inbound_request {
        core::channel_request_ticket ticket{};
        std::string type;
        std::vector<std::byte> payload;
        bool want_reply = false;
    };

    struct open_outcome {
        bool failed = false;
        channel_open_reason reason{};
        std::string description;
    };

    struct channel_state : detail::intrusive_list_item<channel_state> {
        std::uint32_t refs = 0;
        core::channel_ref ref{};
        corral::ParkingLot rd_lot;
        corral::ParkingLot ext_lot;
        corral::ParkingLot wr_lot;
        corral::ParkingLot req_lot;
        corral::ParkingLot open_lot;
        bool recv_eof = false;
        bool recv_close = false;
        bool serving_requests = false;
        std::optional<open_outcome> open;
        std::vector<pending_inbound_request> pending_reqs;
        detail::intrusive_list<reply_waiter> reply_waiters;
        std::uint64_t next_send_seq = 1;
        std::uint64_t next_reply_seq = 1;
    };

    detail::intrusive_list<channel_state> live_channels_;

    struct pending_inbound_open {
        core::open_ticket ticket{};
        core::channel_ref ref{};
        channel_id ch{};
        channel_type type = channel_type::unknown;
        std::string request_type;
        std::string host;
        std::uint32_t port = 0;
        std::string originator_host;
        std::uint32_t originator_port = 0;
        std::string socket_path;
        std::vector<std::byte> extra;
    };
    std::vector<pending_inbound_open> pending_opens_;

    struct pending_inbound_global {
        core::global_request_ticket ticket{};
        std::string type;
        std::vector<std::byte> payload;
        bool want_reply = false;
    };
    std::vector<pending_inbound_global> pending_globals_;
    detail::intrusive_list<reply_waiter> global_waiters_;
    std::uint64_t next_global_send_seq_ = 1;
    std::uint64_t next_global_reply_seq_ = 1;

    void release(channel_state* st) noexcept;
    void complete_channel_reply(channel_state& st, bool success);
    void complete_global_reply(bool success, std::span<const std::byte> payload);
    void fail_reply_waiters(channel_state& st);
    void wake_reply_waiters();
    void unpark_live_channels();
    void reject_pending_inbound();
    std::optional<pending_inbound_open> take_pending_open();
    std::optional<pending_inbound_global> take_pending_global();

    ~session_impl();
};

inline session_impl::session_impl(
    core::role r, auv::stream stream, crypto::provider provider, session_options o,
    std::pmr::memory_resource* mr, std::string auth_banner, std::string auth_banner_language,
    std::string accepted_publickey_algorithms,
    std::function<void(std::string_view, std::string_view)> on_banner)
    : software_(std::move(o.software))
    , preferred_kex_(std::move(o.preferred_kex))
    , preferred_host_key_(std::move(o.preferred_host_key))
    , preferred_cipher_(std::move(o.preferred_cipher))
    , preferred_mac_(std::move(o.preferred_mac))
    , max_output_bytes_(o.max_output_bytes)
    , mr_(mr != nullptr ? mr : memory::default_page_resource())
    , provider_(provider)
    , stream_(std::move(stream))
    , core_(r, provider,
            [&] {
                core::config cfg;
                cfg.software = software_;
                cfg.rekey_bytes = o.rekey_bytes;
                cfg.rekey_packets = o.rekey_packets;
                cfg.preferred_kex = preferred_kex_;
                cfg.preferred_host_key = preferred_host_key_;
                cfg.preferred_cipher = preferred_cipher_;
                cfg.preferred_mac = preferred_mac_;
                cfg.advertise_ext_info = o.advertise_ext_info;
                cfg.advertise_strict_kex = o.advertise_strict_kex;
                cfg.initial_window = o.initial_window;
                cfg.max_channel_packet = o.max_channel_packet;
                cfg.max_channels = o.max_channels;
                cfg.auth_banner = auth_banner;
                cfg.auth_banner_language = auth_banner_language;
                cfg.accepted_publickey_algorithms = accepted_publickey_algorithms;
                return cfg;
            }(),
            *this, mr_)
    , max_pending_requests_(o.max_pending_requests == 0 ? default_max_pending_requests
                                                        : o.max_pending_requests)
    , on_debug_(std::move(o.on_debug)) {
    auth_ = std::make_unique<auth_stage>();
    auth_->on_banner = std::move(on_banner);
}

inline session_impl::~session_impl() {
    in_.release(mr_);
    for (auto it = live_channels_.begin(); it != live_channels_.end();) {
        channel_state& st = *it;
        assert(st.refs == 1);
        it = live_channels_.erase(it);
        release(&st);
    }
}

inline void session_impl::release(channel_state* st) noexcept {
    if (st == nullptr) return;
    if (--st->refs > 0) return;
    live_channels_.erase(*st);
    delete st;
}

inline bool session_impl::inbound_queue_full() const noexcept {
    if (pending_globals_.size() >= max_pending_requests_) return true;
    bool full = false;
    for (const channel_state& st : live_channels_) {
        if (st.pending_reqs.size() >= max_pending_requests_) full = true;
    }
    return full;
}

inline void session_impl::on_host_key(core::connection&, core::host_key_ticket ticket,
                                      std::span<const std::byte> blob) {
    if (!auth_) return;
    pending_host_verify pending;
    pending.ticket = ticket;
    if (keys::public_key::parse_blob(blob, pending.key)) {
        latch(code::invalid_host_key);
        return;
    }
    auth_->pending_verify = std::move(pending);
    inbound_lot_.unparkAll();
}

inline void session_impl::on_handshake_done(core::connection&) {
    hs_done_ = true;
    inbound_lot_.unparkAll();
}

inline void session_impl::on_rekey_done(core::connection&) {
    ++rekey_gen_;
    rekey_lot_.unparkAll();
}

inline void session_impl::on_debug(core::connection&, bool always_display,
                                   std::string_view text, std::string_view language) {
    if (on_debug_) on_debug_(always_display, text, language);
}

inline void session_impl::on_disconnect(core::connection&, wire::disconnect_reason reason,
                                        std::string_view description,
                                        std::string_view language) {
    disc_.reason = reason;
    disc_.description.assign(description.begin(), description.end());
    disc_.language.assign(language.begin(), language.end());
    have_disc_ = true;
    // RFC 4253 §11.1: nothing may be sent after receiving DISCONNECT.
    output_closed_ = true;
    latch(code::peer_disconnected);
}

inline void session_impl::on_auth_banner(core::connection&, std::string_view text,
                                         std::string_view language) {
    if (!auth_) return;
    if (auth_->on_banner) auth_->on_banner(text, language);
}

inline void session_impl::on_auth_result(core::connection&, const auth::auth_result& result) {
    if (!auth_) return;
    auth_->last_auth_methods.assign(result.methods.begin(), result.methods.end());
    auth_->pending_auth_resp = pending_auth_response{result};
    auth_->pending_auth_resp->result.methods = auth_->last_auth_methods;
    inbound_lot_.unparkAll();
}

inline void session_impl::on_kbdint_request(core::connection&, core::kbdint_ticket ticket,
                                            const auth::info_request_view& request) {
    if (!auth_) return;
    pending_info_request info;
    info.ticket = ticket;
    info.name.assign(request.name.begin(), request.name.end());
    info.instruction.assign(request.instruction.begin(), request.instruction.end());
    info.prompts.assign(request.prompts.begin(), request.prompts.end());
    auth_->pending_info_req = std::move(info);
    inbound_lot_.unparkAll();
}

inline void session_impl::on_auth_request(core::connection&, core::auth_ticket ticket,
                                          const auth::auth_request_view& request) {
    if (!auth_) return;
    pending_auth_request req;
    req.ticket = ticket;
    req.user.assign(request.user.begin(), request.user.end());
    req.service.assign(request.service.begin(), request.service.end());
    req.method.assign(request.method.begin(), request.method.end());
    req.has_signature = request.has_signature;
    req.algorithm.assign(request.algorithm.begin(), request.algorithm.end());
    req.public_blob.assign(request.public_blob.begin(), request.public_blob.end());
    req.password.assign(request.password);
    auth_->pending_auth_req = std::move(req);
    inbound_lot_.unparkAll();
}

inline void session_impl::on_kbdint_response(core::connection&, core::auth_ticket,
                                             std::span<const std::string_view> responses) {
    if (!auth_) return;
    pending_info_response resp;
    resp.responses.reserve(responses.size());
    for (const std::string_view response : responses) {
        crypto::secure_string answer;
        answer.assign(response);
        resp.responses.push_back(std::move(answer));
    }
    auth_->pending_info_resp = std::move(resp);
    inbound_lot_.unparkAll();
}

// Before serve() nothing stalls reading for a full queue, so requests past the
// bound are rejected instead.
inline void session_impl::on_open_request(core::connection& c, core::open_ticket ticket,
                                          const channels::open_request_view& request) {
    if (!serving_ && pending_opens_.size() >= max_pending_requests_) {
        (void)c.resolve(ticket, channels::channel_open_verdict::rejected(
                                  channels::channel_open_reason::resource_shortage,
                                  "too many pending requests"));
        wake_pumps();
        return;
    }
    const auto ref = core::connection::channel_ref_of(ticket);
    pending_inbound_open o;
    o.ticket = ticket;
    o.ref = ref;
    o.ch = ref.index;
    o.type = request.type;
    o.request_type.assign(request.type_name.begin(), request.type_name.end());
    o.host.assign(request.host.begin(), request.host.end());
    o.port = request.port;
    o.originator_host.assign(request.originator_host.begin(), request.originator_host.end());
    o.originator_port = request.originator_port;
    o.socket_path.assign(request.socket_path.begin(), request.socket_path.end());
    o.extra.assign(request.extra.begin(), request.extra.end());
    pending_opens_.push_back(std::move(o));
    inbound_lot_.unparkAll();
}

inline void session_impl::on_open_result(core::connection&, core::channel_ref, void* user,
                                         const channels::open_result_view& result) {
    auto* st = static_cast<channel_state*>(user);
    if (st == nullptr) return;
    open_outcome o;
    if (!result.success) {
        o.failed = true;
        o.reason = result.reason;
        o.description.assign(result.description.begin(), result.description.end());
    }
    st->open = std::move(o);
    st->open_lot.unparkAll();
}

inline void session_impl::on_channel_request(core::connection& c, core::channel_request_ticket ticket,
                                             void* user, const channels::request_view& request) {
    auto* st = static_cast<channel_state*>(user);
    if (st != nullptr && st->serving_requests) {
        pending_inbound_request r;
        r.ticket = ticket;
        r.type.assign(request.type.begin(), request.type.end());
        r.payload.assign(request.payload.begin(), request.payload.end());
        r.want_reply = request.want_reply;
        st->pending_reqs.push_back(std::move(r));
        st->req_lot.unparkAll();
        return;
    }
    (void)c.resolve(ticket, false);
    wake_pumps();
}

inline void session_impl::on_channel_reply(core::connection&, core::channel_ref, void* user,
                                           bool success) {
    if (auto* st = static_cast<channel_state*>(user)) complete_channel_reply(*st, success);
}

inline void session_impl::on_global_request(core::connection& c, core::global_request_ticket ticket,
                                            const channels::request_view& request) {
    if (!serving_ && pending_globals_.size() >= max_pending_requests_) {
        (void)c.resolve(ticket, false);
        wake_pumps();
        return;
    }
    pending_inbound_global g;
    g.ticket = ticket;
    g.type.assign(request.type.begin(), request.type.end());
    g.payload.assign(request.payload.begin(), request.payload.end());
    g.want_reply = request.want_reply;
    pending_globals_.push_back(std::move(g));
    inbound_lot_.unparkAll();
}

inline void session_impl::on_global_reply(core::connection&, bool success,
                                          std::span<const std::byte> payload) {
    complete_global_reply(success, payload);
}

inline void session_impl::on_readable(core::connection&, core::channel_ref, void* user,
                                      std::uint32_t ext_type) {
    auto* st = static_cast<channel_state*>(user);
    if (st == nullptr) return;
    if (ext_type == 0) st->rd_lot.unparkAll();
    else st->ext_lot.unparkAll();
}

inline void session_impl::on_writable(core::connection&, core::channel_ref, void* user) {
    if (auto* st = static_cast<channel_state*>(user)) st->wr_lot.unparkAll();
}

inline void session_impl::on_eof(core::connection&, core::channel_ref, void* user) {
    auto* st = static_cast<channel_state*>(user);
    if (st == nullptr) return;
    st->recv_eof = true;
    st->rd_lot.unparkAll();
    st->ext_lot.unparkAll();
}

inline void session_impl::on_closed(core::connection&, core::channel_ref, void* user) {
    auto* st = static_cast<channel_state*>(user);
    if (st == nullptr) return;
    st->recv_eof = true;
    st->recv_close = true;
    st->rd_lot.unparkAll();
    st->ext_lot.unparkAll();
    st->wr_lot.unparkAll();
    st->req_lot.unparkAll();
    fail_reply_waiters(*st);
}

inline void session_impl::on_released(core::connection&, core::channel_ref, void* user) {
    if (user != nullptr) release(static_cast<channel_state*>(user));
    wake_pumps();
}

inline void session_impl::latch(std::error_code ec, std::string detail) {
    if (!latch_) {
        latch_ = ec;
        latch_detail_ = std::move(detail);
    }
    wake_reply_waiters();
    inbound_lot_.unparkAll();
    wake_pumps();
    written_lot_.unparkAll();
    rekey_lot_.unparkAll();
    unpark_live_channels();
    reject_pending_inbound();
    // until_closed() runs only after all library-side cleanup above is done.
    closed_ev_.trigger();
}

inline void session_impl::complete_channel_reply(channel_state& st, bool success) {
    const auto seq = st.next_reply_seq++;
    if (st.reply_waiters.empty()) return;
    auto& head = st.reply_waiters.front();
    if (head.seq == seq) {
        head.success = success;
        head.from_reply = true;
        head.done = true;
        // trigger() resumes inline and destroys the waiter before returning.
        st.reply_waiters.pop_front();
        head.ready.trigger();
        return;
    }
    assert(head.seq > seq);
}

inline void session_impl::complete_global_reply(bool success, std::span<const std::byte> payload) {
    const auto seq = next_global_reply_seq_++;
    if (global_waiters_.empty()) return;
    auto& head = global_waiters_.front();
    if (head.seq == seq) {
        head.success = success;
        head.from_reply = true;
        head.done = true;
        if (success) head.payload.assign(payload.begin(), payload.end());
        // trigger() resumes inline and destroys the waiter before returning.
        global_waiters_.pop_front();
        head.ready.trigger();
        return;
    }
    assert(head.seq > seq);
}

inline void session_impl::fail_reply_waiters(channel_state& st) {
    while (!st.reply_waiters.empty()) {
        auto& w = st.reply_waiters.front();
        w.done = true;
        w.success = false;
        w.from_reply = false;
        // trigger() resumes inline and destroys the waiter before returning.
        st.reply_waiters.pop_front();
        w.ready.trigger();
    }
}

inline void session_impl::wake_reply_waiters() {
    for (auto it = live_channels_.begin(); it != live_channels_.end();) {
        channel_state& st = *it++;
        while (!st.reply_waiters.empty()) {
            auto& w = st.reply_waiters.front();
            // trigger() resumes inline. latch_ makes the waiter return
            // session_closed, and that caller may destroy the next waiter.
            st.reply_waiters.pop_front();
            w.ready.trigger();
        }
    }
    while (!global_waiters_.empty()) {
        auto& w = global_waiters_.front();
        global_waiters_.pop_front();
        w.ready.trigger();
    }
}

inline void session_impl::unpark_live_channels() {
    for (auto it = live_channels_.begin(); it != live_channels_.end();) {
        channel_state& st = *it++;
        st.rd_lot.unparkAll();
        st.ext_lot.unparkAll();
        st.wr_lot.unparkAll();
        st.req_lot.unparkAll();
        st.open_lot.unparkAll();
    }
}

inline void session_impl::reject_pending_inbound() {
    while (auto o = take_pending_open()) {
        (void)core_.resolve(o->ticket, channels::channel_open_verdict::rejected(
                                 channels::channel_open_reason::administratively_prohibited,
                                 "serve not installed"));
    }
    while (auto g = take_pending_global()) {
        (void)core_.resolve(g->ticket, false);
    }
    // A channel ticket still ahead of the in-flight head cannot be settled.
    // Leave it at the front so the serve_requests guard can reject the head
    // first, then this one. Nothing retries the queue once serve() returns.
    for (auto it = live_channels_.begin(); it != live_channels_.end();) {
        channel_state& st = *it++;
        while (!st.pending_reqs.empty()) {
            auto r = std::move(st.pending_reqs.front());
            st.pending_reqs.erase(st.pending_reqs.begin());
            if (core_.resolve(r.ticket, false) == code::invalid_state) {
                st.pending_reqs.insert(st.pending_reqs.begin(), std::move(r));
                break;
            }
        }
    }
}

inline std::optional<session_impl::pending_inbound_open> session_impl::take_pending_open() {
    if (pending_opens_.empty()) return std::nullopt;
    auto o = std::move(pending_opens_.front());
    pending_opens_.erase(pending_opens_.begin());
    return o;
}

inline std::optional<session_impl::pending_inbound_global> session_impl::take_pending_global() {
    if (pending_globals_.empty()) return std::nullopt;
    auto g = std::move(pending_globals_.front());
    pending_globals_.erase(pending_globals_.begin());
    return g;
}

inline void session_impl::close_locally(disconnect_reason reason, std::string_view description) {
    if (latch_) return;
    local_close_ = true;
    (void)core_.disconnect(reason, description);
    latch(code::session_closed);
}

inline std::error_code session_impl::close_status() const noexcept {
    if (local_close_) return {};
    if (have_disc_ && disc_.reason == disconnect_reason::by_application) return {};
    return latch_;
}

inline void session_impl::recv_buffer::release(std::pmr::memory_resource* mr) noexcept {
    if (data == nullptr) return;
    mr->deallocate(data, capacity, alignof(std::max_align_t));
    data = nullptr;
    off = 0;
    end = 0;
}

inline void session_impl::recv_buffer::compact(std::pmr::memory_resource* mr) noexcept {
    if (empty()) {
        release(mr);
    } else if (off > 0) {
        std::memmove(data, data + off, end - off);
        end -= off;
        off = 0;
    }
}

inline auv::buffer session_impl::recv_buffer::space(std::pmr::memory_resource* mr) {
    if (data == nullptr) {
        data = static_cast<std::byte*>(mr->allocate(capacity, alignof(std::max_align_t)));
    }
    return auv::buffer(reinterpret_cast<char*>(data + end), capacity - end);
}

inline std::size_t session_impl::next_output(std::array<auv::buffer, output_batch>& bufs,
                                             std::size_t& bytes) const {
    bytes = 0;
    if (output_closed_ || core_.pending_output_bytes() == 0) return 0;
    std::array<std::span<const std::byte>, output_batch> segs{};
    const std::size_t n = core_.pending_output(segs);
    for (std::size_t i = 0; i < n; ++i) {
        bufs[i] = auv::buffer(reinterpret_cast<const char*>(segs[i].data()), segs[i].size());
        bytes += segs[i].size();
    }
    return n;
}

inline bool session_impl::feed_buffered(std::size_t& accepted) {
    accepted = 0;
    if (in_.empty()) return true;
    auto ec = core_.feed(std::span(in_.data + in_.off, in_.end - in_.off), accepted);
    in_.off += accepted;
    wake_pumps();
    if (ec) {
        note_core_failure();
        latch(ec);
        return false;
    }
    if (in_.empty()) in_.release(mr_);
    return true;
}

inline bool session_impl::input_read(std::error_code ec, std::size_t n) {
    if (!ec && n == 0) ec = auv::make_error_code(auv::errc::eof);
    if (ec) {
        if (in_.empty()) in_.release(mr_);
        latch(ec, core::detail::format_transport_io("read", ec));
        return false;
    }
    in_.end += n;
    return true;
}

template <class Steps>
inline auto session_impl::run_phase(Steps&& steps) {
    return corral::just(false) | corral::then([&](bool& stop) {
        assert(!reading_ && !writing_);
        return corral::allOf(
            corral::anyOf(read_pump(), write_pump(stop)),
            steps() | corral::then([&](auto v) {
                stop = true;
                wake_pumps();
                return corral::just(std::move(v));
            }));
    }) | corral::then([](auto t) { return corral::just(std::move(std::get<1>(t))); });
}

inline corral::Task<void> session_impl::read_pump() {
    struct reading_guard {
        session_impl* s;
        explicit reading_guard(session_impl* p) : s(p) {
            assert(!s->reading_);
            s->reading_ = true;
        }
        reading_guard(const reading_guard&) = delete;
        reading_guard& operator=(const reading_guard&) = delete;
        ~reading_guard() { s->reading_ = false; }
    } guard{this};

    // Never co_returns: a closed session suspends here so the phase's steps
    // are not cancelled. Only cancelling the phase ends this pump.
    while (!closed()) {
        // Before serve() nothing drains the inbound queues; their callbacks
        // reject past the bound instead.
        const bool blocked =
            core_.inbound_requests_stalled() || (serving_ && inbound_queue_full());
        if (!blocked && !in_.empty()) {
            std::size_t accepted = 0;
            if (!feed_buffered(accepted) || accepted != 0) continue;
        }
        in_.compact(mr_);
        if (!blocked) {
            auto [ec, n] = co_await stream_.read([this] { return in_.space(mr_); });
            // A close that won the race drops this read. Feeding it would parse
            // past the latch, and a later error must not replace the recorded one.
            if (closed() || !input_read(ec, n)) continue;
            continue;
        }
        // Core takes nothing while blocked, but reading on into the buffer
        // still lets a transport EOF or read error reach the latch.
        if (in_.end == recv_buffer::capacity) {
            co_await pump_lot_.park();
            continue;
        }
        // A cancelled read delivers nothing, so the session stays consistent.
        auto r = co_await corral::anyOf(stream_.read([this] { return in_.space(mr_); }),
                                        pump_lot_.park());
        if (closed() || !std::get<0>(r)) continue;
        auto [ec, n] = *std::get<0>(r);
        if (!input_read(ec, n)) continue;
    }
    co_await corral::suspendForever;
}

inline corral::Task<void> session_impl::write_pump(const bool& stop) {
    struct writing_guard {
        session_impl* s;
        explicit writing_guard(session_impl* p) : s(p) {
            assert(!s->writing_);
            s->writing_ = true;
        }
        writing_guard(const writing_guard&) = delete;
        writing_guard& operator=(const writing_guard&) = delete;
        ~writing_guard() {
            s->writing_ = false;
            s->written_lot_.unparkAll();
        }
    } guard{this};

    std::array<auv::buffer, output_batch> bufs{};
    while (!output_closed_) {
        std::size_t bytes = 0;
        const std::size_t n = next_output(bufs, bytes);
        if (n == 0) {
            if (closed() || stop) co_return;
            co_await pump_lot_.park();
            continue;
        }
        // A write error latches and closes output; the next pass exits.
        const std::error_code ec = co_await stream_.write(bufs.data(), n);
        if (ec) {
            output_closed_ = true;
            latch(ec, core::detail::format_transport_io("write", ec));
            continue;
        }
        core_.consume_output(bytes);
        written_lot_.unparkAll();
    }
}

inline void session_impl::release_auth_stage() noexcept { auth_.reset(); }

inline auth_result session_impl::take_auth_response() {
    auth_result r = auth_->pending_auth_resp->result;
    if (r.success) r.methods = {};
    else r.methods = auth_->last_auth_methods;
    auth_->pending_auth_resp.reset();
    return r;
}

inline corral::Task<std::tuple<std::error_code, auth_result>> session_impl::wait_auth_response() {
    for (;;) {
        if (closed()) co_return {latch_, {}};
        if (auth_ && auth_->pending_auth_resp) {
            auto r = take_auth_response();
            auth_->client_auth_outstanding = false;
            if (r.success) release_auth_stage();
            co_return {std::error_code{}, r};
        }
        co_await inbound_lot_.park();
    }
}

}  // namespace yanterm::ssh
