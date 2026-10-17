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

#include <array>
#include <cassert>
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
#include <utility>
#include <vector>

namespace yanterm::ssh {

struct session_impl : core::handler {
    session_impl(core::role r, auv::stream stream, crypto::provider provider,
                 session_options o, std::pmr::memory_resource* mr,
                 std::string auth_banner = {},
                 std::string auth_banner_language = {},
                 std::function<void(std::string_view, std::string_view)> on_banner = {});

    void latch(std::error_code ec, std::string detail = {});
    [[nodiscard]] bool inbound_queue_full() const noexcept;
    auth_result take_auth_response();
    corral::Task<void> read_pump();
    corral::Task<void> write_pump(corral::TaskStarted<> started);
    corral::Task<void> flush_pending();
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

    bool run_active_ = false;
    std::uint32_t max_pending_requests_ = default_max_pending_requests;
    std::error_code latch_{};
    std::string latch_detail_;
    disconnect_info disc_{};
    bool have_disc_ = false;
    corral::ParkingLot write_lot_;
    corral::ParkingLot unstall_lot_;
    corral::ParkingLot out_space_lot_;
    corral::ParkingLot flushed_lot_;
    corral::ParkingLot rekey_lot_;
    std::uint64_t rekey_gen_ = 0;
    corral::Event failed_ev_;
    std::function<void(bool always_display, std::string_view text, std::string_view language)>
        on_debug_;
    corral::ParkingLot hs_lot_;
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

    corral::ParkingLot auth_lot_;

    bool serving_ = false;
    corral::ParkingLot serve_lot_;

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
    void reject_pending_opens_and_globals();
    void reject_pending_inbound();
    std::optional<pending_inbound_open> take_pending_open();
    std::optional<pending_inbound_global> take_pending_global();

    ~session_impl();
};

inline session_impl::session_impl(
    core::role r, auv::stream stream, crypto::provider provider, session_options o,
    std::pmr::memory_resource* mr, std::string auth_banner, std::string auth_banner_language,
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
    hs_lot_.unparkAll();
}

inline void session_impl::on_handshake_done(core::connection&) {
    hs_done_ = true;
    hs_lot_.unparkAll();
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
    auth_lot_.unparkAll();
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
    auth_lot_.unparkAll();
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
    auth_lot_.unparkAll();
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
    auth_lot_.unparkAll();
}

inline void session_impl::on_open_request(core::connection& c, core::open_ticket ticket,
                                          const channels::open_request_view& request) {
    if (!serving_) {
        (void)c.resolve(ticket, channels::channel_open_verdict::rejected(
                                  channels::channel_open_reason::administratively_prohibited,
                                  "serve not installed"));
        write_lot_.unparkAll();
        unstall_lot_.unparkAll();
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
    serve_lot_.unparkAll();
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
    write_lot_.unparkAll();
    unstall_lot_.unparkAll();
}

inline void session_impl::on_channel_reply(core::connection&, core::channel_ref, void* user,
                                           bool success) {
    if (auto* st = static_cast<channel_state*>(user)) complete_channel_reply(*st, success);
}

inline void session_impl::on_global_request(core::connection& c, core::global_request_ticket ticket,
                                            const channels::request_view& request) {
    if (!serving_) {
        (void)c.resolve(ticket, false);
        write_lot_.unparkAll();
        unstall_lot_.unparkAll();
        return;
    }
    pending_inbound_global g;
    g.ticket = ticket;
    g.type.assign(request.type.begin(), request.type.end());
    g.payload.assign(request.payload.begin(), request.payload.end());
    g.want_reply = request.want_reply;
    pending_globals_.push_back(std::move(g));
    serve_lot_.unparkAll();
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
    unstall_lot_.unparkAll();
}

inline void session_impl::latch(std::error_code ec, std::string detail) {
    if (!latch_) {
        latch_ = ec;
        latch_detail_ = core::detail::clip_failure_detail(std::move(detail));
    }
    failed_ev_.trigger();
    wake_reply_waiters();
    write_lot_.unparkAll();
    unstall_lot_.unparkAll();
    out_space_lot_.unparkAll();
    flushed_lot_.unparkAll();
    rekey_lot_.unparkAll();
    hs_lot_.unparkAll();
    auth_lot_.unparkAll();
    serve_lot_.unparkAll();
    unpark_live_channels();
    reject_pending_inbound();
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

inline void session_impl::reject_pending_opens_and_globals() {
    while (auto o = take_pending_open()) {
        (void)core_.resolve(o->ticket, channels::channel_open_verdict::rejected(
                                 channels::channel_open_reason::administratively_prohibited,
                                 "serve not installed"));
    }
    while (auto g = take_pending_global()) {
        (void)core_.resolve(g->ticket, false);
    }
}

inline void session_impl::reject_pending_inbound() {
    reject_pending_opens_and_globals();
    // A channel ticket still ahead of the in-flight head cannot be settled.
    // Leave it at the front so the serve_requests guard can reject the head
    // first, then this one. Globals are dropped: nothing retries that queue
    // after run_active_ becomes false.
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

inline corral::Task<void> session_impl::read_pump() {
    // One page-sized block, held only while unread bytes remain.
    static constexpr std::size_t inbuf_size = memory::default_page_size;
    static_assert(inbuf_size > 4 + core::detail::max_packet_length + 64,
                  "the receive block must hold one whole SSH binary packet");
    struct recv_block {
        std::pmr::memory_resource* mr = nullptr;
        std::byte* data = nullptr;
        std::size_t off = 0;
        std::size_t end = 0;

        explicit recv_block(std::pmr::memory_resource* resource) noexcept : mr(resource) {}
        recv_block(const recv_block&) = delete;
        recv_block& operator=(const recv_block&) = delete;
        ~recv_block() { release(); }

        void release() noexcept {
            if (data == nullptr) return;
            mr->deallocate(data, inbuf_size, alignof(std::max_align_t));
            data = nullptr;
            off = 0;
            end = 0;
        }

        std::byte* acquire() {
            if (data == nullptr) {
                data = static_cast<std::byte*>(mr->allocate(inbuf_size, alignof(std::max_align_t)));
            }
            return data;
        }
    };

    recv_block in{mr_};
    for (;;) {
        if (latch_ || core_.failure()) break;
        if (in.off < in.end) {
            std::size_t accepted = 0;
            auto ec = core_.feed(std::span(in.data + in.off, in.end - in.off), accepted);
            in.off += accepted;
            write_lot_.unparkAll();
            if (ec) {
                latch(ec, std::string(core_.failure_detail()));
                break;
            }
            if (in.off == in.end) in.release();
            if (core_.inbound_requests_stalled()) {
                co_await unstall_lot_.park();
                continue;
            }
            if (inbound_queue_full()) {
                co_await unstall_lot_.park();
                continue;
            }
            if (accepted != 0) continue;
        }
        if (in.off == in.end) {
            in.release();
        } else if (in.off > 0) {
            std::memmove(in.data, in.data + in.off, in.end - in.off);
            in.end -= in.off;
            in.off = 0;
        }
        // Empty buffer still waits here. Bytes already read stay a single feed.
        if (core_.inbound_requests_stalled() || inbound_queue_full()) {
            co_await unstall_lot_.park();
            continue;
        }
        auto [ec, n] = co_await stream_.read([&in] {
            std::byte* buf = in.acquire();
            return auv::buffer(reinterpret_cast<char*>(buf + in.end), inbuf_size - in.end);
        });
        if (ec) {
            latch(ec, core::detail::format_transport_io("read", ec));
            break;
        }
        if (n == 0) {
            const auto eof = auv::make_error_code(auv::errc::eof);
            latch(eof, core::detail::format_transport_io("read", eof));
            break;
        }
        in.end += n;
    }
    if (in.off == in.end) in.release();
    latch(latch_ ? latch_ : core_.failure(),
          latch_ ? std::string{} : std::string(core_.failure_detail()));
}

inline corral::Task<void> session_impl::write_pump(corral::TaskStarted<> started) {
    std::array<std::span<const std::byte>, 8> segs{};
    std::array<auv::buffer, 8> bufs{};
    bool announced = false;
    auto announce = [&] {
        if (!announced) {
            announced = true;
            started();
        }
    };
    for (;;) {
        if (latch_ && core_.pending_output_bytes() == 0) break;
        if (core_.pending_output_bytes() == 0) {
            announce();
            co_await write_lot_.park();
            continue;
        }
        const std::size_t n = core_.pending_output(segs);
        for (std::size_t i = 0; i < n; ++i) {
            bufs[i] = auv::buffer(reinterpret_cast<const char*>(segs[i].data()), segs[i].size());
        }
        std::size_t bytes = 0;
        for (std::size_t i = 0; i < n; ++i) bytes += segs[i].size();
        auto ec = co_await stream_.write(bufs.data(), n);
        if (ec) {
            announce();
            latch(ec, core::detail::format_transport_io("write", ec));
            break;
        }
        core_.consume_output(bytes);
        out_space_lot_.unparkAll();
        flushed_lot_.unparkAll();
        announce();
    }
    announce();
}

inline corral::Task<void> session_impl::flush_pending() {
    std::array<std::span<const std::byte>, 8> segs{};
    std::array<auv::buffer, 8> bufs{};
    while (core_.pending_output_bytes() > 0 && !latch_) {
        const std::size_t n = core_.pending_output(segs);
        if (n == 0) break;
        for (std::size_t i = 0; i < n; ++i) {
            bufs[i] = auv::buffer(reinterpret_cast<const char*>(segs[i].data()), segs[i].size());
        }
        std::size_t bytes = 0;
        for (std::size_t i = 0; i < n; ++i) bytes += segs[i].size();
        auto ec = co_await stream_.write(bufs.data(), n);
        if (ec) {
            latch(ec, core::detail::format_transport_io("flush", ec));
            break;
        }
        core_.consume_output(bytes);
        out_space_lot_.unparkAll();
        flushed_lot_.unparkAll();
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
        if (latch_) co_return {code::session_closed, {}};
        if (auth_ && auth_->pending_auth_resp) {
            auto r = take_auth_response();
            auth_->client_auth_outstanding = false;
            if (r.success) release_auth_stage();
            co_return {std::error_code{}, r};
        }
        co_await auth_lot_.park();
        if (latch_) co_return {code::session_closed, {}};
    }
}

}  // namespace yanterm::ssh
