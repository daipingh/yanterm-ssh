#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/detail/session_impl.hpp>
#include <yanterm-ssh/channels/requests.hpp>

#include <auv/error.hpp>
#include <auv/stream.hpp>
#include <corral/Task.h>
#include <corral/utility.h>
#include <corral/wait.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace yanterm::ssh {

class session;

class channel {
public:
    channel() noexcept = default;
    channel(const channel&) = delete;
    channel& operator=(const channel&) = delete;
    channel(channel&& other) noexcept;
    channel& operator=(channel&& other) noexcept;
    ~channel();

    corral::Task<auv::read_result> read(auv::read_allocator alloc_cb, void* alloc_arg);
    corral::Task<std::error_code> write(const auv::buffer* bufs, std::size_t nbufs);
    corral::Task<std::error_code> shutdown();
    corral::Task<void> close();
    corral::Task<auv::read_result> read_stderr(auv::read_allocator alloc_cb, void* alloc_arg);
    corral::Task<std::error_code> write_stderr(const auv::buffer* bufs, std::size_t nbufs);

    template <typename Allocator>
        requires auv::detail::read_allocator_callable<std::remove_reference_t<Allocator>>
    auto read(Allocator&& alloc_cb) {
        return read(
            [](void* p) {
                auto& cb = *static_cast<std::remove_reference_t<Allocator>*>(p);
                return static_cast<auv::buffer>(cb());
            },
            &alloc_cb);
    }

    template <typename Allocator>
        requires auv::detail::read_allocator_callable<std::remove_reference_t<Allocator>>
    auto read_stderr(Allocator&& alloc_cb) {
        return read_stderr(
            [](void* p) {
                auto& cb = *static_cast<std::remove_reference_t<Allocator>*>(p);
                return static_cast<auv::buffer>(cb());
            },
            &alloc_cb);
    }

    auto read(auv::buffer dest) {
        return corral::just(dest) | corral::then([&](auto& buf) {
                   return read([](void* p) { return *static_cast<auv::buffer*>(p); }, &buf);
               });
    }

    auto read_stderr(auv::buffer dest) {
        return corral::just(dest) | corral::then([&](auto& buf) {
                   return read_stderr([](void* p) { return *static_cast<auv::buffer*>(p); }, &buf);
               });
    }

    corral::Task<std::error_code> request_pty(pty_spec spec);
    corral::Task<std::error_code> request_shell();
    corral::Task<std::error_code> request_exec(std::string_view command);
    corral::Task<std::error_code> request_subsystem(std::string_view name);
    corral::Task<std::error_code> request_env(std::string_view name, std::string_view value);
    corral::Task<std::error_code> request_window_change(window_size size);
    corral::Task<std::error_code> request_signal(std::string_view name);
    corral::Task<std::error_code> send_exit_status(std::uint32_t status);
    corral::Task<std::error_code> send_exit_signal(exit_signal sig);
    corral::Task<std::error_code> request_x11(x11_req_spec spec);

    template <class Handler>
    corral::Task<void> serve_requests(Handler handler);

    explicit operator bool() const noexcept;

private:
    friend class session;
    friend class inbound_channel_open;

    channel(std::shared_ptr<session_impl> impl, session_impl::channel_state* st) noexcept;

    void close_now() noexcept;
    corral::Task<auv::read_result> read_ext(std::uint32_t ext, auv::read_allocator alloc_cb,
                                            void* alloc_arg);
    corral::Task<std::error_code> write_ext(std::uint32_t ext, const auv::buffer* bufs,
                                            std::size_t nbufs);
    template <class Enqueue>
    corral::Task<std::error_code> enqueue_channel_request(bool want_reply, Enqueue enqueue);
    corral::Task<std::error_code> wait_channel_response();
    template <class Handler>
    corral::Task<void> serve_requests_loop(Handler handler);

    std::shared_ptr<session_impl> impl_;
    session_impl::channel_state* st_ = nullptr;
    core::channel_ref ref_{};
    bool app_closed_ = false;
};

struct channel_open_result {
    std::error_code ec;
    channel ch;
    channel_open_reason reason{};
    std::string description;
};

class inbound_channel_open {
public:
    inbound_channel_open(const inbound_channel_open&) = delete;
    inbound_channel_open& operator=(const inbound_channel_open&) = delete;
    inbound_channel_open(inbound_channel_open&& other) noexcept;
    inbound_channel_open& operator=(inbound_channel_open&& other) noexcept;
    ~inbound_channel_open();

    [[nodiscard]] channel_type type() const noexcept { return type_; }
    [[nodiscard]] std::string_view request_type() const noexcept { return request_type_; }
    [[nodiscard]] std::string_view host() const noexcept { return host_; }
    [[nodiscard]] std::uint32_t port() const noexcept { return port_; }
    [[nodiscard]] std::string_view originator_host() const noexcept { return originator_host_; }
    [[nodiscard]] std::uint32_t originator_port() const noexcept { return originator_port_; }
    [[nodiscard]] std::string_view socket_path() const noexcept { return socket_path_; }
    [[nodiscard]] std::span<const std::byte> payload() const noexcept { return payload_; }

    channel accept();
    void reject(channel_open_reason reason, std::string_view description);

private:
    friend class session;

    inbound_channel_open(session_impl& impl, std::weak_ptr<session_impl> owner,
                         session_impl::pending_inbound_open o);

    void reject_now() noexcept;

    session_impl* impl_ = nullptr;
    std::weak_ptr<session_impl> owner_;
    core::open_ticket ticket_{};
    core::channel_ref ref_{};
    channel_type type_ = channel_type::unknown;
    std::string request_type_;
    std::string host_;
    std::uint32_t port_ = 0;
    std::string originator_host_;
    std::uint32_t originator_port_ = 0;
    std::string socket_path_;
    std::vector<std::byte> payload_;
    bool settled_ = false;
};

class inbound_channel_request {
public:
    inbound_channel_request() = default;

    [[nodiscard]] std::string_view type() const noexcept { return type_; }
    [[nodiscard]] std::span<const std::byte> payload() const noexcept { return payload_; }
    [[nodiscard]] bool want_reply() const noexcept { return want_reply_; }

    [[nodiscard]] std::optional<pty_spec> pty() const;
    [[nodiscard]] std::optional<std::string_view> exec_command() const;
    [[nodiscard]] std::optional<std::string_view> subsystem() const;
    [[nodiscard]] std::optional<std::pair<std::string_view, std::string_view>> env() const;
    [[nodiscard]] std::optional<window_size> window_change() const;
    [[nodiscard]] std::optional<std::string_view> signal() const;
    [[nodiscard]] std::optional<std::uint32_t> exit_status() const;
    [[nodiscard]] auto exit_signal() const -> std::optional<channels::exit_signal>;
    [[nodiscard]] std::optional<x11_req_spec> x11() const;

private:
    friend class channel;
    inbound_channel_request(session_impl::pending_inbound_request r);

    std::string type_;
    std::vector<std::byte> payload_;
    bool want_reply_ = false;
};

class inbound_global_request {
public:
    inbound_global_request() = default;
    inbound_global_request(const inbound_global_request&) = delete;
    inbound_global_request& operator=(const inbound_global_request&) = delete;
    inbound_global_request(inbound_global_request&& other) noexcept;
    inbound_global_request& operator=(inbound_global_request&& other) noexcept;
    ~inbound_global_request();

    [[nodiscard]] std::string_view type() const noexcept { return type_; }
    [[nodiscard]] std::span<const std::byte> payload() const noexcept { return payload_; }
    [[nodiscard]] bool want_reply() const noexcept { return want_reply_; }
    void accept(std::span<const std::byte> response_payload = {});
    void reject();

private:
    friend class session;
    inbound_global_request(session_impl& impl, session_impl::pending_inbound_global g);
    void reject_now() noexcept;

    session_impl* impl_ = nullptr;
    core::global_request_ticket ticket_{};
    std::string type_;
    std::vector<std::byte> payload_;
    bool want_reply_ = false;
    bool settled_ = false;
};

inline channel::channel(std::shared_ptr<session_impl> impl, session_impl::channel_state* st) noexcept
    : impl_(std::move(impl)), st_(st), ref_(st != nullptr ? st->ref : core::channel_ref{}) {}

inline channel::channel(channel&& other) noexcept
    : impl_(std::move(other.impl_))
    , st_(other.st_)
    , ref_(other.ref_)
    , app_closed_(other.app_closed_) {
    other.st_ = nullptr;
    other.app_closed_ = true;
}

inline channel& channel::operator=(channel&& other) noexcept {
    if (this != &other) {
        close_now();
        if (st_ != nullptr && impl_) impl_->release(st_);
        impl_ = std::move(other.impl_);
        st_ = other.st_;
        ref_ = other.ref_;
        app_closed_ = other.app_closed_;
        other.st_ = nullptr;
        other.impl_.reset();
        other.app_closed_ = true;
    }
    return *this;
}

inline channel::~channel() {
    close_now();
    if (st_ != nullptr && impl_) impl_->release(st_);
    st_ = nullptr;
}

inline channel::operator bool() const noexcept { return static_cast<bool>(impl_) && st_ != nullptr; }

inline void channel::close_now() noexcept {
    if (!impl_ || st_ == nullptr || app_closed_) return;
    app_closed_ = true;
    if (!impl_->run_active_) return;
    (void)impl_->core_.channel_close(ref_);
    impl_->write_lot_.unparkAll();
}

inline corral::Task<auv::read_result> channel::read(auv::read_allocator alloc_cb, void* alloc_arg) {
    co_return co_await read_ext(0, alloc_cb, alloc_arg);
}

inline corral::Task<auv::read_result> channel::read_stderr(auv::read_allocator alloc_cb,
                                                           void* alloc_arg) {
    co_return co_await read_ext(channels::extended_data_stderr, alloc_cb, alloc_arg);
}

inline corral::Task<auv::read_result> channel::read_ext(std::uint32_t ext,
                                                        auv::read_allocator alloc_cb,
                                                        void* alloc_arg) {
    if (!impl_ || st_ == nullptr) co_return {code::invalid_state, 0};
    auto& self = *impl_;
    auto& lot = (ext == 0) ? st_->rd_lot : st_->ext_lot;
    for (;;) {
        auv::buffer buf = alloc_cb(alloc_arg);
        if (buf.size() == 0) {
            co_return {std::make_error_code(std::errc::no_buffer_space), 0};
        }
        auto dst = std::span<std::byte>(reinterpret_cast<std::byte*>(buf.data()), buf.size());
        const std::size_t n = self.core_.channel_read(ref_, ext, dst);
        if (n > 0) {
            // channel_read may enqueue WINDOW_ADJUST, so unpark write_lot.
            self.write_lot_.unparkAll();
            co_return {std::error_code{}, n};
        }
        const bool stopped = !self.run_active_ || bool(self.latch_) || bool(self.core_.failure());
        const bool ended = st_->recv_eof || st_->recv_close;
        if (stopped || ended) {
            if (ended) co_return {auv::make_error_code(auv::errc::eof), 0};
            co_return {code::session_closed, 0};
        }
        co_await lot.park();
    }
}

inline corral::Task<std::error_code> channel::write(const auv::buffer* bufs, std::size_t nbufs) {
    co_return co_await write_ext(0, bufs, nbufs);
}

inline corral::Task<std::error_code> channel::write_stderr(const auv::buffer* bufs,
                                                           std::size_t nbufs) {
    co_return co_await write_ext(channels::extended_data_stderr, bufs, nbufs);
}

inline corral::Task<std::error_code> channel::write_ext(std::uint32_t ext, const auv::buffer* bufs,
                                                        std::size_t nbufs) {
    if (!impl_ || st_ == nullptr) co_return code::invalid_state;
    auto& self = *impl_;
    if (!self.run_active_ || self.latch_) co_return code::session_closed;

    std::vector<std::span<const std::byte>> frags;
    frags.reserve(nbufs);
    std::size_t total = 0;
    for (std::size_t i = 0; i < nbufs; ++i) {
        auto* p = reinterpret_cast<const std::byte*>(bufs[i].data());
        frags.emplace_back(p, bufs[i].size());
        total += bufs[i].size();
    }
    if (total == 0) co_return {};

    std::size_t sent = 0;
    auto remaining = [&](std::size_t skip) {
        std::vector<std::span<const std::byte>> out;
        for (auto f : frags) {
            if (skip >= f.size()) {
                skip -= f.size();
                continue;
            }
            if (skip > 0) {
                out.push_back(f.subspan(skip));
                skip = 0;
            } else {
                out.push_back(f);
            }
        }
        return out;
    };

    auto& wr = st_->wr_lot;
    for (;;) {
        if (!self.run_active_ || self.latch_) co_return code::session_closed;
        while (self.core_.pending_output_bytes() >= self.max_output_bytes_) {
            if (!self.run_active_ || self.latch_) co_return code::session_closed;
            co_await self.out_space_lot_.park();
        }
        if (sent >= total) co_return {};
        auto rem = remaining(sent);
        std::size_t accepted = 0;
        std::error_code wec;
        if (ext == 0) {
            wec = self.core_.channel_write(ref_, rem, accepted);
        } else {
            wec = self.core_.channel_write_extended(ref_, ext, rem, accepted);
        }
        if (wec) co_return wec;
        self.write_lot_.unparkAll();
        sent += accepted;
        if (sent >= total) continue;
        co_await wr.park();
    }
}

inline corral::Task<std::error_code> channel::shutdown() {
    if (!impl_ || st_ == nullptr) co_return code::invalid_state;
    auto& self = *impl_;
    if (!self.run_active_ || self.latch_) co_return code::session_closed;
    auto ec = self.core_.channel_eof(ref_);
    self.write_lot_.unparkAll();
    co_return ec;
}

inline corral::Task<void> channel::close() {
    if (!impl_ || st_ == nullptr) co_return;
    auto& self = *impl_;
    app_closed_ = true;
    if (!self.run_active_) co_return;
    // Always mark app_close while pumps run. Peer CLOSE may already have
    // set recv_close / sent_close, but a non-empty rx buffer still needs
    // app_close for releasable(); core.channel_close is idempotent.
    (void)self.core_.channel_close(ref_);
    self.write_lot_.unparkAll();
    while (!st_->recv_close && self.run_active_ && !self.latch_) {
        co_await st_->rd_lot.park();
    }
}

inline inbound_channel_open::inbound_channel_open(session_impl& impl,
                                                  std::weak_ptr<session_impl> owner,
                                                  session_impl::pending_inbound_open o)
    : impl_(&impl)
    , owner_(std::move(owner))
    , ticket_(o.ticket)
    , ref_(o.ref)
    , type_(o.type)
    , request_type_(std::move(o.request_type))
    , host_(std::move(o.host))
    , port_(o.port)
    , originator_host_(std::move(o.originator_host))
    , originator_port_(o.originator_port)
    , socket_path_(std::move(o.socket_path))
    , payload_(std::move(o.extra)) {}

inline inbound_channel_open::inbound_channel_open(inbound_channel_open&& other) noexcept
    : impl_(other.impl_)
    , owner_(std::move(other.owner_))
    , ticket_(other.ticket_)
    , ref_(other.ref_)
    , type_(other.type_)
    , request_type_(std::move(other.request_type_))
    , host_(std::move(other.host_))
    , port_(other.port_)
    , originator_host_(std::move(other.originator_host_))
    , originator_port_(other.originator_port_)
    , socket_path_(std::move(other.socket_path_))
    , payload_(std::move(other.payload_))
    , settled_(other.settled_) {
    other.settled_ = true;
    other.impl_ = nullptr;
}

inline inbound_channel_open& inbound_channel_open::operator=(inbound_channel_open&& other) noexcept {
    if (this != &other) {
        reject_now();
        impl_ = other.impl_;
        owner_ = std::move(other.owner_);
        ticket_ = other.ticket_;
        ref_ = other.ref_;
        type_ = other.type_;
        request_type_ = std::move(other.request_type_);
        host_ = std::move(other.host_);
        port_ = other.port_;
        originator_host_ = std::move(other.originator_host_);
        originator_port_ = other.originator_port_;
        socket_path_ = std::move(other.socket_path_);
        payload_ = std::move(other.payload_);
        settled_ = other.settled_;
        other.settled_ = true;
        other.impl_ = nullptr;
    }
    return *this;
}

inline inbound_channel_open::~inbound_channel_open() { reject_now(); }

inline void inbound_channel_open::reject_now() noexcept {
    if (settled_ || !impl_) return;
    settled_ = true;
    if (!impl_->run_active_ || impl_->core_.failure()) return;
    (void)impl_->core_.resolve(ticket_, channels::channel_open_verdict::rejected(
                                  channels::channel_open_reason::administratively_prohibited,
                                  "unhandled inbound open"));
    impl_->write_lot_.unparkAll();
    impl_->unstall_lot_.unparkAll();
}

inline channel inbound_channel_open::accept() {
    auto sp = owner_.lock();
    if (settled_ || !sp) return {};
    settled_ = true;
    auto* st = new session_impl::channel_state{};
    st->refs = 2;
    st->ref = ref_;
    sp->live_channels_.push_back(*st);
    if (auto ec = sp->core_.resolve(ticket_, channels::channel_open_verdict::accepted(), st)) {
        st->refs = 1;
    }
    sp->write_lot_.unparkAll();
    sp->unstall_lot_.unparkAll();
    return channel{std::move(sp), st};
}

inline void inbound_channel_open::reject(channel_open_reason reason, std::string_view description) {
    if (settled_ || !impl_) return;
    settled_ = true;
    (void)impl_->core_.resolve(ticket_, channels::channel_open_verdict::rejected(reason, description));
    impl_->write_lot_.unparkAll();
    impl_->unstall_lot_.unparkAll();
}

inline inbound_global_request::inbound_global_request(session_impl& impl,
                                                      session_impl::pending_inbound_global g)
    : impl_(&impl)
    , ticket_(g.ticket)
    , type_(std::move(g.type))
    , payload_(std::move(g.payload))
    , want_reply_(g.want_reply) {}

inline inbound_global_request::inbound_global_request(inbound_global_request&& other) noexcept
    : impl_(other.impl_)
    , ticket_(other.ticket_)
    , type_(std::move(other.type_))
    , payload_(std::move(other.payload_))
    , want_reply_(other.want_reply_)
    , settled_(other.settled_) {
    other.settled_ = true;
    other.impl_ = nullptr;
}

inline inbound_global_request& inbound_global_request::operator=(
    inbound_global_request&& other) noexcept {
    if (this != &other) {
        reject_now();
        impl_ = other.impl_;
        ticket_ = other.ticket_;
        type_ = std::move(other.type_);
        payload_ = std::move(other.payload_);
        want_reply_ = other.want_reply_;
        settled_ = other.settled_;
        other.settled_ = true;
        other.impl_ = nullptr;
    }
    return *this;
}

inline inbound_global_request::~inbound_global_request() { reject_now(); }

inline void inbound_global_request::reject_now() noexcept {
    if (settled_ || !impl_) return;
    settled_ = true;
    if (!impl_->run_active_ || impl_->core_.failure()) return;
    (void)impl_->core_.resolve(ticket_, false);
    impl_->write_lot_.unparkAll();
    impl_->unstall_lot_.unparkAll();
}

inline void inbound_global_request::accept(std::span<const std::byte> response_payload) {
    if (settled_ || !impl_) return;
    settled_ = true;
    (void)impl_->core_.resolve(ticket_, true, response_payload);
    impl_->write_lot_.unparkAll();
    impl_->unstall_lot_.unparkAll();
}

inline void inbound_global_request::reject() {
    if (settled_ || !impl_) return;
    reject_now();
}

inline inbound_channel_request::inbound_channel_request(session_impl::pending_inbound_request r)
    : type_(std::move(r.type)), payload_(std::move(r.payload)), want_reply_(r.want_reply) {}

inline std::optional<pty_spec> inbound_channel_request::pty() const {
    if (type_ != "pty-req") return std::nullopt;
    std::string_view term;
    window_size ws;
    std::span<const std::byte> modes;
    if (!channels::decode_pty_req(payload_, term, ws, modes)) return std::nullopt;
    pty_spec spec;
    spec.term = term;
    spec.width = ws.cols;
    spec.height = ws.rows;
    spec.pixel_width = ws.pixel_width;
    spec.pixel_height = ws.pixel_height;
    spec.modes = modes;
    return spec;
}

inline std::optional<std::string_view> inbound_channel_request::exec_command() const {
    if (type_ != "exec") return std::nullopt;
    std::string_view command;
    if (!channels::decode_exec(payload_, command)) return std::nullopt;
    return command;
}

inline std::optional<std::string_view> inbound_channel_request::subsystem() const {
    if (type_ != "subsystem") return std::nullopt;
    std::string_view name;
    if (!channels::decode_subsystem(payload_, name)) return std::nullopt;
    return name;
}

inline std::optional<std::pair<std::string_view, std::string_view>> inbound_channel_request::env()
    const {
    if (type_ != "env") return std::nullopt;
    std::string_view name;
    std::string_view value;
    if (!channels::decode_env(payload_, name, value)) return std::nullopt;
    return std::pair{name, value};
}

inline std::optional<window_size> inbound_channel_request::window_change() const {
    if (type_ != "window-change") return std::nullopt;
    window_size ws;
    if (!channels::decode_window_change(payload_, ws)) return std::nullopt;
    return ws;
}

inline std::optional<std::string_view> inbound_channel_request::signal() const {
    if (type_ != "signal") return std::nullopt;
    std::string_view name;
    if (!channels::decode_signal(payload_, name)) return std::nullopt;
    return name;
}

inline std::optional<std::uint32_t> inbound_channel_request::exit_status() const {
    if (type_ != "exit-status") return std::nullopt;
    std::uint32_t status = 0;
    if (!channels::decode_exit_status(payload_, status)) return std::nullopt;
    return status;
}

inline auto inbound_channel_request::exit_signal() const
    -> std::optional<channels::exit_signal> {
    if (type_ != "exit-signal") return std::nullopt;
    channels::exit_signal sig;
    if (!channels::decode_exit_signal(payload_, sig.name, sig.core_dumped, sig.message,
                                            sig.language)) {
        return std::nullopt;
    }
    return sig;
}

inline std::optional<x11_req_spec> inbound_channel_request::x11() const {
    if (type_ != "x11-req") return std::nullopt;
    x11_req_spec spec;
    if (!channels::decode_x11_req(payload_, spec.single_connection, spec.protocol, spec.cookie,
                                  spec.screen)) {
        return std::nullopt;
    }
    return spec;
}

template <class Enqueue>
inline corral::Task<std::error_code> channel::enqueue_channel_request(bool want_reply,
                                                                      Enqueue enqueue) {
    if (!impl_ || st_ == nullptr) co_return code::invalid_state;
    auto& self = *impl_;
    if (!self.run_active_ || self.latch_) co_return code::session_closed;
    if (auto ec = enqueue()) co_return ec;
    self.write_lot_.unparkAll();
    if (!want_reply) co_return {};
    co_return co_await wait_channel_response();
}

inline corral::Task<std::error_code> channel::wait_channel_response() {
    auto& self = *impl_;
    session_impl::reply_waiter waiter;
    waiter.seq = st_->next_send_seq++;
    st_->reply_waiters.push_back(waiter);

    for (;;) {
        if (self.latch_ || !self.run_active_) {
            waiter.done = true;
            co_return code::session_closed;
        }
        if (waiter.done) {
            if (waiter.from_reply) {
                co_return waiter.success ? std::error_code{} : code::request_denied;
            }
            co_return code::invalid_state;
        }
        if (st_->recv_close) {
            waiter.done = true;
            co_return code::invalid_state;
        }
        co_await waiter.ready;
    }
}

inline corral::Task<std::error_code> channel::request_pty(pty_spec spec) {
    co_return co_await enqueue_channel_request(true, [&] {
        return impl_->core_.request_pty(ref_, spec);
    });
}

inline corral::Task<std::error_code> channel::request_shell() {
    co_return co_await enqueue_channel_request(true, [&] {
        return impl_->core_.request_shell(ref_);
    });
}

inline corral::Task<std::error_code> channel::request_exec(std::string_view command) {
    co_return co_await enqueue_channel_request(true, [&] {
        return impl_->core_.request_exec(ref_, command);
    });
}

inline corral::Task<std::error_code> channel::request_subsystem(std::string_view name) {
    co_return co_await enqueue_channel_request(true, [&] {
        return impl_->core_.request_subsystem(ref_, name);
    });
}

inline corral::Task<std::error_code> channel::request_env(std::string_view name,
                                                         std::string_view value) {
    co_return co_await enqueue_channel_request(true, [&] {
        return impl_->core_.request_env(ref_, name, value);
    });
}

inline corral::Task<std::error_code> channel::request_window_change(window_size size) {
    co_return co_await enqueue_channel_request(false, [&] {
        return impl_->core_.request_window_change(ref_, size);
    });
}

inline corral::Task<std::error_code> channel::request_signal(std::string_view name) {
    co_return co_await enqueue_channel_request(false, [&] {
        return impl_->core_.request_signal(ref_, name);
    });
}

inline corral::Task<std::error_code> channel::send_exit_status(std::uint32_t status) {
    co_return co_await enqueue_channel_request(false, [&] {
        return impl_->core_.send_exit_status(ref_, status);
    });
}

inline corral::Task<std::error_code> channel::send_exit_signal(exit_signal sig) {
    co_return co_await enqueue_channel_request(false, [&] {
        return impl_->core_.send_exit_signal(ref_, sig);
    });
}

inline corral::Task<std::error_code> channel::request_x11(x11_req_spec spec) {
    co_return co_await enqueue_channel_request(true, [&] {
        return impl_->core_.request_x11(ref_, spec);
    });
}

template <class Handler>
inline corral::Task<void> channel::serve_requests(Handler handler) {
    if (!impl_ || st_ == nullptr) {
        return []() -> corral::Task<void> { co_return; }();
    }
    // Arm before the returned task is awaited so OPEN_CONFIRMATION cannot
    // race a channel_request into the auto-reject drain path.
    st_->serving_requests = true;
    return serve_requests_loop(std::move(handler));
}

template <class Handler>
inline corral::Task<void> channel::serve_requests_loop(Handler handler) {
    if (!impl_ || st_ == nullptr) co_return;
    auto& self = *impl_;
    struct serving_guard {
        session_impl* self;
        session_impl::channel_state* st;
        core::channel_request_ticket in_flight{};
        bool has_in_flight = false;
        explicit serving_guard(session_impl* s, session_impl::channel_state* channel_st)
            : self(s), st(channel_st) {
            st->serving_requests = true;
        }
        serving_guard(const serving_guard&) = delete;
        serving_guard& operator=(const serving_guard&) = delete;
        ~serving_guard() {
            auto reject = [&](core::channel_request_ticket ticket) {
                (void)self->core_.resolve(ticket, false);
            };
            if (has_in_flight) reject(in_flight);
            while (!st->pending_reqs.empty()) {
                auto r = std::move(st->pending_reqs.front());
                st->pending_reqs.erase(st->pending_reqs.begin());
                reject(r.ticket);
            }
            st->serving_requests = false;
            self->write_lot_.unparkAll();
            self->unstall_lot_.unparkAll();
        }
    } guard{&self, st_};

    while (!self.latch_ && self.run_active_) {
        if (!st_->pending_reqs.empty()) {
            auto pending = std::move(st_->pending_reqs.front());
            st_->pending_reqs.erase(st_->pending_reqs.begin());
            const core::channel_request_ticket rid = pending.ticket;
            inbound_channel_request req{std::move(pending)};
            guard.in_flight = rid;
            guard.has_in_flight = true;
            bool ok = co_await handler(std::move(req));
            if (self.latch_ || !self.run_active_ || self.core_.failure()) co_return;
            guard.has_in_flight = false;
            (void)self.core_.resolve(rid, ok);
            self.write_lot_.unparkAll();
            self.unstall_lot_.unparkAll();
            continue;
        }
        if (st_->recv_close) co_return;
        co_await st_->req_lot.park();
    }
}

}  // namespace yanterm::ssh
