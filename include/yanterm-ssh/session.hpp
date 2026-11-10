#pragma once

#include <yanterm-ssh/detail/session_impl.hpp>
#include <yanterm-ssh/channel.hpp>
#include <yanterm-ssh/core/types.hpp>
#include <yanterm-ssh/keys/public_key.hpp>
#include <yanterm-ssh/wire/types.hpp>

#include <corral/concepts.h>

#include <concepts>
#include <cstddef>
#include <span>
#include <system_error>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace yanterm::ssh {

// Called as an lvalue with the chosen algorithm and the data to sign. The
// awaited result is either an error or an SSH signature blob (string
// algorithm, string signature), the format of an ssh-agent SIGN_RESPONSE.
template <class S>
concept publickey_signer =
    std::invocable<S&, const core::publickey_sign_request&, std::span<const std::byte>>
    && corral::Awaitable<
        std::invoke_result_t<S&, const core::publickey_sign_request&, std::span<const std::byte>>,
        std::tuple<std::error_code, std::vector<std::byte>>>;

class session {
public:
    session(const session&) = delete;
    session& operator=(const session&) = delete;
    explicit operator bool() const noexcept;

    corral::Task<void> disconnect(disconnect_reason reason, std::string_view description);

    // Completes after the library-side cleanup of the session latch has
    // finished; already closed, it completes immediately. Sends no DISCONNECT
    // and does not change the latch. Never drives a transport read itself, so
    // a peer close is observed only while handshake(), authentication or
    // serve() is running: each keeps a read pump alive for the whole call,
    // including inside application callbacks. Requires operator bool. Query
    // the cause with failure() and disconnected().
    corral::Event::Awaiter until_closed();

    // Runs the session after authentication. Without `body` it waits for the
    // session to close and for already started callbacks to return. With one,
    // a peer close does not cancel `body`; after `body` and already started
    // callbacks return, it returns close_status(). A local close (disconnect()
    // or `body` returning) succeeds, and a peer close succeeds only for
    // by_application. If the session was already latched when called, it
    // returns the recorded latch_ (the recorded cause, not close_status()).
    // Cancelling serve() cancels `body`, the pumps and already started
    // callbacks, and sends no DISCONNECT. An in-flight stream write is not
    // cancellable and may delay the return. Nothing is read between
    // authentication and serve(), so the peer's keepalives go unanswered until
    // it starts.
    template <class OnOpen, class OnGlobal>
    corral::Task<std::error_code> serve(OnOpen on_open, OnGlobal on_global);
    template <class OnOpen, class OnGlobal, class Body>
    corral::Task<std::error_code> serve(OnOpen on_open, OnGlobal on_global, Body body);

    corral::Task<channel_open_result> open_session_channel();
    corral::Task<channel_open_result> open_auth_agent();
    corral::Task<channel_open_result> open_direct_tcpip(std::string_view host, std::uint32_t port,
                                                       std::string_view originator_host,
                                                       std::uint32_t originator_port);
    corral::Task<channel_open_result> open_direct_streamlocal(std::string_view socket_path);
    corral::Task<channel_open_result> open_forwarded_tcpip(std::string_view host, std::uint32_t port,
                                                          std::string_view originator_host,
                                                          std::uint32_t originator_port);
    corral::Task<channel_open_result> open_x11(std::string_view originator_host,
                                              std::uint32_t originator_port);
    corral::Task<channel_open_result> open_forwarded_streamlocal(std::string_view socket_path);

    corral::Task<std::error_code> request_tcpip_forward(std::string_view addr, std::uint32_t port,
                                                       std::uint16_t& bound);
    corral::Task<std::error_code> cancel_tcpip_forward(std::string_view addr, std::uint32_t port);
    corral::Task<std::error_code> request_streamlocal_forward(std::string_view socket_path);
    corral::Task<std::error_code> cancel_streamlocal_forward(std::string_view socket_path);
    corral::Task<std::error_code> send_global_request(std::string_view name,
                                                     std::span<const std::byte> payload,
                                                     bool want_reply);
    corral::Task<std::error_code> rekey();
    corral::Task<std::error_code> send_keepalive();

    [[nodiscard]] std::error_code failure() const noexcept;
    [[nodiscard]] std::string_view failure_detail() const noexcept;
    [[nodiscard]] const disconnect_info* disconnected() const noexcept;
    [[nodiscard]] std::string_view peer_identification() const noexcept;
    [[nodiscard]] std::span<const std::byte> session_id() const noexcept;
    [[nodiscard]] std::span<const std::byte> initial_host_key() const noexcept;
    [[nodiscard]] std::span<const std::byte> initial_kex_signature() const noexcept;
    [[nodiscard]] bool supports_hostbound_publickey() const noexcept;
    [[nodiscard]] bool supports_agent_forward() const noexcept;
    [[nodiscard]] const kex::negotiated* negotiated() const noexcept;

protected:
    using impl = session_impl;

    session() noexcept = default;
    session(session&& other) noexcept;
    session& operator=(session&& other) noexcept;
    session(core::role r, auv::stream stream, crypto::provider provider, session_options opts,
            std::pmr::memory_resource* mr);
    ~session();

    [[nodiscard]] std::error_code ready_or_closed() const;
    [[nodiscard]] std::error_code phase_ready() const;

    template <class OnOpen, class OnGlobal>
    corral::Task<void> dispatch_inbound(corral::Nursery& nursery, OnOpen& on_open,
                                       OnGlobal& on_global);

    channel make_channel(session_impl::channel_state* st);
    corral::Task<channel_open_result> open_typed_channel(channels::channel_open_spec spec);
    corral::Task<std::tuple<std::error_code, bool, std::vector<std::byte>>> wait_global_response();

    std::shared_ptr<session_impl> impl_;

    friend class channel;
    friend class inbound_channel_open;
    friend class inbound_channel_request;
    friend class inbound_global_request;
};

class client_session : public session {
public:
    client_session() noexcept = default;
    client_session(client_session&&) noexcept = default;
    client_session& operator=(client_session&&) noexcept = default;
    client_session(auv::stream stream, crypto::provider provider, client_options opts,
                   std::pmr::memory_resource* mr = memory::default_page_resource());

    template <class Verifier>
    corral::Task<std::error_code> handshake(Verifier verify);

    corral::Task<std::tuple<std::error_code, auth_result>> auth_none(std::string_view user);
    corral::Task<std::tuple<std::error_code, auth_result>> auth_password(std::string_view user,
                                                                        std::string_view password);
    // auth_result::pk_ok reports whether the server would accept `key`.
    corral::Task<std::tuple<std::error_code, auth_result>> auth_publickey_query(
        std::string_view user, const keys::public_key& key);
    corral::Task<std::tuple<std::error_code, auth_result>> auth_publickey(
        std::string_view user, const keys::private_key& key);
    template <publickey_signer Signer>
    corral::Task<std::tuple<std::error_code, auth_result>> auth_publickey(
        std::string_view user, const keys::public_key& key, Signer signer);
    template <class Responder>
    corral::Task<std::tuple<std::error_code, auth_result>> auth_keyboard_interactive(
        std::string_view user, Responder responder);

private:
    // `begin` queues the method's first USERAUTH_REQUEST and returns its error.
    template <class Begin>
    corral::Task<std::tuple<std::error_code, auth_result>> authenticate_with(Begin begin);
};

class server_session : public session {
public:
    server_session() noexcept = default;
    server_session(server_session&&) noexcept = default;
    server_session& operator=(server_session&&) noexcept = default;
    server_session(auv::stream stream, crypto::provider provider, server_options opts,
                   std::pmr::memory_resource* mr = memory::default_page_resource());

    corral::Task<std::error_code> handshake();
    template <class Authenticator>
    corral::Task<std::error_code> authenticate(Authenticator authenticator);
};

// Handler for serve() that rejects every inbound channel open and global request.
struct reject_inbound_t {
    corral::Task<void> operator()(inbound_channel_open) const { co_return; }
    corral::Task<void> operator()(inbound_global_request) const { co_return; }
};
inline constexpr reject_inbound_t reject_inbound{};

namespace detail {
[[nodiscard]] inline bool session_idle(const session_impl* p) noexcept {
    return p == nullptr || (!p->reading_ && !p->writing_);
}
}  // namespace detail

inline session::session(session&& other) noexcept {
    assert(detail::session_idle(impl_.get()) && detail::session_idle(other.impl_.get()));
    impl_ = std::move(other.impl_);
}

inline session& session::operator=(session&& other) noexcept {
    if (this != &other) {
        assert(detail::session_idle(impl_.get()) && detail::session_idle(other.impl_.get()));
        impl_ = std::move(other.impl_);
    }
    return *this;
}

inline session::session(core::role r, auv::stream stream, crypto::provider provider,
                        session_options opts, std::pmr::memory_resource* mr)
    : impl_(std::make_shared<session_impl>(r, std::move(stream), provider, std::move(opts), mr)) {}

inline session::~session() {
    assert(detail::session_idle(impl_.get()));
    if (impl_) impl_->reject_pending_inbound();
}

inline session::operator bool() const noexcept {
    return static_cast<bool>(impl_);
}

inline std::error_code session::failure() const noexcept {
    if (!impl_) return code::invalid_state;
    return impl_->latch_;
}

inline std::string_view session::failure_detail() const noexcept {
    if (!impl_ || !impl_->latch_) return {};
    return impl_->latch_detail_;
}

inline const disconnect_info* session::disconnected() const noexcept {
    if (!impl_ || !impl_->have_disc_) return nullptr;
    return &impl_->disc_;
}

inline std::string_view session::peer_identification() const noexcept {
    if (!impl_) return {};
    return impl_->core_.peer_identification();
}

inline std::span<const std::byte> session::session_id() const noexcept {
    if (!impl_) return {};
    return impl_->core_.session_id();
}

inline std::span<const std::byte> session::initial_host_key() const noexcept {
    if (!impl_) return {};
    return impl_->core_.initial_host_key();
}

inline std::span<const std::byte> session::initial_kex_signature() const noexcept {
    if (!impl_) return {};
    return impl_->core_.initial_kex_signature();
}

inline bool session::supports_hostbound_publickey() const noexcept {
    return impl_ && impl_->core_.supports_hostbound_publickey();
}

inline bool session::supports_agent_forward() const noexcept {
    return impl_ && impl_->core_.supports_agent_forward();
}

inline const kex::negotiated* session::negotiated() const noexcept {
    if (!impl_) return nullptr;
    return impl_->core_.negotiated();
}

inline corral::Task<void> session::disconnect(disconnect_reason reason,
                                              std::string_view description) {
    if (!impl_) co_return;
    auto& self = *impl_;
    self.close_locally(reason, description);
    // A phase's write pump is already the only writer. Wait for it to drain
    // the DISCONNECT. If that phase is then cancelled, the pump's guard
    // clears writing_ and this returns without a second writer.
    if (self.writing_) {
        while (self.writing_) co_await self.written_lot_.park();
        co_return;
    }
    const bool stop = true;
    co_await self.write_pump(stop);
}

inline corral::Event::Awaiter session::until_closed() { return impl_->closed_ev_.get(); }

inline client_session::client_session(auv::stream stream, crypto::provider provider,
                                      client_options opts, std::pmr::memory_resource* mr) {
    auto on_banner = std::move(opts.on_banner);
    impl_ = std::make_shared<session_impl>(core::role::client, std::move(stream), provider,
                                           std::move(opts), mr, std::string{}, std::string{},
                                           std::string{}, std::move(on_banner));
}

inline server_session::server_session(auv::stream stream, crypto::provider provider,
                                      server_options opts, std::pmr::memory_resource* mr) {
    auto keys = std::move(opts.host_keys);
    auto banner = std::move(opts.auth_banner);
    auto banner_lang = std::move(opts.auth_banner_language);
    auto pubkey_algs = std::move(opts.accepted_publickey_algorithms);
    impl_ = std::make_shared<session_impl>(
        core::role::server, std::move(stream), provider, std::move(opts), mr, std::move(banner),
        std::move(banner_lang), std::move(pubkey_algs),
        std::function<void(std::string_view, std::string_view)>{});
    if (keys.empty()) {
        impl_->latch(code::invalid_state);
        return;
    }
    std::vector<core::connection::host_key_spec> specs;
    specs.reserve(keys.size());
    for (auto& k : keys) {
        specs.push_back({k.pub().blob(), k.material()});
    }
    if (auto ec = impl_->core_.set_host_keys(specs)) {
        impl_->note_core_failure();
        impl_->latch(ec);
    }
}

inline std::error_code session::ready_or_closed() const {
    if (!impl_) return code::invalid_state;
    if (impl_->latch_) return impl_->latch_;
    if (!impl_->serving_) return code::invalid_state;
    return {};
}

inline std::error_code session::phase_ready() const {
    if (!impl_) return code::invalid_state;
    if (impl_->latch_) return impl_->latch_;
    if (impl_->reading_ || impl_->writing_) return code::invalid_state;
    return {};
}

template <class Verifier>
inline corral::Task<std::error_code> client_session::handshake(Verifier verify) {
    if (auto ec = phase_ready()) co_return ec;
    co_return co_await impl_->run_phase([&]() -> corral::Task<std::error_code> {
        auto& self = *impl_;
        while (!self.closed()) {
            if (self.hs_done_) co_return {};
            if (self.auth_ && self.auth_->pending_verify) {
                host_key_view view{self.auth_->pending_verify->key, self.provider_};
                core::host_key_ticket ticket = self.auth_->pending_verify->ticket;
                const bool ok = co_await verify(view);
                if (self.closed()) co_return failure();
                auto ec = self.core_.resolve(ticket, ok ? core::host_key_verdict::accept
                                                        : core::host_key_verdict::reject);
                self.auth_->pending_verify.reset();
                self.wake_pumps();
                if (!ok) {
                    self.latch(code::host_key_rejected);
                    co_return code::host_key_rejected;
                }
                if (ec) {
                    self.note_core_failure();
                    self.latch(ec);
                    co_return ec;
                }
                continue;
            }
            co_await self.inbound_lot_.park();
        }
        co_return failure();
    });
}

inline corral::Task<std::error_code> server_session::handshake() {
    if (auto ec = phase_ready()) co_return ec;
    co_return co_await impl_->run_phase([this]() -> corral::Task<std::error_code> {
        auto& self = *impl_;
        for (;;) {
            if (self.hs_done_) co_return {};
            if (self.closed()) co_return failure();
            co_await self.inbound_lot_.park();
        }
    });
}

inline channel session::make_channel(session_impl::channel_state* st) {
    return channel{impl_, st};
}

inline corral::Task<channel_open_result> session::open_typed_channel(
    channels::channel_open_spec spec) {
    channel_open_result r;
    if (auto ec = ready_or_closed()) {
        r.ec = ec;
        co_return r;
    }
    auto& self = *impl_;
    auto* st = new session_impl::channel_state{};
    st->refs = 2;
    self.live_channels_.push_back(*st);

    core::channel_ref ref{};
    if (auto ec = self.core_.open_channel(spec, st, ref)) {
        self.note_core_failure();
        self.release(st);
        self.release(st);
        r.ec = ec;
        co_return r;
    }
    st->ref = ref;
    self.wake_pumps();

    struct abandon_guard {
        session_impl* self;
        core::channel_ref ref;
        session_impl::channel_state* st;
        bool done = false;
        ~abandon_guard() {
            if (!done && self) {
                if (st != nullptr) self->release(st);
                (void)self->core_.abandon_open(ref);
            }
        }
    } g{&self, ref, st};

    for (;;) {
        if (self.closed()) {
            g.done = true;
            g.st = nullptr;
            const bool confirmed = st->open && !st->open->failed;
            self.release(st);
            if (confirmed) (void)self.core_.channel_close(ref);
            else (void)self.core_.abandon_open(ref);
            r.ec = failure();
            co_return r;
        }
        if (st->open) {
            g.done = true;
            auto outcome = std::move(*st->open);
            st->open.reset();
            if (outcome.failed) {
                self.release(st);
                g.st = nullptr;
                r.ec = code::request_denied;
                r.reason = outcome.reason;
                r.description = std::move(outcome.description);
                co_return r;
            }
            r.ch = make_channel(st);
            co_return r;
        }
        co_await st->open_lot.park();
    }
}

inline corral::Task<channel_open_result> session::open_session_channel() {
    return open_typed_channel(channels::channel_open_spec{});
}

inline corral::Task<channel_open_result> session::open_auth_agent() {
    channels::channel_open_spec spec;
    spec.type = channel_type::auth_agent;
    return open_typed_channel(std::move(spec));
}

inline corral::Task<channel_open_result> session::open_direct_tcpip(
    std::string_view host, std::uint32_t port, std::string_view originator_host,
    std::uint32_t originator_port) {
    channels::channel_open_spec spec;
    spec.type = channel_type::direct_tcpip;
    spec.host.assign(host.begin(), host.end());
    spec.port = port;
    spec.originator_host.assign(originator_host.begin(), originator_host.end());
    spec.originator_port = originator_port;
    return open_typed_channel(std::move(spec));
}

inline corral::Task<channel_open_result> session::open_direct_streamlocal(
    std::string_view socket_path) {
    channels::channel_open_spec spec;
    spec.type = channel_type::direct_streamlocal;
    spec.socket_path.assign(socket_path.begin(), socket_path.end());
    return open_typed_channel(std::move(spec));
}

inline corral::Task<channel_open_result> session::open_forwarded_tcpip(
    std::string_view host, std::uint32_t port, std::string_view originator_host,
    std::uint32_t originator_port) {
    channels::channel_open_spec spec;
    spec.type = channel_type::forwarded_tcpip;
    spec.host.assign(host.begin(), host.end());
    spec.port = port;
    spec.originator_host.assign(originator_host.begin(), originator_host.end());
    spec.originator_port = originator_port;
    return open_typed_channel(std::move(spec));
}

inline corral::Task<channel_open_result> session::open_x11(std::string_view originator_host,
                                                          std::uint32_t originator_port) {
    channels::channel_open_spec spec;
    spec.type = channel_type::x11;
    spec.originator_host.assign(originator_host.begin(), originator_host.end());
    spec.originator_port = originator_port;
    return open_typed_channel(std::move(spec));
}

inline corral::Task<channel_open_result> session::open_forwarded_streamlocal(
    std::string_view socket_path) {
    channels::channel_open_spec spec;
    spec.type = channel_type::forwarded_streamlocal;
    spec.socket_path.assign(socket_path.begin(), socket_path.end());
    return open_typed_channel(std::move(spec));
}

inline corral::Task<std::tuple<std::error_code, bool, std::vector<std::byte>>>
session::wait_global_response() {
    auto& self = *impl_;
    session_impl::reply_waiter waiter;
    waiter.seq = self.next_global_send_seq_++;
    self.global_waiters_.push_back(waiter);

    for (;;) {
        if (self.closed()) {
            waiter.done = true;
            co_return {failure(), false, {}};
        }
        if (waiter.done) {
            if (waiter.from_reply) {
                co_return {std::error_code{}, waiter.success, std::move(waiter.payload)};
            }
            co_return {code::invalid_state, false, {}};
        }
        co_await waiter.ready;
    }
}

inline corral::Task<std::error_code> session::send_global_request(
    std::string_view name, std::span<const std::byte> payload, bool want_reply) {
    if (auto ec = ready_or_closed()) co_return ec;
    auto& self = *impl_;
    if (auto ec = self.core_.send_global_request(name, payload, want_reply)) {
        self.note_core_failure();
        co_return ec;
    }
    self.wake_pumps();
    if (!want_reply) co_return {};
    auto [ec, success, resp] = co_await wait_global_response();
    if (ec) co_return ec;
    co_return success ? std::error_code{} : code::request_denied;
}

inline corral::Task<std::error_code> session::rekey() {
    if (auto ec = ready_or_closed()) co_return ec;
    auto& self = *impl_;
    const auto gen = self.rekey_gen_;
    if (auto ec = self.core_.rekey()) {
        self.note_core_failure();
        co_return ec;
    }
    self.wake_pumps();
    while (self.rekey_gen_ == gen) {
        if (self.closed()) co_return failure();
        co_await self.rekey_lot_.park();
    }
    co_return {};
}

inline corral::Task<std::error_code> session::send_keepalive() {
    return send_global_request("keepalive@openssh.com", {}, true);
}

inline corral::Task<std::error_code> session::request_tcpip_forward(std::string_view addr,
                                                                   std::uint32_t port,
                                                                   std::uint16_t& bound) {
    if (auto ec = ready_or_closed()) co_return ec;
    auto& self = *impl_;
    if (auto ec = self.core_.request_tcpip_forward(addr, port)) {
        self.note_core_failure();
        co_return ec;
    }
    self.wake_pumps();
    auto [ec, success, payload] = co_await wait_global_response();
    if (ec) co_return ec;
    if (!success) co_return code::request_denied;
    if (payload.empty()) {
        bound = static_cast<std::uint16_t>(port);
        co_return {};
    }
    wire::reader r{payload};
    std::uint32_t p = 0;
    if (!r.read_uint32(p) || !r.empty() || p > 65535u) {
        co_return code::invalid_format;
    }
    bound = static_cast<std::uint16_t>(p);
    co_return {};
}

inline corral::Task<std::error_code> session::cancel_tcpip_forward(std::string_view addr,
                                                                  std::uint32_t port) {
    if (auto ec = ready_or_closed()) co_return ec;
    auto& self = *impl_;
    if (auto ec = self.core_.cancel_tcpip_forward(addr, port)) {
        self.note_core_failure();
        co_return ec;
    }
    self.wake_pumps();
    auto [ec, success, payload] = co_await wait_global_response();
    if (ec) co_return ec;
    co_return success ? std::error_code{} : code::request_denied;
}

inline corral::Task<std::error_code> session::request_streamlocal_forward(std::string_view socket_path) {
    if (auto ec = ready_or_closed()) co_return ec;
    auto& self = *impl_;
    if (auto ec = self.core_.request_streamlocal_forward(socket_path)) {
        self.note_core_failure();
        co_return ec;
    }
    self.wake_pumps();
    auto [ec, success, payload] = co_await wait_global_response();
    if (ec) co_return ec;
    co_return success ? std::error_code{} : code::request_denied;
}

inline corral::Task<std::error_code> session::cancel_streamlocal_forward(std::string_view socket_path) {
    if (auto ec = ready_or_closed()) co_return ec;
    auto& self = *impl_;
    if (auto ec = self.core_.cancel_streamlocal_forward(socket_path)) {
        self.note_core_failure();
        co_return ec;
    }
    self.wake_pumps();
    auto [ec, success, payload] = co_await wait_global_response();
    if (ec) co_return ec;
    co_return success ? std::error_code{} : code::request_denied;
}

template <class OnOpen, class OnGlobal>
inline corral::Task<std::error_code> session::serve(OnOpen on_open, OnGlobal on_global) {
    if (!impl_) return corral::just(code::invalid_state);
    return serve(on_open, on_global, [this] { return until_closed(); });
}

template <class OnOpen, class OnGlobal, class Body>
inline corral::Task<std::error_code> session::serve(OnOpen on_open, OnGlobal on_global,
                                                    Body body) {
    if (!impl_) co_return code::invalid_state;
    auto& self = *impl_;
    if (self.latch_) co_return self.latch_;
    if (self.reading_ || self.writing_ || !self.hs_done_ || self.auth_) {
        co_return code::invalid_state;
    }
    // Cancelling serve() cancels the pumps and the body; only a stream write
    // that cannot be cancelled may delay the return. No DISCONNECT is sent.
    CORRAL_TRY {
        self.serving_ = true;
        co_await self.run_phase([&]() -> corral::Task<std::monostate> {
            CORRAL_WITH_NURSERY(n) {
                n.start([&]() -> corral::Task<void> {
                    co_await dispatch_inbound(n, on_open, on_global);
                });
                co_await body();
                if (!self.closed()) self.close_locally(disconnect_reason::by_application, {});
                co_return corral::join;
            };
            co_return {};
        });
    }
    CORRAL_FINALLY {
        self.serving_ = false;
        self.latch(code::session_closed);
        co_return;
    };
    co_return self.close_status();
}

template <class OnOpen, class OnGlobal>
inline corral::Task<void> session::dispatch_inbound(corral::Nursery& nursery, OnOpen& on_open,
                                                   OnGlobal& on_global) {
    auto& self = *impl_;
    while (!self.closed()) {
        if (auto open = self.take_pending_open()) {
            co_await nursery.start([&](corral::TaskStarted<> st) -> corral::Task<void> {
                inbound_channel_open handle{*impl_, impl_, std::move(*open)};
                st();
                co_await on_open(std::move(handle));
            });
            continue;
        }
        if (auto g = self.take_pending_global()) {
            inbound_global_request req{self, std::move(*g)};
            co_await on_global(std::move(req));
            self.wake_pumps();
            continue;
        }
        co_await self.inbound_lot_.park();
    }
}

template <class Begin>
inline corral::Task<std::tuple<std::error_code, auth_result>> client_session::authenticate_with(
    Begin begin) {
    if (auto ec = phase_ready()) co_return std::tuple{ec, auth_result{}};
    co_return co_await impl_->run_phase(
        [&]() -> corral::Task<std::tuple<std::error_code, auth_result>> {
            auto& self = *impl_;
            if (!self.auth_) co_return {code::invalid_state, {}};
            if (!self.auth_->client_auth_outstanding) {
                if (auto ec = begin()) {
                    self.note_core_failure();
                    co_return {ec, {}};
                }
                self.auth_->client_auth_outstanding = true;
                self.wake_pumps();
            }
            co_return co_await self.wait_auth_response();
        });
}

inline corral::Task<std::tuple<std::error_code, auth_result>> client_session::auth_none(
    std::string_view user) {
    return authenticate_with([this, user] { return impl_->core_.auth_none(user); });
}

inline corral::Task<std::tuple<std::error_code, auth_result>> client_session::auth_password(
    std::string_view user, std::string_view password) {
    return authenticate_with(
        [this, user, password] { return impl_->core_.auth_password(user, password); });
}

inline corral::Task<std::tuple<std::error_code, auth_result>> client_session::auth_publickey_query(
    std::string_view user, const keys::public_key& key) {
    return authenticate_with([this, user, key = &key] {
        return impl_->core_.auth_publickey_query(user, key->blob());
    });
}

inline corral::Task<std::tuple<std::error_code, auth_result>> client_session::auth_publickey(
    std::string_view user, const keys::private_key& key) {
    return authenticate_with([this, user, key = &key] {
        return impl_->core_.auth_publickey(user, key->pub().blob(), key->material());
    });
}

template <publickey_signer Signer>
inline corral::Task<std::tuple<std::error_code, auth_result>> client_session::auth_publickey(
    std::string_view user, const keys::public_key& key, Signer signer) {
    if (auto ec = phase_ready()) co_return std::tuple{ec, auth_result{}};
    co_return co_await impl_->run_phase(
        [&]() -> corral::Task<std::tuple<std::error_code, auth_result>> {
            auto& self = *impl_;
            if (!self.auth_) co_return {code::invalid_state, {}};
            if (!self.auth_->client_auth_outstanding) {
                core::publickey_sign_request req;
                wire::writer data;
                if (auto ec = self.core_.auth_publickey_sign_request(user, key.blob(), req, data)) {
                    self.note_core_failure();
                    co_return {ec, {}};
                }
                std::tuple<std::error_code, std::vector<std::byte>> signed_data =
                    co_await signer(std::as_const(req), data.data());
                if (self.closed()) co_return {failure(), {}};
                auto& [sign_ec, signature] = signed_data;
                if (sign_ec) co_return {sign_ec, {}};
                if (!self.auth_ || self.auth_->client_auth_outstanding) {
                    co_return {code::invalid_state, {}};
                }
                if (auto ec = self.core_.auth_publickey_signed(user, key.blob(), signature)) {
                    self.note_core_failure();
                    co_return {ec, {}};
                }
                self.auth_->client_auth_outstanding = true;
                self.wake_pumps();
            }
            co_return co_await self.wait_auth_response();
        });
}

template <class Responder>
inline corral::Task<std::tuple<std::error_code, auth_result>>
client_session::auth_keyboard_interactive(std::string_view user, Responder responder) {
    if (auto ec = phase_ready()) co_return std::tuple{ec, auth_result{}};
    co_return co_await impl_->run_phase(
        [&]() -> corral::Task<std::tuple<std::error_code, auth_result>> {
            auto& self = *impl_;
            if (!self.auth_) co_return {code::invalid_state, {}};
            if (!self.auth_->client_auth_outstanding) {
                if (auto ec = self.core_.auth_keyboard_interactive(user)) {
                    self.note_core_failure();
                    co_return {ec, {}};
                }
                self.auth_->client_auth_outstanding = true;
                self.wake_pumps();
            }
            for (;;) {
                if (self.closed()) co_return {failure(), {}};
                if (self.auth_ && self.auth_->pending_auth_resp) {
                    auto r = self.take_auth_response();
                    self.auth_->client_auth_outstanding = false;
                    if (r.success) self.release_auth_stage();
                    co_return {std::error_code{}, r};
                }
                if (self.auth_ && self.auth_->pending_info_req) {
                    const std::string name = self.auth_->pending_info_req->name;
                    const std::string instruction = self.auth_->pending_info_req->instruction;
                    const std::vector<kbdint_prompt> prompts = self.auth_->pending_info_req->prompts;
                    std::vector<std::string> answers = co_await responder(
                        std::string_view{name}, std::string_view{instruction},
                        std::span<const kbdint_prompt>{prompts});
                    if (self.closed()) co_return {failure(), {}};
                    if (!self.auth_ || !self.auth_->pending_info_req) {
                        co_return {code::invalid_state, {}};
                    }
                    const core::kbdint_ticket ticket = self.auth_->pending_info_req->ticket;
                    self.auth_->pending_info_req.reset();
                    std::vector<std::string_view> views;
                    views.reserve(answers.size());
                    for (const auto& s : answers) views.emplace_back(s);
                    if (auto ec = self.core_.resolve(ticket, views)) {
                        self.note_core_failure();
                        self.latch(ec);
                        co_return {ec, {}};
                    }
                    self.wake_pumps();
                    continue;
                }
                co_await self.inbound_lot_.park();
            }
        });
}

template <class Authenticator>
inline corral::Task<std::error_code> server_session::authenticate(Authenticator authenticator) {
    if (auto ec = phase_ready()) co_return ec;
    co_return co_await impl_->run_phase(
        [&]() -> corral::Task<std::error_code> {
            auto& self = *impl_;
            if (!self.auth_) co_return code::invalid_state;
            for (;;) {
                if (self.closed()) co_return failure();
                if (self.auth_ && self.auth_->pending_auth_req) {
                    auth_request req;
                    req.impl_ = &self;
                    req.ticket_ = self.auth_->pending_auth_req->ticket;
                    req.user_ = self.auth_->pending_auth_req->user;
                    req.service_ = self.auth_->pending_auth_req->service;
                    req.method_ = self.auth_->pending_auth_req->method;
                    req.has_signature_ = self.auth_->pending_auth_req->has_signature;
                    req.algorithm_ = self.auth_->pending_auth_req->algorithm;
                    req.public_blob_ = self.auth_->pending_auth_req->public_blob;
                    req.password_ = std::move(self.auth_->pending_auth_req->password);
                    const bool unsigned_publickey =
                        auth::is_publickey_method(req.method()) && !req.has_signature();
                    self.auth_->auth_callback_live = true;
                    auth_verdict v = co_await authenticator(std::move(req));
                    self.auth_->auth_callback_live = false;
                    self.auth_->challenge_outstanding = false;
                    // A transport close only latches the facade, so core would
                    // still accept and send the verdict.
                    if (self.closed()) co_return failure();
                    if (v.kind == auth::verdict_kind::info) {
                        v = auth_verdict::failure(self.auth_->pending_auth_req->method);
                    }
                    const core::auth_ticket ticket = self.auth_->pending_auth_req->ticket;
                    if (auto ec = self.core_.resolve(ticket, v)) {
                        self.note_core_failure();
                        self.latch(ec);
                        co_return ec;
                    }
                    self.auth_->pending_auth_req.reset();
                    self.wake_pumps();
                    // Unsigned publickey success is USERAUTH_PK_OK, not authenticated.
                    if (v.kind == auth::verdict_kind::success && !unsigned_publickey) {
                        self.release_auth_stage();
                        co_return {};
                    }
                    continue;
                }
                co_await self.inbound_lot_.park();
            }
        });
}

inline corral::Task<std::tuple<std::error_code, std::vector<crypto::secure_string>>>
auth_request::challenge(std::string_view name, std::string_view instruction,
                        std::span<const kbdint_prompt> prompts) {
    if (!impl_ || !impl_->auth_ || !impl_->auth_->auth_callback_live
        || method_ != auth::method_kbdint) {
        co_return std::make_tuple(code::invalid_state, std::vector<crypto::secure_string>{});
    }
    auto& self = *impl_;
    if (self.closed()) {
        co_return std::make_tuple(self.latch_, std::vector<crypto::secure_string>{});
    }
    if (!self.auth_->challenge_outstanding) {
        (void)self.core_.resolve(ticket_, auth_verdict::info(name, instruction, prompts));
        self.note_core_failure();
        self.wake_pumps();
        self.auth_->challenge_outstanding = true;
    }
    for (;;) {
        if (self.closed()) {
            co_return std::make_tuple(self.latch_, std::vector<crypto::secure_string>{});
        }
        if (self.auth_ && self.auth_->pending_info_resp) {
            auto answers = std::move(self.auth_->pending_info_resp->responses);
            self.auth_->pending_info_resp.reset();
            self.auth_->challenge_outstanding = false;
            co_return std::make_tuple(std::error_code{}, std::move(answers));
        }
        co_await self.inbound_lot_.park();
    }
}

inline corral::Task<std::tuple<std::error_code, crypto::secure_string>> auth_request::challenge(
    std::string_view prompt, bool echo, std::string_view name, std::string_view instruction) {
    kbdint_prompt one;
    one.prompt.assign(prompt.begin(), prompt.end());
    one.echo = echo;
    auto [ec, answers] =
        co_await challenge(name, instruction, std::span<const kbdint_prompt>{&one, 1});
    if (ec) co_return std::make_tuple(ec, crypto::secure_string{});
    if (answers.empty()) co_return std::make_tuple(std::error_code{}, crypto::secure_string{});
    co_return std::make_tuple(std::error_code{}, std::move(answers.front()));
}
}  // namespace yanterm::ssh
