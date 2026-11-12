#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/detail/error.hpp>
#include <yanterm-ssh/agent/packets.hpp>
#include <yanterm-ssh/crypto/secure_buffer.hpp>
#include <yanterm-ssh/keys/private_key.hpp>
#include <yanterm-ssh/session.hpp>

#include <auv/error.hpp>
#include <auv/stream.hpp>

#include <corral/Event.h>
#include <corral/Semaphore.h>
#include <corral/Task.h>
#include <corral/utility.h>
#include <corral/wait.h>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <string>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

namespace yanterm::ssh {

struct agent_options {
    std::uint32_t max_message_length = agent::default_max_message_length;
};

// One ssh-agent connection. A whole request and its reply occupy the stream
// before the next request is written. The client has no background reader
// and no timeout; cancellation is the caller's coroutine cancellation.
//
// Copy and move are unavailable. signer() and every suspended call borrow
// this object at this address, so the absence of a move is not a promise
// that moving an in-flight client would be safe.
//
// A complete SSH_AGENT_FAILURE or SSH_AGENT_EXTENSION_FAILURE is returned
// and leaves the client usable. EOF, a short or illegal frame, a malformed
// body, an unexpected type, or cancellation after a write or read has
// started latches failure(); later protocol calls return that error.
// Cancellation that is still waiting for an earlier exchange does not latch
// and does not write.
template <class Stream>
class basic_agent_client {
    static_assert(auv::detail::stream_like<Stream>);

public:
    explicit basic_agent_client(Stream stream, agent_options opts = {})
        : stream_(std::move(stream)), opts_(opts) {}

    basic_agent_client(const basic_agent_client&) = delete;
    basic_agent_client& operator=(const basic_agent_client&) = delete;
    basic_agent_client(basic_agent_client&&) = delete;
    basic_agent_client& operator=(basic_agent_client&&) = delete;

    corral::Task<agent::identity_list> list_identities();
    corral::Task<sign_result> sign(std::span<const std::byte> key_blob,
                                  std::span<const std::byte> data, std::uint32_t flags = 0);

    corral::Task<std::error_code> bind_session(std::span<const std::byte> host_key,
                                              std::span<const std::byte> session_id,
                                              std::span<const std::byte> signature,
                                              bool is_forwarding = false);
    corral::Task<std::error_code> add_identity(const keys::private_key& key,
                                              std::string_view comment,
                                              const agent::key_constraints& constraints = {});
    corral::Task<std::error_code> remove_identity(std::span<const std::byte> key_blob);
    corral::Task<std::error_code> remove_all_identities();
    corral::Task<std::error_code> add_smartcard_key(std::string_view token_id,
                                                   std::string_view pin,
                                                   const agent::key_constraints& constraints = {});
    corral::Task<std::error_code> remove_smartcard_key(std::string_view token_id,
                                                      std::string_view pin);
    corral::Task<std::error_code> lock(std::string_view passphrase);
    corral::Task<std::error_code> unlock(std::string_view passphrase);
    corral::Task<agent::extension_reply> extension(std::string_view name,
                                                  std::span<const std::byte> data);
    corral::Task<agent::extension_list> query_extensions();

    class signer_adapter {
    public:
        explicit signer_adapter(basic_agent_client& client) noexcept : client_(&client) {}

        corral::Task<sign_result> operator()(const core::publickey_sign_request& request,
                                            std::span<const std::byte> data);

    private:
        basic_agent_client* client_;
    };

    [[nodiscard]] signer_adapter signer() noexcept { return signer_adapter{*this}; }

    [[nodiscard]] std::error_code failure() const noexcept { return failed_; }

private:
    template <class S>
    friend corral::Task<std::error_code> forward_agent_channel(channel& ch,
                                                              basic_agent_client<S>& agent);

    enum class reply_accept { identities, signature, bind, status, extension };

    struct raw_reply {
        std::error_code ec;
        std::vector<std::byte> payload;
    };

    corral::Task<raw_reply> exchange(std::vector<std::byte> request, reply_accept accept,
                                     std::string_view extension_name = {});
    corral::Task<raw_reply> read_frame();
    corral::Task<std::tuple<std::error_code, std::size_t>> read_some(std::span<std::byte> dst);

    void fail(std::error_code ec) {
        if (ec && !failed_) failed_ = ec;
    }

    Stream stream_;
    agent_options opts_;
    corral::Semaphore turn_{1};
    int busy_ = 0;
    bool bridging_ = false;
    std::error_code failed_;
};

using agent_client = basic_agent_client<auv::stream>;

template <class Stream>
corral::Task<std::tuple<std::error_code, std::size_t>>
basic_agent_client<Stream>::read_some(std::span<std::byte> dst) {
    auv::buffer buf{reinterpret_cast<char*>(dst.data()), dst.size()};
    auto [ec, n] = co_await stream_.read([](void* p) { return *static_cast<auv::buffer*>(p); }, &buf);
    if (ec) co_return {ec, 0};
    if (n == 0) co_return {auv::make_error_code(auv::errc::eof), 0};
    co_return {std::error_code{}, n};
}

template <class Stream>
corral::Task<typename basic_agent_client<Stream>::raw_reply>
basic_agent_client<Stream>::read_frame() {
    std::byte hdr[4];
    std::size_t got = 0;
    while (got < 4) {
        auto [ec, n] = co_await read_some(std::span<std::byte>(hdr + got, 4 - got));
        if (ec) co_return {ec, {}};
        got += n;
    }
    const auto len = agent::decode_frame_header(std::span<const std::byte>(hdr, 4));
    if (!agent::message_length_ok(len, opts_.max_message_length)) {
        co_return {code::invalid_packet_length, {}};
    }
    std::vector<std::byte> body(len);
    got = 0;
    while (got < len) {
        auto [ec, n] = co_await read_some(std::span<std::byte>(body.data() + got, len - got));
        if (ec) co_return {ec, {}};
        got += n;
    }
    co_return {std::error_code{}, std::move(body)};
}

template <class Stream>
corral::Task<typename basic_agent_client<Stream>::raw_reply>
basic_agent_client<Stream>::exchange(std::vector<std::byte> request, reply_accept accept,
                                     std::string_view extension_name) {
    raw_reply out;
    struct wipe_request {
        std::vector<std::byte>& buf;
        ~wipe_request() { crypto::secure_zero(std::span<std::byte>{buf}); }
    } wipe{request};

    if (failed_ || bridging_) {
        out.ec = failed_ ? failed_ : code::invalid_state;
        co_return out;
    }
    if (request.empty() || request.size() > opts_.max_message_length
        || request.size() > std::numeric_limits<std::uint32_t>::max()) {
        out.ec = code::invalid_argument;
        co_return out;
    }

    ++busy_;
    struct busy_leave {
        basic_agent_client* self;
        ~busy_leave() { --self->busy_; }
    };
    [[maybe_unused]] busy_leave leave{this};

    auto hold = co_await turn_.lock();
    if (failed_ || bridging_) {
        out.ec = failed_ ? failed_ : code::invalid_state;
        co_return out;
    }

    struct cancel_latch {
        basic_agent_client* self = nullptr;
        bool dismiss = false;
        ~cancel_latch() {
            if (!dismiss) self->fail(std::make_error_code(std::errc::operation_canceled));
        }
    } guard{this};

    const auto len = static_cast<std::uint32_t>(request.size());
    std::byte hdr[4] = {
        static_cast<std::byte>(len >> 24),
        static_cast<std::byte>(len >> 16),
        static_cast<std::byte>(len >> 8),
        static_cast<std::byte>(len),
    };
    auv::buffer bufs[2] = {
        {reinterpret_cast<char*>(hdr), 4},
        {reinterpret_cast<const char*>(request.data()), request.size()},
    };
    const auto wrote = co_await corral::noncancellable(stream_.write(bufs, 2));
    if (wrote) {
        fail(wrote);
        guard.dismiss = true;
        out.ec = failed_;
        co_return out;
    }

    auto reply = co_await read_frame();
    if (reply.ec) {
        fail(reply.ec);
        guard.dismiss = true;
        out.ec = failed_;
        co_return out;
    }
    auto& body = reply.payload;

    const auto type = agent::message_type(body);
    const auto refuse = [&](agent::refusal refusal) {
        out.ec = refusal;
    };
    const auto desync = [&](std::error_code ec) {
        fail(ec);
        out.ec = failed_;
    };

    if (type == agent::msg::failure && accept != reply_accept::bind) {
        if (!agent::decode_failure(body)) desync(code::invalid_format);
        else refuse(agent::refusal::failure);
    } else if (accept == reply_accept::bind && type == agent::msg::success) {
        if (!agent::decode_success(body)) desync(code::invalid_format);
    } else if (accept == reply_accept::bind && type == agent::msg::failure) {
        if (!agent::decode_failure(body)) desync(code::invalid_format);
        else refuse(agent::refusal::failure);
    } else if (accept == reply_accept::bind && type == agent::msg::extension_failure) {
        if (!agent::decode_extension_failure(body)) desync(code::invalid_format);
        else refuse(agent::refusal::extension_failure);
    } else if (accept == reply_accept::identities && type == agent::msg::identities_answer) {
        std::vector<agent::identity_view> views;
        if (!agent::decode_identities_answer(body, views)) desync(code::invalid_format);
        else out.payload = std::move(body);
    } else if (accept == reply_accept::signature && type == agent::msg::sign_response) {
        std::span<const std::byte> signature;
        if (!agent::decode_sign_response(body, signature)) desync(code::invalid_format);
        else out.payload = std::move(body);
    } else if (accept == reply_accept::status && type == agent::msg::success) {
        if (!agent::decode_success(body)) desync(code::invalid_format);
    } else if (accept == reply_accept::extension && type == agent::msg::success) {
        if (!agent::decode_success(body)) desync(code::invalid_format);
        else out.payload = std::move(body);
    } else if (accept == reply_accept::extension && type == agent::msg::extension_failure) {
        if (!agent::decode_extension_failure(body)) desync(code::invalid_format);
        else refuse(agent::refusal::extension_failure);
    } else if (accept == reply_accept::extension && type == agent::msg::extension_response) {
        std::string_view got;
        std::span<const std::byte> data;
        if (!agent::decode_extension_response(body, got, data)) desync(code::invalid_format);
        else if (got != extension_name) desync(code::unexpected_message);
        else out.payload = std::move(body);
    } else {
        desync(code::unexpected_message);
    }

    guard.dismiss = true;
    co_return out;
}

template <class Stream>
corral::Task<agent::identity_list> basic_agent_client<Stream>::list_identities() {
    wire::writer w;
    agent::encode_request_identities(w);
    auto rep = co_await exchange(w.take(), reply_accept::identities);
    if (rep.ec) co_return {rep.ec, {}};

    std::vector<agent::identity_view> views;
    if (!agent::decode_identities_answer(rep.payload, views)) {
        fail(code::invalid_format);
        co_return {failed_, {}};
    }
    std::vector<agent::identity> owned;
    owned.reserve(views.size());
    for (const auto& view : views) {
        owned.push_back(agent::identity{
            std::vector<std::byte>(view.key_blob.begin(), view.key_blob.end()),
            std::string(view.comment),
        });
    }
    co_return {std::error_code{}, std::move(owned)};
}

template <class Stream>
corral::Task<sign_result> basic_agent_client<Stream>::sign(std::span<const std::byte> key_blob,
                                                          std::span<const std::byte> data,
                                                          std::uint32_t flags) {
    wire::writer w;
    agent::encode_sign_request(w, key_blob, data, flags);
    auto rep = co_await exchange(w.take(), reply_accept::signature);
    if (rep.ec) co_return {rep.ec, {}};

    std::span<const std::byte> signature;
    if (!agent::decode_sign_response(rep.payload, signature)) {
        fail(code::invalid_format);
        co_return {failed_, {}};
    }
    co_return {std::error_code{}, std::vector<std::byte>(signature.begin(), signature.end())};
}

template <class Stream>
corral::Task<std::error_code> basic_agent_client<Stream>::bind_session(
    std::span<const std::byte> host_key, std::span<const std::byte> session_id,
    std::span<const std::byte> signature, bool is_forwarding) {
    wire::writer w;
    agent::encode_session_bind(w, host_key, session_id, signature, is_forwarding);
    auto rep = co_await exchange(w.take(), reply_accept::bind);
    co_return rep.ec;
}

template <class Stream>
corral::Task<std::error_code> basic_agent_client<Stream>::add_identity(
    const keys::private_key& key, std::string_view comment,
    const agent::key_constraints& constraints) {
    const auto material = key.material();
    const auto name = key.pub().algorithm_name();
    std::size_t key_bytes = wire::encoded_string_size(name.size()) + 16;
    if (name == "ssh-ed25519") {
        key_bytes += wire::encoded_string_size(32) + wire::encoded_string_size(64);
    } else if (!material.n.empty()) {
        key_bytes += wire::encoded_mpint_size(material.n) + wire::encoded_mpint_size(material.e)
            + wire::encoded_mpint_size(material.d) + wire::encoded_mpint_size(material.iqmp)
            + wire::encoded_mpint_size(material.p) + wire::encoded_mpint_size(material.q);
    } else {
        key_bytes += wire::encoded_string_size(name.size())
            + wire::encoded_string_size(material.public_key.size())
            + wire::encoded_mpint_size(material.seed);
    }

    struct secret_writer {
        wire::writer w;
        void wipe() noexcept {
            auto held = w.take();
            crypto::secure_zero(std::span<std::byte>{held});
        }
        ~secret_writer() { wipe(); }
    };
    secret_writer body;
    body.w.reserve(key_bytes);
    if (auto ec = keys::detail::encode_private_body(key.pub(), material, body.w)) co_return ec;

    std::size_t extra = 1 + wire::encoded_string_size(comment.size());
    if (!agent::constraints_empty(constraints)) {
        if (constraints.lifetime_seconds) extra += 5;
        if (constraints.confirm) ++extra;
        for (const auto& ext : constraints.extensions) {
            extra += 1 + wire::encoded_string_size(ext.name.size()) + ext.details.size();
        }
    }
    secret_writer request;
    request.w.reserve(body.w.size() + extra);
    agent::encode_add_identity(request.w, body.w.data(), comment, constraints);
    body.wipe();
    auto rep = co_await exchange(request.w.take(), reply_accept::status);
    co_return rep.ec;
}

template <class Stream>
corral::Task<std::error_code> basic_agent_client<Stream>::remove_identity(
    std::span<const std::byte> key_blob) {
    wire::writer w;
    agent::encode_remove_identity(w, key_blob);
    auto rep = co_await exchange(w.take(), reply_accept::status);
    co_return rep.ec;
}

template <class Stream>
corral::Task<std::error_code> basic_agent_client<Stream>::remove_all_identities() {
    wire::writer w;
    agent::encode_remove_all_identities(w);
    auto rep = co_await exchange(w.take(), reply_accept::status);
    co_return rep.ec;
}

template <class Stream>
corral::Task<std::error_code> basic_agent_client<Stream>::add_smartcard_key(
    std::string_view token_id, std::string_view pin, const agent::key_constraints& constraints) {
    std::size_t extra = 1 + wire::encoded_string_size(token_id.size())
        + wire::encoded_string_size(pin.size());
    if (!agent::constraints_empty(constraints)) {
        if (constraints.lifetime_seconds) extra += 5;
        if (constraints.confirm) ++extra;
        for (const auto& ext : constraints.extensions) {
            extra += 1 + wire::encoded_string_size(ext.name.size()) + ext.details.size();
        }
    }
    wire::writer w;
    w.reserve(extra);
    agent::encode_add_smartcard_key(w, token_id, pin, constraints);
    auto rep = co_await exchange(w.take(), reply_accept::status);
    co_return rep.ec;
}

template <class Stream>
corral::Task<std::error_code> basic_agent_client<Stream>::remove_smartcard_key(
    std::string_view token_id, std::string_view pin) {
    wire::writer w;
    w.reserve(1 + wire::encoded_string_size(token_id.size()) + wire::encoded_string_size(pin.size()));
    agent::encode_remove_smartcard_key(w, token_id, pin);
    auto rep = co_await exchange(w.take(), reply_accept::status);
    co_return rep.ec;
}

template <class Stream>
corral::Task<std::error_code> basic_agent_client<Stream>::lock(std::string_view passphrase) {
    wire::writer w;
    w.reserve(1 + wire::encoded_string_size(passphrase.size()));
    agent::encode_lock(w, passphrase);
    auto rep = co_await exchange(w.take(), reply_accept::status);
    co_return rep.ec;
}

template <class Stream>
corral::Task<std::error_code> basic_agent_client<Stream>::unlock(std::string_view passphrase) {
    wire::writer w;
    w.reserve(1 + wire::encoded_string_size(passphrase.size()));
    agent::encode_unlock(w, passphrase);
    auto rep = co_await exchange(w.take(), reply_accept::status);
    co_return rep.ec;
}

template <class Stream>
corral::Task<agent::extension_reply>
basic_agent_client<Stream>::extension(std::string_view name, std::span<const std::byte> data) {
    wire::writer w;
    agent::encode_extension(w, name, data);
    auto rep = co_await exchange(w.take(), reply_accept::extension, name);
    if (rep.ec) co_return {rep.ec, {}};
    if (agent::message_type(rep.payload) == agent::msg::success) co_return {std::error_code{}, {}};

    std::string_view got;
    std::span<const std::byte> rest;
    if (!agent::decode_extension_response(rep.payload, got, rest)) {
        fail(code::invalid_format);
        co_return {failed_, {}};
    }
    co_return {std::error_code{}, std::vector<std::byte>(rest.begin(), rest.end())};
}

template <class Stream>
corral::Task<agent::extension_list> basic_agent_client<Stream>::query_extensions() {
    wire::writer w;
    agent::encode_extension(w, agent::query_extension, {});
    auto rep = co_await exchange(w.take(), reply_accept::extension, agent::query_extension);
    if (rep.ec) co_return {rep.ec, {}};
    if (agent::message_type(rep.payload) == agent::msg::success) co_return {std::error_code{}, {}};

    std::vector<std::string> names;
    if (!agent::decode_query_response(rep.payload, names)) {
        fail(code::invalid_format);
        co_return {failed_, {}};
    }
    co_return {std::error_code{}, std::move(names)};
}

template <class Stream>
corral::Task<sign_result> basic_agent_client<Stream>::signer_adapter::operator()(
    const core::publickey_sign_request& request, std::span<const std::byte> data) {
    std::uint32_t flags = 0;
    switch (request.sig) {
    case crypto::sig_id::rsa_pkcs1_sha256: flags = agent::sign_flags::rsa_sha2_256; break;
    case crypto::sig_id::rsa_pkcs1_sha512: flags = agent::sign_flags::rsa_sha2_512; break;
    default: break;
    }
    return client_->sign(request.public_blob, data, flags);
}

template <class Stream>
corral::Task<std::error_code> bind_agent_session(basic_agent_client<Stream>& agent,
                                                const client_session& session,
                                                bool is_forwarding = false) {
    const auto host_key = session.initial_host_key();
    const auto session_id = session.session_id();
    const auto signature = session.initial_kex_signature();
    if (host_key.empty() || session_id.empty() || signature.empty()) {
        co_return code::invalid_state;
    }
    co_return co_await agent.bind_session(host_key, session_id, signature, is_forwarding);
}

template <class Stream>
corral::Task<std::tuple<std::error_code, auth_result>> auth_publickey_from_agent(
    client_session& session, std::string_view user, basic_agent_client<Stream>& agent) {
    auto [list_ec, identities] = co_await agent.list_identities();
    if (list_ec) co_return {list_ec, {}};
    if (agent.failure()) co_return {agent.failure(), {}};

    std::error_code last = code::request_denied;
    auth_result last_result{};
    bool tried = false;
    for (const auto& id : identities) {
        if (agent.failure()) co_return {agent.failure(), last_result};
        keys::public_key key;
        if (keys::public_key::parse_blob(id.key_blob, key)) continue;

        auto [query_ec, query] = co_await session.auth_publickey_query(user, key);
        if (agent.failure()) co_return {agent.failure(), query};
        if (query_ec == code::unsupported_algorithm || query_ec == code::unsupported_key_format) {
            continue;
        }
        if (query_ec) co_return {query_ec, query};
        if (!query.pk_ok) continue;

        tried = true;
        auto [auth_ec, result] = co_await session.auth_publickey(user, key, agent.signer());
        if (agent.failure()) co_return {agent.failure(), result};
        if (!auth_ec && result.success) co_return {std::error_code{}, result};
        if (!auth_ec) auth_ec = code::request_denied;
        last = auth_ec;
        last_result = result;
        if (auth_ec == agent::refusal::failure || auth_ec == agent::refusal::extension_failure
            || auth_ec == code::sign_failure || auth_ec == code::request_denied) {
            continue;
        }
        co_return {auth_ec, result};
    }
    co_return {tried ? last : code::request_denied, last_result};
}

template <class Stream>
corral::Task<std::error_code> forward_agent_channel(channel& ch, basic_agent_client<Stream>& agent) {
    if (agent.failed_) co_return agent.failed_;
    if (agent.busy_ != 0 || agent.bridging_) co_return code::invalid_state;
    agent.bridging_ = true;

    struct finish {
        basic_agent_client<Stream>* self;
        ~finish() {
            if (!self->failed_) self->failed_ = code::invalid_state;
        }
    } guard{&agent};

    [[maybe_unused]] auto hold = co_await agent.turn_.lock();
    corral::Event stop;
    auto fail = [&](std::error_code ec) {
        if (!agent.failed_) agent.failed_ = ec;
        stop.trigger();
    };
    auto pump = [&](auto& src, auto& dst) -> corral::Task<void> {
        crypto::secure_array<4096> buf;
        for (;;) {
            auv::buffer in(buf.span());
            auto [ec, nread] =
                co_await src.read([](void* p) { return *static_cast<auv::buffer*>(p); }, &in);
            if (ec && ec != auv::errc::eof) {
                fail(ec);
                co_return;
            }
            if (ec || nread == 0) {
                (void)co_await dst.shutdown();
                co_return;
            }
            auv::buffer out(buf.span().data(), nread);
            const std::size_t nbufs = 1;
            auto wec = co_await dst.write(&out, nbufs);
            if (wec) {
                fail(wec);
                co_return;
            }
            crypto::secure_zero(buf.span());
        }
    };
    (void)co_await corral::anyOf(corral::allOf(pump(ch, agent.stream_), pump(agent.stream_, ch)),
                                 stop.get());

    co_return stop.triggered() ? agent.failed_ : std::error_code{};
}

}  // namespace yanterm::ssh
