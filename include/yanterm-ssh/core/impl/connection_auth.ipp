#pragma once

#include <yanterm-ssh/core/connection.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/core/impl/connection_auth.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/core/detail/auth_signature.hpp>
#include <yanterm-ssh/wire/detail/messages.hpp>
#include <yanterm-ssh/wire/types.hpp>
#include <yanterm-ssh/detail/error.hpp>

#include <cassert>
#include <limits>

namespace yanterm::ssh::core::detail {

// Page-local secret wipes. Kept as inline detail functions: an anonymous
// namespace in this .ipp is rejected by the source-layout check (I-5).

[[nodiscard]] YANTERM_SSH_INLINE std::span<std::byte> mutable_secret_field(
    memory::detail::page_slice* page, std::string_view field) {
    if (page == nullptr || field.empty()) return {};
    const auto page_bytes = page->bytes();
    const auto* page_begin = page_bytes.data();
    const auto* field_begin = reinterpret_cast<const std::byte*>(field.data());
    if (field_begin < page_begin || field_begin + field.size() > page_begin + page_bytes.size()) {
        return {};
    }
    const std::size_t off = static_cast<std::size_t>(field_begin - page_begin);
    return page->mutable_bytes().subspan(off, field.size());
}

YANTERM_SSH_INLINE void secure_zero_field(memory::detail::page_slice* page,
                                          std::string_view field) noexcept {
    if (auto bytes = mutable_secret_field(page, field); !bytes.empty()) {
        crypto::secure_zero(bytes);
    }
}

// Zeros caller-owned page spans when the guard leaves scope, including when a
// notify callback throws. The span-of-spans overload views storage the caller
// keeps alive; the single-span overload keeps its view in `one_`.
class secret_wipe_guard {
public:
    explicit secret_wipe_guard(std::span<std::byte> bytes) noexcept
        : one_{bytes}
        , spans_{bytes.empty() ? std::span<const std::span<std::byte>>{}
                               : std::span<const std::span<std::byte>>{&one_, 1}} {}

    explicit secret_wipe_guard(std::span<const std::span<std::byte>> spans) noexcept : spans_{spans} {}

    secret_wipe_guard(const secret_wipe_guard&) = delete;
    secret_wipe_guard& operator=(const secret_wipe_guard&) = delete;

    ~secret_wipe_guard() noexcept {
        for (auto bytes : spans_) crypto::secure_zero(bytes);
    }

private:
    std::span<std::byte> one_{};
    std::span<const std::span<std::byte>> spans_{};
};

YANTERM_SSH_INLINE void push_service_packet(wire::msg id, std::string_view name,
                                            std::vector<std::byte>& scratch) {
    wire::detail::service_msg msg;
    msg.id = id;
    msg.service_name = name;
    wire::writer w;
    msg.encode(w);
    scratch.assign(w.data().begin(), w.data().end());
}

}  // namespace yanterm::ssh::core::detail

namespace yanterm::ssh::core {

YANTERM_SSH_INLINE bool auth_resolve_error_is_fatal(std::error_code ec) noexcept {
    return ec && ec != code::invalid_state;
}

YANTERM_SSH_INLINE std::error_code connection::resolve(auth_ticket ticket, const auth::auth_verdict& v) {
    // Auth packets are control packets: during rekey write_control_packet holds
    // them until NEWKEYS, so auth calls and resolves are accepted then too.
    if (!auth_ || !app_traffic_ok()) return code::invalid_state;
    if (role_ != role::server) return code::invalid_state;
    if (auto ec = auth_resolve_verdict(ticket.seq_, v)) {
        if (auth_resolve_error_is_fatal(ec)) {
            fail(ec);
            phase_ = phase::dead;
        }
        return ec;
    }
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::resolve(kbdint_ticket ticket, std::span<const std::string_view> responses) {
    if (!auth_ || !app_traffic_ok()) return code::invalid_state;
    if (auto ec = auth_resolve_kbdint(ticket.seq_, responses)) {
        if (auth_resolve_error_is_fatal(ec)) {
            fail(ec);
            phase_ = phase::dead;
        }
        return ec;
    }
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::send_service_request() {
    std::vector<std::byte> scratch;
    detail::push_service_packet(wire::msg::service_request, auth::service_userauth, scratch);
    return write_control_packet(scratch);
}

YANTERM_SSH_INLINE std::error_code connection::on_service_message(wire::msg id,
                                                                 std::span<const std::byte> payload) {
    assert(auth_);
    const wire::msg expected =
        role_ == role::client ? wire::msg::service_accept : wire::msg::service_request;
    if (id != expected) return code::unexpected_message;
    wire::detail::service_msg msg;
    msg.id = id;
    wire::reader r{payload};
    if (!msg.decode(r) || !r.empty()) return code::invalid_format;

    if (role_ == role::client) {
        if (msg.service_name != auth::service_userauth) return code::unsupported_service;
        return emit_handshake_done();
    }

    if (msg.service_name != auth::service_userauth) {
        wire::detail::disconnect_msg disc;
        disc.reason = wire::disconnect_reason::service_not_available;
        disc.description = "unsupported service";
        wire::writer w;
        disc.encode(w);
        if (auto ec = write_control_packet(w.data())) return ec;
        return code::unsupported_service;
    }
    std::vector<std::byte> scratch;
    detail::push_service_packet(wire::msg::service_accept, auth::service_userauth, scratch);
    if (auto ec = write_control_packet(scratch)) return ec;
    if (!auth_->banner.empty()) {
        wire::detail::userauth_banner banner;
        banner.message = auth_->banner;
        banner.language = auth_->banner_language;
        wire::writer w;
        banner.encode(w);
        if (auto ec = write_control_packet(w.data())) return ec;
    }
    return emit_handshake_done();
}

YANTERM_SSH_INLINE std::error_code connection::auth_none(std::string_view user) {
    return auth_client_start(auth::method_none, false, [&]() -> std::error_code {
        wire::detail::userauth_request_none msg;
        msg.user = user;
        msg.service = auth::service_connection;
        wire::writer w;
        msg.encode(w);
        return write_control_packet(w.data());
    });
}

YANTERM_SSH_INLINE std::error_code connection::auth_password(std::string_view user, std::string_view password) {
    return auth_client_start(auth::method_password, false, [&]() -> std::error_code {
        wire::detail::userauth_request_password msg;
        msg.user = user;
        msg.service = auth::service_connection;
        msg.password = password;
        constexpr std::string_view method = "password";
        const std::size_t encoded_bytes = 1u
            + wire::encoded_string_size(user.size())
            + wire::encoded_string_size(auth::service_connection.size())
            + wire::encoded_string_size(method.size())
            + 1u
            + wire::encoded_string_size(password.size());
        struct wiping_writer {
            wire::writer w;
            ~wiping_writer() {
                auto held = w.take();
                crypto::secure_zero(std::span<std::byte>{held});
            }
        } enc;
        enc.w.reserve(encoded_bytes);
        msg.encode(enc.w);
        assert(enc.w.size() <= encoded_bytes);
        return write_control_packet(enc.w.data());
    });
}

YANTERM_SSH_INLINE std::error_code connection::send_auth_banner(std::string_view text, std::string_view language) {
    if (!auth_ || !service_ready_ || !app_traffic_ok()) return code::invalid_state;
    if (role_ != role::server) return code::invalid_state;
    const auto ap = auth_->phase;
    if (ap != detail::auth_phase::ready && ap != detail::auth_phase::wait_app
        && ap != detail::auth_phase::wait_userauth_reply) {
        return code::invalid_state;
    }
    wire::detail::userauth_banner msg;
    msg.message = text;
    msg.language = language;
    wire::writer payload;
    msg.encode(payload);
    return write_control_packet(payload.data());
}

YANTERM_SSH_INLINE std::error_code connection::auth_publickey(std::string_view user, std::span<const std::byte> public_blob,
                               const crypto::private_key_material& priv) {
    return auth_client_start(auth::method_publickey, false, [&]() -> std::error_code {
        std::string alg;
        std::vector<std::byte> signature;
        if (auto err = detail::sign_userauth_publickey(
                p_, session_id_, user, public_blob, priv, server_sig_algs_, advertised_ssh_rsa(),
                sm2_userauth_sig_, alg, signature)) {
            return err;
        }
        wire::detail::userauth_request_publickey msg;
        msg.user = user;
        msg.service = auth::service_connection;
        msg.has_signature = true;
        msg.algorithm = alg;
        msg.blob = public_blob;
        msg.signature = signature;
        wire::writer w;
        msg.encode(w);
        return write_control_packet(w.data());
    });
}

YANTERM_SSH_INLINE std::error_code connection::auth_publickey_query(std::string_view user, std::span<const std::byte> public_blob,
                                     std::string_view algorithm) {
    return auth_client_start(auth::method_publickey, true, [&]() -> std::error_code {
        wire::detail::userauth_request_publickey msg;
        msg.user = user;
        msg.service = auth::service_connection;
        msg.has_signature = false;
        msg.algorithm = algorithm;
        msg.blob = public_blob;
        wire::writer w;
        msg.encode(w);
        return write_control_packet(w.data());
    });
}

YANTERM_SSH_INLINE std::error_code connection::auth_keyboard_interactive(std::string_view user,
                                          std::string_view language,
                                          std::span<const std::string_view> submethods) {
    return auth_client_start(auth::method_kbdint, false, [&]() -> std::error_code {
        wire::detail::userauth_request_kbdint msg;
        msg.user = user;
        msg.service = auth::service_connection;
        msg.language = language;
        msg.out_submethods = submethods;
        wire::writer w;
        msg.encode(w);
        return write_control_packet(w.data());
    });
}

YANTERM_SSH_INLINE std::error_code connection::auth_bump_seq(std::uint64_t& seq) {
    if (seq == std::numeric_limits<std::uint64_t>::max()) return code::invalid_state;
    ++seq;
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::auth_send_failure(std::string_view methods, bool partial) {
    wire::detail::userauth_failure msg;
    const std::string_view names[] = {methods};
    msg.out_methods = names;
    msg.partial_success = partial;
    wire::writer w;
    msg.encode(w);
    return write_control_packet(w.data());
}

YANTERM_SSH_INLINE void connection::auth_notify_result() {
    auth::auth_result published = auth_->result;
    published.methods = auth_->result.success ? std::string_view{} : std::string_view{auth_->methods};
    notify([&](handler& app, connection& self) { app.on_auth_result(self, published); });
}

YANTERM_SSH_INLINE std::error_code connection::auth_resolve_verdict(std::uint64_t seq,
                                                                   const auth::auth_verdict& verdict) {
    if (seq == 0 || !auth_->auth_ticket_open || seq != auth_->auth_seq) return code::invalid_state;
    if (auth_->phase != detail::auth_phase::wait_app) return code::invalid_state;
    if (verdict.kind == auth::verdict_kind::info && auth_->method != auth::method_kbdint) {
        return code::invalid_state;
    }
    if (verdict.kind == auth::verdict_kind::success) {
        if (auth_->method == auth::method_publickey && !auth_->pk_has_signature) {
            wire::detail::userauth_pk_ok msg;
            msg.algorithm = auth_->pk_alg;
            msg.blob = auth_->pk_blob;
            wire::writer w;
            msg.encode(w);
            if (auto ec = write_control_packet(w.data())) return ec;
            auth_->auth_ticket_open = false;
            auth_->phase = detail::auth_phase::ready;
            return {};
        }
        wire::detail::userauth_success msg;
        wire::writer w;
        msg.encode(w);
        if (auto ec = write_control_packet(w.data())) return ec;
        auth_->auth_ticket_open = false;
        auth_->phase = detail::auth_phase::authenticated;
        return {};
    }
    if (verdict.kind == auth::verdict_kind::failure) {
        auth_->have_app_failure = true;
        auth_->last_failure_methods.assign(verdict.methods.begin(), verdict.methods.end());
        if (auto ec = auth_send_failure(auth_->last_failure_methods, verdict.partial_success)) return ec;
        auth_->auth_ticket_open = false;
        auth_->phase = detail::auth_phase::ready;
        return {};
    }
    if (verdict.kind == auth::verdict_kind::info) {
        std::vector<wire::detail::userauth_info_prompt> prompts;
        prompts.reserve(verdict.prompts.size());
        for (const auto& p : verdict.prompts) {
            prompts.push_back({p.prompt, p.echo});
        }
        wire::detail::userauth_info_request msg;
        msg.name = verdict.info_name;
        msg.instruction = verdict.info_instruction;
        msg.language = verdict.info_language;
        msg.prompts = prompts;
        wire::writer w;
        msg.encode(w);
        if (auto ec = write_control_packet(w.data())) return ec;
        auth_->expected_info_count = static_cast<std::uint32_t>(verdict.prompts.size());
        auth_->phase = detail::auth_phase::wait_info_response;
        return {};
    }
    return code::invalid_state;
}

YANTERM_SSH_INLINE std::error_code connection::auth_resolve_kbdint(
    std::uint64_t seq, std::span<const std::string_view> responses) {
    if (role_ != role::client) return code::invalid_state;
    if (seq == 0 || !auth_->kbdint_ticket_open || seq != auth_->kbdint_seq) return code::invalid_state;
    if (auth_->phase != detail::auth_phase::wait_app) return code::invalid_state;
    if (auth_->method != auth::method_kbdint) return code::invalid_state;
    if (responses.size() != auth_->info_prompts.size()) {
        return code::invalid_state;
    }
    wire::detail::userauth_info_response msg;
    msg.responses = responses;
    std::size_t encoded_bytes = 1u + 4u;
    for (const std::string_view response : responses) {
        encoded_bytes += wire::encoded_string_size(response.size());
    }
    struct wiping_writer {
        wire::writer w;
        ~wiping_writer() {
            auto held = w.take();
            crypto::secure_zero(std::span<std::byte>{held});
        }
    } enc;
    enc.w.reserve(encoded_bytes);
    msg.encode(enc.w);
    assert(enc.w.size() <= encoded_bytes);
    if (auto ec = write_control_packet(enc.w.data())) return ec;
    auth_->kbdint_ticket_open = false;
    auth_->phase = detail::auth_phase::wait_userauth_reply;
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::auth_on_payload(std::span<const std::byte> payload,
                                                              memory::detail::page_slice* page) {
    if (payload.empty()) return code::invalid_format;
    const auto id = static_cast<wire::msg>(std::to_integer<std::uint8_t>(payload[0]));
    if (role_ == role::client) {
        return auth_on_client_payload(id, payload, page);
    }
    return auth_on_server_payload(id, payload, page);
}

YANTERM_SSH_INLINE std::error_code connection::auth_on_client_payload(
    wire::msg id, std::span<const std::byte> payload, memory::detail::page_slice* page) {
    (void)page;
    if (id == wire::msg::userauth_banner) {
        if (auth_->phase == detail::auth_phase::authenticated) {
            return code::unexpected_message;
        }
        wire::reader r{payload};
        wire::detail::userauth_banner msg;
        if (!msg.decode(r) || !r.empty()) return code::invalid_format;
        notify([&](handler& app, connection& self) {
            app.on_auth_banner(self, msg.message, msg.language);
        });
        return {};
    }

    if (id == wire::msg::userauth_failure) {
        if (auth_->phase != detail::auth_phase::wait_userauth_reply) {
            return code::unexpected_message;
        }
        wire::reader r{payload};
        wire::detail::userauth_failure msg;
        if (!msg.decode(r) || !r.empty()) return code::invalid_format;
        auth_->methods.assign(msg.methods.raw().begin(), msg.methods.raw().end());
        auth_->result = {};
        auth_->result.success = false;
        auth_->result.partial_success = msg.partial_success;
        auth_->phase = detail::auth_phase::ready;
        auth_notify_result();
        return {};
    }

    if (id == wire::msg::userauth_success) {
        if (auth_->phase != detail::auth_phase::wait_userauth_reply) {
            return code::unexpected_message;
        }
        wire::reader r{payload};
        wire::detail::userauth_success msg;
        if (!msg.decode(r) || !r.empty()) return code::invalid_format;
        auth_->methods.clear();
        auth_->result = {};
        auth_->result.success = true;
        auth_->phase = detail::auth_phase::authenticated;
        auth_notify_result();
        return {};
    }

    if (id == wire::msg::userauth_pk_ok) {
        if (auth_->phase != detail::auth_phase::wait_userauth_reply) {
            return code::unexpected_message;
        }
        if (auth_->method == auth::method_kbdint) {
            return auth_take_info_request(payload);
        }
        if (auth_->method != auth::method_publickey || !auth_->publickey_query) {
            return code::unexpected_message;
        }
        wire::reader r{payload};
        wire::detail::userauth_pk_ok msg;
        if (!msg.decode(r) || !r.empty()) return code::invalid_format;
        auth_->methods.clear();
        auth_->result = {};
        auth_->result.success = false;
        auth_->result.pk_ok = true;
        auth_->phase = detail::auth_phase::ready;
        auth_notify_result();
        return {};
    }

    return code::unexpected_message;
}

YANTERM_SSH_INLINE std::error_code connection::auth_on_server_payload(
    wire::msg id, std::span<const std::byte> payload, memory::detail::page_slice* page) {
    if (id == wire::msg::userauth_request) {
        if (auth_->phase != detail::auth_phase::ready) return code::unexpected_message;
        wire::reader r{payload};
        std::uint8_t raw = 0;
        if (!r.read_byte(raw) || raw != static_cast<std::uint8_t>(wire::msg::userauth_request)) {
            return code::invalid_format;
        }
        std::string_view user;
        std::string_view service;
        std::string_view method;
        if (!r.read_string(user) || !r.read_string(service) || !r.read_string(method)) {
            return code::invalid_format;
        }
        auth_->user.assign(user.begin(), user.end());
        auth_->service.assign(service.begin(), service.end());
        auth_->method.assign(method.begin(), method.end());
        auth_->kbdint_submethods_raw.clear();
        auth_->kbdint_language.clear();
        std::string_view inbound_password;
        std::span<const std::byte> signature;
        if (method == auth::method_none) {
            if (!r.empty()) return code::invalid_format;
            auth_->clear_pk_fields();
        } else if (method == auth::method_password) {
            bool change = false;
            if (!r.read_bool(change) || !r.read_string(inbound_password)) {
                return code::invalid_format;
            }
            if (change) {
                std::string_view new_password;
                if (!r.read_string(new_password)) {
                    detail::secure_zero_field(page, inbound_password);
                    return code::invalid_format;
                }
                detail::secure_zero_field(page, inbound_password);
                detail::secure_zero_field(page, new_password);
                if (!r.empty()) return code::invalid_format;
                return code::unexpected_message;
            }
            if (!r.empty()) {
                detail::secure_zero_field(page, inbound_password);
                return code::invalid_format;
            }
            auth_->clear_pk_fields();
        } else if (method == auth::method_publickey) {
            bool has_sig = false;
            std::string_view alg;
            std::span<const std::byte> blob;
            if (!r.read_bool(has_sig) || !r.read_string(alg) || !r.read_string(blob)) {
                return code::invalid_format;
            }
            if (has_sig && !r.read_string(signature)) {
                return code::invalid_format;
            }
            if (!r.empty()) return code::invalid_format;
            auth_->pk_has_signature = has_sig;
            auth_->pk_alg.assign(alg.begin(), alg.end());
            auth_->pk_blob.assign(blob.begin(), blob.end());
            if (has_sig) {
                if (detail::verify_userauth_publickey(p_, session_id_, auth_->user, auth_->service,
                                                      auth_->pk_alg, auth_->pk_blob, signature)) {
                    const std::string_view methods =
                        auth_->have_app_failure ? std::string_view{auth_->last_failure_methods}
                                                : auth::method_publickey;
                    if (auto ec = auth_send_failure(methods, false)) return ec;
                    auth_->phase = detail::auth_phase::ready;
                    return {};
                }
            }
        } else if (method == auth::method_kbdint) {
            std::string_view language;
            wire::name_list submethods;
            if (!r.read_string(language) || !r.read_name_list(submethods) || !r.empty()) {
                return code::invalid_format;
            }
            auth_->kbdint_language.assign(language.begin(), language.end());
            auth_->kbdint_submethods_raw.assign(submethods.raw().begin(), submethods.raw().end());
            auth_->clear_pk_fields();
        } else {
            auth_->clear_pk_fields();
        }
        if (auto ec = auth_bump_seq(auth_->auth_seq)) return ec;
        auth_->auth_ticket_open = true;
        auth_->phase = detail::auth_phase::wait_app;
        const auth_ticket ticket{auth_->auth_seq};
        auth::auth_request_view view;
        view.user = auth_->user;
        view.service = auth_->service;
        view.method = auth_->method;
        view.has_signature = auth_->pk_has_signature;
        view.algorithm = auth_->pk_alg;
        view.public_blob = auth_->pk_blob;
        view.password = inbound_password;
        view.submethods = auth_->method == auth::method_kbdint ? auth_->kbdint_submethods_raw
                                                               : std::string_view{};
        const detail::secret_wipe_guard password_wipe{
            detail::mutable_secret_field(page, inbound_password)};
        notify([&](handler& app, connection& self) { app.on_auth_request(self, ticket, view); });
        return {};
    }

    if (id == wire::msg::userauth_info_response) {
        if (auth_->phase != detail::auth_phase::wait_info_response) {
            return code::unexpected_message;
        }
        return auth_take_info_response(payload, page);
    }

    return code::unexpected_message;
}

YANTERM_SSH_INLINE std::error_code connection::auth_take_info_request(std::span<const std::byte> payload) {
    wire::reader r{payload};
    wire::detail::userauth_info_request msg;
    if (!msg.decode(r) || !r.empty()) return code::invalid_format;
    auth_->info_prompts.clear();
    auth_->info_prompts.reserve(msg.num_prompts);
    for (std::uint32_t i = 0; i < msg.num_prompts; ++i) {
        std::string_view prompt;
        bool echo = false;
        if (!msg.prompt_at(i, prompt, echo)) return code::invalid_format;
        auth::kbdint_prompt p;
        p.prompt.assign(prompt.begin(), prompt.end());
        p.echo = echo;
        auth_->info_prompts.push_back(std::move(p));
    }
    if (auto ec = auth_bump_seq(auth_->kbdint_seq)) return ec;
    auth_->kbdint_ticket_open = true;
    auth_->phase = detail::auth_phase::wait_app;
    const kbdint_ticket ticket{auth_->kbdint_seq};
    auth::info_request_view view{msg.name, msg.instruction, msg.language, auth_->info_prompts};
    notify([&](handler& app, connection& self) { app.on_kbdint_request(self, ticket, view); });
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::auth_take_info_response(
    std::span<const std::byte> payload, memory::detail::page_slice* page) {
    wire::reader r{payload};
    wire::detail::userauth_info_response msg;
    if (!msg.decode(r) || !r.empty()) return code::invalid_format;
    if (msg.num_responses != auth_->expected_info_count) {
        for (std::uint32_t i = 0; i < msg.num_responses; ++i) {
            std::string_view v;
            if (!msg.response_at(i, v)) break;
            detail::secure_zero_field(page, v);
        }
        return code::invalid_format;
    }
    std::vector<std::span<std::byte>> wipe_storage;
    wipe_storage.reserve(msg.num_responses);
    std::vector<std::string_view> response_views;
    response_views.reserve(msg.num_responses);
    for (std::uint32_t i = 0; i < msg.num_responses; ++i) {
        std::string_view v;
        if (!msg.response_at(i, v)) {
            for (const auto bytes : wipe_storage) crypto::secure_zero(bytes);
            return code::invalid_format;
        }
        response_views.push_back(v);
        if (auto page_wipe = detail::mutable_secret_field(page, v); !page_wipe.empty()) {
            wipe_storage.push_back(page_wipe);
        }
    }
    auth_->phase = detail::auth_phase::wait_app;
    const auth_ticket ticket{auth_->auth_seq};
    const detail::secret_wipe_guard response_wipe{std::span<const std::span<std::byte>>{wipe_storage}};
    notify([&](handler& app, connection& self) {
        app.on_kbdint_response(self, ticket, response_views);
    });
    return {};
}

}  // namespace yanterm::ssh::core
