#pragma once

#include <yanterm-ssh/core/connection.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/core/impl/connection_lifecycle.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/core/detail/detail_format.hpp>
#include <yanterm-ssh/kex/detail/tables.hpp>
#include <yanterm-ssh/wire/detail/messages.hpp>
#include <yanterm-ssh/wire/types.hpp>
#include <yanterm-ssh/detail/error.hpp>

#include <cassert>

namespace yanterm::ssh::core {

YANTERM_SSH_INLINE connection::connection(role r, crypto::provider p, const config& cfg,
                                          handler& h, std::pmr::memory_resource* mr)
    : app_{h}
    , role_{r}
    , pool_{memory::default_page_size, mr}
    , p_{p}
    , cfg_{cfg}
    , version_{r, cfg.software}
    , reader_{p}
    , writer_{p}
    , slots_{cfg_.max_channels} {
    auth_ = std::make_unique<detail::auth_state>();
    auth_->banner.assign(cfg.auth_banner);
    auth_->banner_language.assign(cfg.auth_banner_language);
    if (r == role::server) {
        if (cfg.accepted_publickey_algorithms.empty()) {
            accepted_publickey_algorithms_ = kex::default_host_key_algorithms(p_);
        } else {
            for (std::string_view name : wire::name_list{cfg.accepted_publickey_algorithms}) {
                const auto* e = kex::detail::find_host_key(name);
                if (!e || !kex::detail::provider_supports_host_key(p_, *e)) continue;
                if (wire::name_list{accepted_publickey_algorithms_}.contains(e->name)) continue;
                if (!accepted_publickey_algorithms_.empty()) accepted_publickey_algorithms_.push_back(',');
                accepted_publickey_algorithms_.append(e->name);
            }
        }
    }
    const auto banner = version_.outgoing();
    push_output_bytes(banner);
}

YANTERM_SSH_INLINE void connection::on_unwind() noexcept {
    phase_ = phase::dead;
    if (!failure_) failure_ = code::invalid_state;
}

YANTERM_SSH_INLINE std::error_code connection::disconnect(wire::disconnect_reason reason, std::string_view description) {
    if (phase_ == phase::dead) return failure_ ? failure_ : code::invalid_state;
    auto ec = enqueue_disconnect(reason, description);
    phase_ = phase::dead;
    return ec;
}

YANTERM_SSH_INLINE std::error_code connection::fail(std::error_code ec, std::string detail) {
    if (!failure_) {
        failure_ = ec;
        failure_detail_ = detail::clip_failure_detail(std::move(detail));
    }
    return failure_;
}

YANTERM_SSH_INLINE std::error_code connection::fail_and_disconnect(std::error_code ec,
                                                                  wire::disconnect_reason reason,
                                                                  std::string detail) {
    auto err = fail(ec, std::move(detail));
    if (phase_ != phase::dead) {
        std::string_view description;
        switch (reason) {
        case wire::disconnect_reason::protocol_error:
            description = "Protocol error";
            break;
        case wire::disconnect_reason::key_exchange_failed:
            description = "key exchange failed";
            break;
        case wire::disconnect_reason::service_not_available:
            description = "bad service request";
            break;
        case wire::disconnect_reason::host_key_not_verifiable:
            description = "Host key verification failed.";
            break;
        case wire::disconnect_reason::host_not_allowed_to_connect:
        case wire::disconnect_reason::reserved:
        case wire::disconnect_reason::mac_error:
        case wire::disconnect_reason::compression_error:
        case wire::disconnect_reason::protocol_version_not_supported:
        case wire::disconnect_reason::connection_lost:
        case wire::disconnect_reason::by_application:
        case wire::disconnect_reason::too_many_connections:
        case wire::disconnect_reason::auth_cancelled_by_user:
        case wire::disconnect_reason::no_more_auth_methods_available:
        case wire::disconnect_reason::illegal_user_name:
            break;
        }
        (void)enqueue_disconnect(reason, description);
        phase_ = phase::dead;
    }
    return err;
}

YANTERM_SSH_INLINE std::error_code connection::enqueue_disconnect(wire::disconnect_reason reason,
                                   std::string_view description) {
    wire::detail::disconnect_msg msg;
    msg.reason = reason;
    msg.description = description;
    msg.language = {};
    wire::writer payload;
    msg.encode(payload);
    return write_packet(payload.data());
}

YANTERM_SSH_INLINE std::error_code connection::dispatch_payload(memory::detail::page_slice& pkt) {
    const auto payload = pkt.bytes();
    if (payload.empty()) return code::invalid_format;
    const auto id = static_cast<wire::msg>(std::to_integer<std::uint8_t>(payload[0]));

    // RFC 8308 §2.4: a client's EXT_INFO may only be the very next packet
    // after its first NEWKEYS, so the slot closes on whatever comes next.
    if (role_ == role::server && traffic_armed_ && !ext_info_closed_) {
        ext_info_closed_ = true;
        if (id == wire::msg::ext_info && cfg_.advertise_ext_info) {
            if (auto err = apply_ext_info(payload)) return err;
            note_inbound_packet();
            return {};
        }
    }

    if (id == wire::msg::disconnect) {
        wire::reader r{payload};
        wire::detail::disconnect_msg msg;
        if (!msg.decode(r)) {
            // The peer is already tearing down; answering would only race its close.
            fail(code::invalid_format);
            phase_ = phase::dead;
            return failure_;
        }
        fail(code::peer_disconnected);
        phase_ = phase::dead;
        notify([&](handler& app, connection& self) {
            app.on_disconnect(self, msg.reason, msg.description, msg.language);
        });
        return {};
    }

    // Strict KEX (CVE-2023-48795): once enabled, IGNORE/DEBUG/UNIMPLEMENTED
    // are forbidden for the rest of the initial KEX (until NEWKEYS is received).
    if (id == wire::msg::ignore || id == wire::msg::debug || id == wire::msg::unimplemented) {
        if (strict_kex_active_ && in_initial_kex()) return code::strict_kex_violation;
    }

    if (id == wire::msg::ignore) {
        wire::reader r{payload};
        wire::detail::ignore_msg msg;
        if (!msg.decode(r)) {
            return code::invalid_format;
        }
        notify([&](handler& app, connection& self) { app.on_ignore(self, msg.data); });
        note_inbound_packet();
        return {};
    }

    if (id == wire::msg::debug) {
        wire::reader r{payload};
        wire::detail::debug_msg msg;
        if (!msg.decode(r)) {
            return code::invalid_format;
        }
        notify([&](handler& app, connection& self) {
            app.on_debug(self, msg.always_display, msg.message, msg.language);
        });
        note_inbound_packet();
        return {};
    }

    if (id == wire::msg::unimplemented) {
        note_inbound_packet();
        return {};
    }

    if (id == wire::msg::ext_info) {
        // A client accepts server EXT_INFO any number of times from its first
        // NEWKEYS until USERAUTH_SUCCESS: RFC 8308 §2.4 allows both the
        // post-NEWKEYS and pre-USERAUTH_SUCCESS slots, and the window is
        // widened as if ext-info-in-auth@openssh.com had been sent. The
        // NEWKEYS-adjacent packet in the same feed goes through dispatch_payload.
        if (role_ == role::client && traffic_armed_ && !authenticated()) {
            note_inbound_packet();
            return apply_ext_info(payload);
        }
        return code::unexpected_message;
    }

    // First binary packet must be KEXINIT when we advertise strict.
    if (phase_ == phase::wait_kexinit && !rekeying_ && cfg_.advertise_strict_kex
        && id != wire::msg::kexinit) {
        return code::strict_kex_violation;
    }

    if (!is_recognized(id)) {
        if (strict_kex_active_ && in_initial_kex()) return code::strict_kex_violation;
        return send_unimplemented();
    }

    switch (phase_) {
    case phase::wait_kexinit:
        if (id != wire::msg::kexinit) {
            if (rekeying_) return dispatch_app(payload, &pkt);
            return code::unexpected_message;
        }
        note_inbound_packet();
        return on_kexinit(payload);
    case phase::wait_kex_msg:
        if (role_ == role::client) {
            if (id != wire::msg::kex_ecdh_reply) {
                if (rekeying_) return dispatch_app(payload, &pkt);
                return code::unexpected_message;
            }
            note_inbound_packet();
            return on_client_kex_reply(payload);
        }
        if (id != wire::msg::kex_ecdh_init) {
            if (rekeying_) return dispatch_app(payload, &pkt);
            return code::unexpected_message;
        }
        note_inbound_packet();
        return on_server_kex_init(payload);
    case phase::wait_newkeys:
        if (id != wire::msg::newkeys) {
            if (rekeying_) return dispatch_app(payload, &pkt);
            return code::unexpected_message;
        }
        note_inbound_packet();
        return on_newkeys();
    case phase::established:
        if (id == wire::msg::kexinit) {
            // Count traffic but do not maybe_auto_rekey: peer KEXINIT already
            // starts rekey; auto-init here would send a second local KEXINIT.
            note_inbound_packet(/*allow_auto_rekey=*/false);
            return on_peer_rekey_kexinit(payload);
        }
        return dispatch_app(payload, &pkt);
    case phase::await_host_key:
    case phase::version:
    case phase::dead:
    default:
        return code::unexpected_message;
    }
}

// RFC 4253 §11.4: only for message numbers this implementation does not know.
YANTERM_SSH_INLINE std::error_code connection::send_unimplemented() {
    wire::detail::unimplemented_msg msg;
    msg.sequence_number = reader_.sequence_number() - 1u;
    wire::writer payload;
    msg.encode(payload);
    if (auto ec = write_packet(payload.data())) return ec;
    note_inbound_packet();
    return {};
}

YANTERM_SSH_INLINE bool connection::is_recognized(wire::msg id) noexcept {
    const auto n = static_cast<std::uint8_t>(id);
    return (n >= 1 && n <= 7) || n == 20 || n == 21 || n == 30 || n == 31
        || is_userauth_or_service(id) || is_connection_layer(id);
}

YANTERM_SSH_INLINE std::error_code connection::emit_handshake_done() {
    service_ready_ = true;
    notify([](handler& app, connection& self) { app.on_handshake_done(self); });
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::emit_rekey_done() {
    phase_ = phase::established;
    rekeying_ = false;
    finish_round();
    reset_traffic_counters();
    // Deferred control must leave before the callback. on_rekey_done runs
    // inline and may rekey() again, which would otherwise push these packets
    // back onto the queue. The write pause is lifted first so a waiter resumed
    // from that callback can send; channel_writable is signaled afterwards,
    // and skipped when the callback already started another rekey.
    if (auto ec = flush_deferred_control()) return ec;
    if (!rekeying_) writes_paused_ = false;
    // A peer may rekey before ssh-userauth is accepted; on_rekey_done is only
    // reported after on_handshake_done.
    if (service_ready_) {
        notify([](handler& app, connection& self) { app.on_rekey_done(self); });
    }
    if (!rekeying_) resume_writes();
    return {};
}

YANTERM_SSH_INLINE bool connection::is_userauth_or_service(wire::msg id) noexcept {
    const auto n = static_cast<std::uint8_t>(id);
    return id == wire::msg::service_request || id == wire::msg::service_accept
        || (n >= 50 && n <= 53) || n == 60 || n == 61;
}

YANTERM_SSH_INLINE bool connection::channels_active() const noexcept {
    return app_traffic_ok() && authenticated();
}

YANTERM_SSH_INLINE bool connection::is_connection_layer(wire::msg id) noexcept {
    const auto n = static_cast<std::uint8_t>(id);
    return (n >= 80 && n <= 82) || (n >= 90 && n <= 100);
}

YANTERM_SSH_INLINE std::error_code connection::dispatch_app(std::span<const std::byte> payload, memory::detail::page_slice* pkt_page) {
    const auto id = static_cast<wire::msg>(std::to_integer<std::uint8_t>(payload[0]));
    if (!service_ready_) {
        if (id != wire::msg::service_request && id != wire::msg::service_accept) {
            return code::unexpected_message;
        }
        note_inbound_packet();
        return on_service_message(id, payload);
    }
    if (is_userauth_or_service(id)) {
        if (authenticated() || id == wire::msg::service_request
            || id == wire::msg::service_accept) {
            return code::unexpected_message;
        }
        note_inbound_packet();
        assert(auth_);
        return auth_on_payload(payload, pkt_page);
    }
    if (is_connection_layer(id)) {
        if (!authenticated()) return code::unexpected_message;
        note_inbound_packet();
        memory::detail::page_slice dummy;
        memory::detail::page_slice& page = pkt_page ? *pkt_page : dummy;
        return on_channel_payload(page);
    }
    return code::unexpected_message;
}

}  // namespace yanterm::ssh::core
