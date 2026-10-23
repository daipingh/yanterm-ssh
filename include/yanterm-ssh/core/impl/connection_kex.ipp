#pragma once

#include <yanterm-ssh/core/connection.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/core/impl/connection_kex.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/core/detail/kdf.hpp>
#include <yanterm-ssh/core/detail/detail_format.hpp>
#include <yanterm-ssh/kex/detail/tables.hpp>
#include <yanterm-ssh/wire/detail/messages.hpp>
#include <yanterm-ssh/wire/types.hpp>
#include <yanterm-ssh/detail/error.hpp>
#include <yanterm-ssh/crypto/secure_buffer.hpp>

#include <cassert>
#include <limits>

namespace yanterm::ssh::core {

YANTERM_SSH_INLINE std::error_code connection::set_host_key(std::span<const std::byte> blob,
                             const crypto::private_key_material& priv) {
    const host_key_spec spec{blob, priv};
    return set_host_keys(std::span<const host_key_spec>{&spec, 1});
}

YANTERM_SSH_INLINE std::error_code connection::set_host_keys(std::span<const host_key_spec> keys) {
    if (role_ != role::server) return code::invalid_state;
    if (phase_ != phase::version && phase_ != phase::wait_kexinit) {
        return code::invalid_state;
    }
    host_keys_.clear();
    host_key_set_ = false;
    signer_ = {};
    if (keys.empty()) return code::invalid_state;

    for (const auto& spec : keys) {
        installed_host_key hk;
        hk.blob.assign(spec.blob.begin(), spec.blob.end());
        hk.seed.assign(spec.priv.seed);
        hk.public_key.assign(spec.priv.public_key.begin(), spec.priv.public_key.end());
        hk.n.assign(spec.priv.n.begin(), spec.priv.n.end());
        hk.e.assign(spec.priv.e.begin(), spec.priv.e.end());
        hk.d.assign(spec.priv.d);
        hk.p.assign(spec.priv.p);
        hk.q.assign(spec.priv.q);
        hk.iqmp.assign(spec.priv.iqmp);
        hk.algorithm = spec.priv.algorithm;
        detail::host_key_view view;
        if (auto ec = detail::parse_host_key(hk.blob, view)) return ec;
        hk.type_name.assign(view.algorithm_name.begin(), view.algorithm_name.end());
        bool dup = false;
        for (const auto& existing : host_keys_) {
            if (existing.type_name == hk.type_name) {
                dup = true;
                break;
            }
        }
        if (dup) continue;
        host_keys_.push_back(std::move(hk));
    }
    if (host_keys_.empty()) return code::invalid_state;
    host_key_set_ = true;
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::resolve(host_key_ticket ticket, host_key_verdict v) {
    if (failure_ || phase_ != phase::await_host_key || !host_key_pending_
        || ticket.seq_ != host_key_round_ || !(round_ && round_->exchange)) {
        return code::invalid_state;
    }
    host_key_pending_ = false;

    if (v == host_key_verdict::reject) {
        fail(code::host_key_rejected);
        (void)enqueue_disconnect(wire::disconnect_reason::host_key_not_verifiable,
                                 "host key rejected");
        phase_ = phase::dead;
        round_->cached_reply.clear();
        return code::host_key_rejected;
    }

    detail::host_key_view verified;
    std::span<const std::byte> hash;
    if (auto err = round_->exchange->accept_reply(make_exchange_context(), round_->cached_reply, verified, hash)) {
        fail(err);
        phase_ = phase::dead;
        round_->cached_reply.clear();
        return err;
    }
    if (crypto::is_sm2_sig(round_->exchange->host_sig_id())) {
        sm2_userauth_sig_ = round_->exchange->host_sig_id();
    }
    (void)verified;
    round_->cached_reply.clear();

    if (auto err = finish_kex_and_send_newkeys(hash)) {
        fail(err);
        phase_ = phase::dead;
        return err;
    }
    if (auto err = send_service_request()) {
        fail(err);
        phase_ = phase::dead;
        return err;
    }

    phase_ = phase::wait_newkeys;
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::rekey() {
    if (failure_) return failure_;
    if (!service_ready_ || phase_ != phase::established) return code::invalid_state;
    return begin_rekey();
}

YANTERM_SSH_INLINE detail::exchange_context connection::make_exchange_context() const noexcept {
    const std::string_view v_c = (role_ == role::client) ? version_.local_identification()
                                                         : version_.peer_identification();
    const std::string_view v_s = (role_ == role::client) ? version_.peer_identification()
                                                         : version_.local_identification();
    // I_C / I_S are always the client's / server's KEXINIT payloads.
    assert(round_);
    if (role_ == role::client) {
        return {v_c, v_s, round_->our_kexinit, round_->peer_kexinit};
    }
    return {v_c, v_s, round_->peer_kexinit, round_->our_kexinit};
}

YANTERM_SSH_INLINE void connection::reset_traffic_counters() noexcept {
    bytes_sent_ = 0;
    bytes_recv_ = 0;
    packets_sent_ = 0;
    packets_recv_ = 0;
}

YANTERM_SSH_INLINE void connection::maybe_auto_rekey() {
    if (!service_ready_ || phase_ != phase::established || rekeying_ || failure_) return;
    if (bytes_sent_ < cfg_.rekey_bytes && bytes_recv_ < cfg_.rekey_bytes
        && packets_sent_ < cfg_.rekey_packets && packets_recv_ < cfg_.rekey_packets) {
        return;
    }
    if (auto ec = begin_rekey()) fail(ec);
}

YANTERM_SSH_INLINE std::error_code connection::begin_rekey() {
    if (phase_ != phase::established) return code::invalid_state;
    rekeying_ = true;
    writes_paused_ = true;
    phase_ = phase::wait_kexinit;
    if (auto ec = send_kexinit()) return ec;
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::on_peer_identification() {
    if (role_ == role::server && !host_key_set_) {
        return code::invalid_state;
    }

    if (auto ec = send_kexinit()) return ec;
    phase_ = phase::wait_kexinit;
    notify([&](handler& app, connection& self) {
        app.on_peer_identification(self, version_.peer_identification());
    });
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::send_kexinit() {
    // 修正F / RFC 8308 §2.2: never advertise ext-info-* on rekey.
    // Strict-kex markers are first-KEX only; session flag persists for resets.
    const bool first = !rekeying_;

    // Server advertises the union of algorithms the installed keys can sign.
    std::vector<std::string_view> server_host_key_allow;
    std::span<const std::string_view> host_key_allow{};
    if (role_ == role::server) {
        if (!host_key_set_ || host_keys_.empty()) return code::invalid_state;
        for (const auto& e : kex::detail::host_key_table) {
            if (!p_.supports(e.id)) continue;
            bool ok = false;
            for (const auto& hk : host_keys_) {
                detail::host_key_view view;
                if (detail::parse_host_key(hk.blob, view)) continue;
                if (detail::key_compatible_with_sig(view, e.id)) {
                    ok = true;
                    break;
                }
            }
            if (ok) server_host_key_allow.push_back(e.name);
        }
        if (server_host_key_allow.empty()) {
            return code::unsupported_algorithm;
        }
        host_key_allow = server_host_key_allow;
    }

    auto& r = ensure_round();
    r.local_algs.emplace(p_, cfg_, role_, first && cfg_.advertise_ext_info,
                        first && cfg_.advertise_strict_kex, host_key_allow);
    const auto names = r.local_algs->names();
    if (detail::usable_name_count(names.kex) == 0 || names.host_key.empty()
        || names.cipher.empty() || names.mac.empty()) {
        std::string empty{"empty="};
        bool first = true;
        auto add = [&](std::string_view cls) {
            if (!first) empty.push_back(',');
            first = false;
            empty.append(cls);
        };
        if (detail::usable_name_count(names.kex) == 0) add("kex");
        if (names.host_key.empty()) add("host_key");
        if (names.cipher.empty()) add("cipher");
        if (names.mac.empty()) add("mac");
        return fail(code::empty_algorithm_list,
                    std::move(empty));
    }

    wire::detail::kexinit msg;
    if (auto ec = p_.random_bytes(msg.cookie)) return ec;
    msg.out_kex_algorithms = names.kex;
    msg.out_server_host_key_algorithms = names.host_key;
    msg.out_encryption_c2s = names.cipher;
    msg.out_encryption_s2c = names.cipher;
    msg.out_mac_c2s = names.mac;
    msg.out_mac_s2c = names.mac;
    msg.out_compression_c2s = names.compression;
    msg.out_compression_s2c = names.compression;

    wire::writer payload;
    msg.encode(payload);
    r.our_kexinit.assign(payload.data().begin(), payload.data().end());
    return write_packet(r.our_kexinit);
}

YANTERM_SSH_INLINE bool connection::in_initial_kex() const noexcept {
    return phase_ == phase::wait_kexinit || phase_ == phase::wait_kex_msg
        || phase_ == phase::await_host_key || phase_ == phase::wait_newkeys;
}

YANTERM_SSH_INLINE void connection::note_inbound_packet(bool allow_auto_rekey) {
    if (!traffic_armed_) return;
    ++packets_recv_;
    if (allow_auto_rekey) maybe_auto_rekey();
}

YANTERM_SSH_INLINE std::error_code connection::on_peer_rekey_kexinit(std::span<const std::byte> payload) {
    // Peer initiated rekey while we were established: send our KEXINIT then
    // negotiate. Mid-rekey IGNORE/DEBUG remain accepted (strict_kex_active_
    // stays false for rekey).
    // If auto-rekey already armed us (rekeying_), only store/negotiate the
    // peer KEXINIT — do not send a second local KEXINIT.
    if (!rekeying_) {
        rekeying_ = true;
        writes_paused_ = true;
        phase_ = phase::wait_kexinit;
        if (auto ec = send_kexinit()) return ec;
    }
    return on_kexinit(payload);
}

YANTERM_SSH_INLINE std::error_code connection::on_kexinit(std::span<const std::byte> payload) {
    auto& r = ensure_round();
    r.peer_kexinit.assign(payload.begin(), payload.end());

    wire::reader peer_r{r.peer_kexinit};
    wire::detail::kexinit peer_msg;
    if (!peer_msg.decode(peer_r) || !peer_r.empty()) {
        return code::invalid_format;
    }

    wire::reader our_r{r.our_kexinit};
    wire::detail::kexinit our_msg;
    if (!our_msg.decode(our_r) || !our_r.empty()) {
        return code::invalid_format;
    }

    const wire::detail::kexinit& client_msg = (role_ == role::client) ? our_msg : peer_msg;
    const wire::detail::kexinit& server_msg = (role_ == role::client) ? peer_msg : our_msg;

    if (auto ec = detail::negotiate(p_, role_, client_msg, server_msg, negotiated_)) {
        const wire::detail::kexinit& local = our_msg;
        const wire::detail::kexinit& peer = peer_msg;
        std::string d;
        if (ec == code::no_common_kex_algorithm) {
            d = "kex";
            detail::append_quoted_field(d, "local", local.kex_algorithms.raw(), false);
            detail::append_quoted_field(d, "peer", peer.kex_algorithms.raw(), true);
        } else if (ec == code::no_common_host_key_algorithm) {
            d = "host_key";
            detail::append_quoted_field(d, "local", local.server_host_key_algorithms.raw(), false);
            detail::append_quoted_field(d, "peer", peer.server_host_key_algorithms.raw(), true);
        } else if (ec == code::no_common_cipher) {
            d = "cipher";
            detail::append_quoted_field(d, "c2s_local", local.encryption_c2s.raw(), false);
            detail::append_quoted_field(d, "c2s_peer", peer.encryption_c2s.raw(), true);
            detail::append_quoted_field(d, "s2c_local", local.encryption_s2c.raw(), false);
            detail::append_quoted_field(d, "s2c_peer", peer.encryption_s2c.raw(), true);
        } else if (ec == code::no_common_mac) {
            d = "mac";
            detail::append_quoted_field(d, "c2s_local", local.mac_c2s.raw(), false);
            detail::append_quoted_field(d, "c2s_peer", peer.mac_c2s.raw(), true);
            detail::append_quoted_field(d, "s2c_local", local.mac_s2c.raw(), false);
            detail::append_quoted_field(d, "s2c_peer", peer.mac_s2c.raw(), true);
        } else if (ec == code::no_common_compression) {
            d = "compression";
            detail::append_quoted_field(d, "c2s_local", local.compression_c2s.raw(), false);
            detail::append_quoted_field(d, "c2s_peer", peer.compression_c2s.raw(), true);
            detail::append_quoted_field(d, "s2c_local", local.compression_s2c.raw(), false);
            detail::append_quoted_field(d, "s2c_peer", peer.compression_s2c.raw(), true);
        }
        return fail(ec, std::move(d));
    }
    negotiated_ready_ = true;
    r.exchange.emplace(p_, negotiated_, role_);

    if (negotiated_.strict_kex) {
        strict_kex_session_ = true;
        // Sequence-0 KEXINIT and mid-KEX IGNORE bans apply only to the
        // initial key exchange (Terrapin). Rekey keeps app traffic flowing.
        if (!rekeying_) {
            if (reader_.sequence_number() != 1) {
                return code::strict_kex_violation;
            }
            strict_kex_active_ = true;
        }
    }

    if (role_ == role::client) {
        wire::writer init_w;
        if (auto ec = r.exchange->start(init_w)) {
            return fail(ec, detail::format_kex_handler(negotiated_.kex_name, "start", rekeying_));
        }
        if (auto ec = write_packet(init_w.data())) return ec;
    }
    phase_ = phase::wait_kex_msg;
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::on_client_kex_reply(std::span<const std::byte> payload) {
    // 修正G: parse host key for policy, cache full reply; accept_reply only
    // after resolve(accept).
    auto fail_kex = [&](std::error_code ec) {
        return fail(ec, detail::format_kex_handler(negotiated_.kex_name, "reply", rekeying_));
    };
    round_->cached_reply.assign(payload.begin(), payload.end());

    std::span<const std::byte> ks;
    if (kex::detail::uses_ecdh_messages(negotiated_.kex)) {
        wire::reader r{round_->cached_reply};
        wire::detail::kex_ecdh_reply msg;
        if (!msg.decode(r) || !r.empty()) return fail_kex(code::invalid_kex_reply);
        ks = msg.host_key;
    } else {
        wire::reader r{round_->cached_reply};
        wire::detail::kexdh_reply msg;
        if (!msg.decode(r) || !r.empty()) return fail_kex(code::invalid_kex_reply);
        ks = msg.host_key;
    }

    peer_host_key_blob_.assign(ks.begin(), ks.end());
    if (auto ec = detail::parse_host_key(peer_host_key_blob_, peer_host_key_)) return fail_kex(ec);

    if (rekeying_) {
        // Rekey: byte-compare to the first K_S; never emit verify_host_key.
        if (ks.size() != first_host_key_blob_.size()
            || !std::equal(ks.begin(), ks.end(), first_host_key_blob_.begin())) {
            return fail_kex(code::host_key_changed);
        }
        detail::host_key_view verified;
        std::span<const std::byte> hash;
        if (auto ec = round_->exchange->accept_reply(make_exchange_context(), round_->cached_reply, verified, hash)) {
            return fail_kex(ec);
        }
        if (crypto::is_sm2_sig(round_->exchange->host_sig_id())) {
            sm2_userauth_sig_ = round_->exchange->host_sig_id();
        }
        (void)verified;
        round_->cached_reply.clear();
        if (auto ec = finish_kex_and_send_newkeys(hash)) return fail_kex(ec);
        phase_ = phase::wait_newkeys;
        return {};
    }

    first_host_key_blob_ = peer_host_key_blob_;

    if (host_key_round_ == std::numeric_limits<std::uint64_t>::max()) {
        return fail(code::invalid_state);
    }
    ++host_key_round_;
    host_key_pending_ = true;
    phase_ = phase::await_host_key;
    notify([&](handler& app, connection& self) {
        app.on_host_key(self, host_key_ticket{host_key_round_}, peer_host_key_blob_);
    });
    return {};
}

YANTERM_SSH_INLINE crypto::private_key_material connection::owned_host_priv(const installed_host_key& hk,
                                             crypto::sig_id sig) const {
    crypto::private_key_material m;
    m.algorithm = sig;
    m.seed = hk.seed.span();
    m.public_key = hk.public_key;
    m.n = hk.n; m.e = hk.e; m.d = hk.d.span();
    m.p = hk.p.span(); m.q = hk.q.span(); m.iqmp = hk.iqmp.span();
    return m;
}

YANTERM_SSH_INLINE const connection::installed_host_key* connection::select_host_key(crypto::sig_id sig) const {
    for (const auto& hk : host_keys_) {
        detail::host_key_view view;
        if (detail::parse_host_key(hk.blob, view)) continue;
        if (detail::key_compatible_with_sig(view, sig)) return &hk;
    }
    return nullptr;
}

YANTERM_SSH_INLINE std::error_code connection::on_server_kex_init(std::span<const std::byte> payload) {
    auto fail_kex = [&](std::error_code ec) {
        return fail(ec, detail::format_kex_handler(negotiated_.kex_name, "init", rekeying_));
    };
    if (!host_key_set_ || host_keys_.empty() || !(round_ && round_->exchange)) {
        return fail_kex(code::invalid_state);
    }
    const installed_host_key* chosen = select_host_key(negotiated_.host_key);
    if (chosen == nullptr) return fail_kex(code::unsupported_algorithm);

    crypto::sig_id sign_id = negotiated_.host_key;
    if (crypto::is_sm2_sig(sign_id)) {
        sign_id = (negotiated_.kex_name == "ecgm-sm2-sm3") ? crypto::sig_id::sm2_ecdsa
                                                          : crypto::sig_id::sm2_za;
    }
    signer_ = p_.new_signing_key(owned_host_priv(*chosen, sign_id));
    if (!signer_) return fail_kex(code::sign_failure);

    wire::writer reply_w;
    std::span<const std::byte> hash;
    if (auto ec = round_->exchange->accept_init(make_exchange_context(), payload, chosen->blob, signer_,
                                    reply_w, hash)) {
        return fail_kex(ec);
    }
    if (auto ec = write_packet(reply_w.data())) return fail_kex(ec);
    if (auto ec = finish_kex_and_send_newkeys(hash)) return fail_kex(ec);
    phase_ = phase::wait_newkeys;
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::send_ext_info() {
    const auto value_bytes =
        std::as_bytes(std::span{ext_info_sig_algs_wire_.data(), ext_info_sig_algs_wire_.size()});
    const wire::detail::ext_info::entry entries[] = {{"server-sig-algs", value_bytes}};
    wire::detail::ext_info msg;
    msg.entries = entries;
    wire::writer payload;
    msg.encode(payload);
    return write_packet(payload.data());
}

YANTERM_SSH_INLINE std::error_code connection::finish_kex_and_send_newkeys(std::span<const std::byte> hash) {
    if (session_id_.empty()) {
        session_id_.assign(hash.begin(), hash.end());
    }

    // Binding J: KDF takes the SSH encoding of K, the same one H used.
    crypto::secure_bytes kbuf;
    {
        struct wiping_writer {
            wire::writer w;
            ~wiping_writer() {
                auto held = w.take();
                crypto::secure_zero(std::span<std::byte>{held});
            }
        } enc;
        const auto encoded = round_->exchange->shared_secret_encoded_size();
        enc.w.reserve(encoded);
        round_->exchange->write_shared_secret(enc.w);
        assert(enc.w.size() <= encoded);
        kbuf.assign(enc.w.data());
        round_->exchange->consume_shared_secret();
    }

    detail::direction_state outbound;
    detail::direction_state inbound;
    if (auto ec = detail::make_direction_states(p_, negotiated_, kbuf.span(), hash,
                                                   session_id_, role_, outbound, inbound)) {
        return ec;
    }
    round_->pending_outbound = std::move(outbound);
    round_->pending_inbound = std::move(inbound);

    const std::byte newkeys_byte{static_cast<std::byte>(wire::msg::newkeys)};
    if (auto ec = write_packet(std::span{&newkeys_byte, 1})) return ec;

    // Continue sequence across the key install unless strict KEX resets it.
    // Use the session flag so rekey (which omits strict markers) still resets.
    round_->pending_outbound.sequence_number = writer_.sequence_number();
    writer_.install(std::move(round_->pending_outbound));
    if (strict_kex_session_) writer_.reset_sequence();

    // RFC 8308: EXT_INFO only after the *first* NEWKEYS, never on rekey.
    if (!rekeying_ && role_ == role::server && negotiated_.peer_supports_ext_info
        && cfg_.advertise_ext_info) {
        if (auto ec = send_ext_info()) return ec;
    }
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::apply_ext_info(std::span<const std::byte> payload) {
    wire::reader r{payload};
    wire::detail::ext_info msg;
    if (!msg.decode(r) || !r.empty()) return code::invalid_format;

    // No client-sent extension is acted on; server-sig-algs is server-only.
    if (role_ != role::client) return {};
    std::string_view algs;
    if (msg.find("server-sig-algs", algs)) {
        server_sig_algs_.assign(algs.begin(), algs.end());
    }
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::on_newkeys() {
    round_->pending_inbound.sequence_number = reader_.sequence_number();
    reader_.install(std::move(round_->pending_inbound));
    if (strict_kex_session_) reader_.reset_sequence();
    strict_kex_active_ = false;

    if (rekeying_) return emit_rekey_done();

    // Keys are live both ways; handshake_done waits for ssh-userauth.
    phase_ = phase::established;
    finish_round();
    traffic_armed_ = true;
    reset_traffic_counters();
    return {};
}

YANTERM_SSH_INLINE bool connection::app_traffic_ok() const noexcept {
    // disconnect() during rekey leaves rekeying_ set.
    return !failure_ && phase_ != phase::dead && (phase_ == phase::established || rekeying_);
}

YANTERM_SSH_INLINE connection::kex_round& connection::ensure_round() {
    if (!round_) round_ = std::make_unique<kex_round>();
    return *round_;
}

YANTERM_SSH_INLINE void connection::finish_round() noexcept {
    if (round_ && round_->local_algs) {
        advertised_ssh_rsa_ = false;
        for (std::string_view n : round_->local_algs->names().host_key) {
            if (n == "ssh-rsa") advertised_ssh_rsa_ = true;
        }
    }
    round_.reset();
}

YANTERM_SSH_INLINE bool connection::advertised_ssh_rsa() const noexcept {
    return advertised_ssh_rsa_;
}

}  // namespace yanterm::ssh::core
