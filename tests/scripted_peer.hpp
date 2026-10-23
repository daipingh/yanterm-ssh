#pragma once

#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/auth/types.hpp>
#include <yanterm-ssh/channels/types.hpp>
#include <yanterm-ssh/core/detail/kdf.hpp>
#include <yanterm-ssh/core/detail/kex_exchange.hpp>
#include <yanterm-ssh/core/detail/kex_negotiation.hpp>
#include <yanterm-ssh/core/detail/packet.hpp>
#include <yanterm-ssh/core/detail/version_exchange.hpp>
#include <yanterm-ssh/crypto/algorithms.hpp>
#include <yanterm-ssh/crypto/secure_buffer.hpp>
#include <yanterm-ssh/detail/error.hpp>
#include <yanterm-ssh/wire/detail/messages.hpp>
#include <yanterm-ssh/wire/message_ids.hpp>

#include "handshake_fixture.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace yanterm::ssh::testing {

// In-process SSH peer. Speaks the binary protocol against one `wired_connection`
// so tests can inject connection-layer messages without a second `connection`.
class scripted_peer {
public:
    static core::config sut_config();

    scripted_peer(core::role role, crypto::provider p, const host_material* host = nullptr);

    void send(std::span<const std::byte> payload);

    template <class Msg>
    void send_msg(const Msg& m) {
        wire::writer w;
        m.encode(w);
        send(w.data());
    }

    [[nodiscard]] std::size_t pending_bytes() const noexcept { return out_.size(); }

    std::error_code deliver(wired_connection& sut);
    void collect(wired_connection& sut);
    std::error_code exchange(wired_connection& sut, int max_rounds = 64);

    // KEX through both NEWKEYS. The client SUT has already emitted
    // SERVICE_REQUEST; the server SUT has not been offered a service yet.
    void exchange_keys(wired_connection& sut);
    void handshake(wired_connection& sut);
    void authenticate(wired_connection& sut);
    void start_rekey();

    std::optional<std::vector<std::byte>> take(wire::msg id);
    std::vector<std::byte> take_pending();
    [[nodiscard]] const std::vector<std::uint8_t>& seen_ids() const noexcept { return seen_ids_; }
    [[nodiscard]] const std::vector<std::vector<std::byte>>& received() const noexcept { return received_; }
    void clear_received() noexcept { received_.clear(); }
    [[nodiscard]] bool kex_in_progress() const noexcept { return kex_running_; }

private:
    void send_kexinit();
    void on_payload(std::span<const std::byte> payload);
    void on_kexinit(std::span<const std::byte> payload);
    void on_ecdh_init(std::span<const std::byte> payload);
    void on_ecdh_reply(std::span<const std::byte> payload);
    void on_newkeys();
    void finish_kex(std::span<const std::byte> hash);
    [[nodiscard]] core::detail::exchange_context make_exchange_context() const;

    core::role role_;
    crypto::provider p_;
    const host_material* host_ = nullptr;
    core::config cfg_ = sut_config();
    core::detail::version_exchange vx_;
    std::optional<core::detail::local_algorithms> algs_;
    std::vector<std::byte> our_kexinit_;
    std::vector<std::byte> peer_kexinit_;
    kex::negotiated negotiated_{};
    std::optional<core::detail::key_exchange> kx_;
    std::vector<std::byte> session_id_;
    std::vector<std::byte> hash_;
    core::detail::direction_state pending_in_;
    bool kex_running_ = false;
    bool newkeys_in_pending_ = false;
    core::detail::packet_writer writer_;
    core::detail::packet_reader reader_;
    memory::detail::page_pool pool_;
    crypto::signing_key signer_;
    std::vector<std::byte> out_;
    std::vector<std::byte> in_;
    std::vector<std::vector<std::byte>> received_;
    std::vector<std::uint8_t> seen_ids_;
};

struct peer_session {
    crypto::provider p;
    host_material hm;
    wired_connection sut;
    scripted_peer peer;

    peer_session(core::role sut_role,
                 const core::config& cfg = scripted_peer::sut_config(),
                 std::pmr::memory_resource* mr = std::pmr::get_default_resource());

    void exchange_keys() { peer.exchange_keys(sut); }
    void handshake() { peer.handshake(sut); }
    void authenticate() { peer.authenticate(sut); }
};

struct peer_channel {
    core::channel_ref local{};
    std::uint32_t sut_id = 0;
    std::uint32_t peer_id = 9;
};

peer_channel open_confirmed(peer_session& s, std::uint32_t window, std::uint32_t max_packet,
                            std::uint32_t peer_id = 9);

inline core::config scripted_peer::sut_config() {
    core::config cfg;
    cfg.preferred_kex = "curve25519-sha256";
    cfg.preferred_host_key = "ssh-ed25519";
    cfg.preferred_cipher = "aes256-gcm@openssh.com";
    return cfg;
}

inline scripted_peer::scripted_peer(core::role role, crypto::provider p, const host_material* host)
    : role_{role}
    , p_{p}
    , host_{host}
    , vx_{role_, "scripted"}
    , writer_{p_}
    , reader_{p_} {
    if (role_ == core::role::server) {
        REQUIRE(host_ != nullptr);
        signer_ = p_.new_signing_key(host_->priv);
        REQUIRE(static_cast<bool>(signer_));
    }
    const auto banner = vx_.outgoing();
    out_.assign(banner.begin(), banner.end());
    send_kexinit();
}

inline void scripted_peer::send(std::span<const std::byte> payload) {
    memory::detail::page_slice slice;
    REQUIRE_FALSE(writer_.write(payload, pool_, slice));
    const auto bytes = slice.bytes();
    out_.insert(out_.end(), bytes.begin(), bytes.end());
}

inline std::error_code scripted_peer::deliver(wired_connection& sut) {
    std::error_code ec;
    while (!out_.empty()) {
        std::size_t accepted = 0;
        ec = sut.conn.feed(out_, accepted);
        REQUIRE(accepted <= out_.size());
        if (accepted > 0) out_.erase(out_.begin(), out_.begin() + accepted);
        if (ec || accepted == 0) break;
    }
    return ec;
}

inline void scripted_peer::collect(wired_connection& sut) {
    for (;;) {
        const auto chunk = sut.conn.pending_output0();
        if (chunk.empty()) break;
        in_.insert(in_.end(), chunk.begin(), chunk.end());
        sut.conn.consume_output(chunk.size());
    }
    if (!vx_.done()) {
        std::size_t accepted = 0;
        REQUIRE_FALSE(vx_.feed(in_, accepted));
        if (accepted > 0) in_.erase(in_.begin(), in_.begin() + accepted);
    }
    // A partial identification line is not a binary packet.
    if (!vx_.done()) return;
    for (;;) {
        std::size_t accepted = 0;
        memory::detail::page_slice payload;
        REQUIRE_FALSE(reader_.read(in_, accepted, pool_, payload));
        if (accepted == 0) break;
        REQUIRE(accepted <= in_.size());
        in_.erase(in_.begin(), in_.begin() + accepted);
        REQUIRE(!payload.empty());
        on_payload(payload.bytes());
    }
}

inline std::error_code scripted_peer::exchange(wired_connection& sut, int max_rounds) {
    for (int round = 0; round < max_rounds; ++round) {
        const auto out_before = out_.size();
        const auto pending_before = sut.conn.pending_output_bytes();
        const auto in_before = in_.size();
        const auto received_before = received_.size();
        const bool kex_before = kex_running_;
        const bool newkeys_before = newkeys_in_pending_;
        const auto ec = deliver(sut);
        const auto out_after_deliver = out_.size();
        const auto pending_after_deliver = sut.conn.pending_output_bytes();
        collect(sut);
        if (ec) return ec;
        const bool progress = out_after_deliver != out_before || pending_after_deliver != pending_before
                              || pending_after_deliver > 0 || out_.size() != out_after_deliver
                              || in_.size() != in_before || received_.size() != received_before
                              || kex_running_ != kex_before || newkeys_in_pending_ != newkeys_before;
        if (!progress) return {};
    }
    return code::invalid_state;
}

inline void scripted_peer::exchange_keys(wired_connection& sut) {
    REQUIRE_FALSE(exchange(sut));
    // Peer role server means the SUT is the client and must accept the host key
    // before it will emit NEWKEYS and SERVICE_REQUEST.
    if (role_ == core::role::server) {
        bool resolved = false;
        for (const auto& ev : sut.handler.events) {
            if (const auto* host = std::get_if<recording_handler::verify_host_key>(&ev)) {
                REQUIRE_FALSE(sut.conn.resolve(host->ticket, core::host_key_verdict::accept));
                resolved = true;
                break;
            }
        }
        REQUIRE(resolved);
        REQUIRE_FALSE(exchange(sut));
    }
    REQUIRE_FALSE(kex_in_progress());
    REQUIRE_FALSE(sut.conn.failure());
    sut.handler.events.clear();
}

inline void scripted_peer::handshake(wired_connection& sut) {
    exchange_keys(sut);
    if (role_ == core::role::server) {
        const auto req = take(wire::msg::service_request);
        REQUIRE(req);
        wire::reader reader{*req};
        wire::detail::service_msg msg;
        msg.id = wire::msg::service_request;
        REQUIRE(msg.decode(reader));
        REQUIRE(reader.empty());
        REQUIRE(msg.service_name == "ssh-userauth");
        send_msg(wire::detail::service_msg{wire::msg::service_accept, "ssh-userauth"});
        REQUIRE_FALSE(exchange(sut));
    } else {
        send_msg(wire::detail::service_msg{wire::msg::service_request, "ssh-userauth"});
        REQUIRE_FALSE(exchange(sut));
        REQUIRE(take(wire::msg::service_accept));
    }
    int dones = 0;
    for (const auto& ev : sut.handler.events) {
        if (std::holds_alternative<recording_handler::handshake_done>(ev)) ++dones;
    }
    REQUIRE(dones == 1);
    REQUIRE_FALSE(sut.conn.failure());
    sut.handler.events.clear();
    clear_received();
}

inline void scripted_peer::authenticate(wired_connection& sut) {
    handshake(sut);
    if (role_ == core::role::server) {
        REQUIRE_FALSE(sut.conn.auth_none("alice"));
        REQUIRE_FALSE(exchange(sut));
        REQUIRE(take(wire::msg::userauth_request));
        const auto ok = static_cast<std::byte>(wire::msg::userauth_success);
        send(std::span<const std::byte>{&ok, 1});
        REQUIRE_FALSE(exchange(sut));
        bool saw_success = false;
        for (const auto& ev : sut.handler.events) {
            if (const auto* resp = std::get_if<recording_handler::auth_response>(&ev)) {
                if (resp->success) saw_success = true;
            }
        }
        REQUIRE(saw_success);
    } else {
        wire::detail::userauth_request_none none;
        none.user = "alice";
        none.service = "ssh-connection";
        send_msg(none);
        REQUIRE_FALSE(exchange(sut));
        const recording_handler::auth_request* auth_req = nullptr;
        for (const auto& ev : sut.handler.events) {
            if (const auto* ar = std::get_if<recording_handler::auth_request>(&ev)) {
                auth_req = ar;
                break;
            }
        }
        REQUIRE(auth_req != nullptr);
        REQUIRE_FALSE(sut.conn.resolve(auth_req->ticket, auth::auth_verdict::success()));
        REQUIRE_FALSE(exchange(sut));
        REQUIRE(take(wire::msg::userauth_success));
    }
    sut.handler.events.clear();
    clear_received();
}

inline void scripted_peer::start_rekey() {
    REQUIRE_FALSE(kex_running_);
    send_kexinit();
}

inline std::vector<std::byte> scripted_peer::take_pending() {
    std::vector<std::byte> out;
    out.swap(out_);
    return out;
}

inline std::optional<std::vector<std::byte>> scripted_peer::take(wire::msg id) {
    const auto want = static_cast<std::byte>(id);
    for (auto it = received_.begin(); it != received_.end(); ++it) {
        if (!it->empty() && (*it)[0] == want) {
            auto msg = std::move(*it);
            received_.erase(it);
            return msg;
        }
    }
    return std::nullopt;
}

inline void scripted_peer::send_kexinit() {
    const std::string_view allow_ed25519[] = {"ssh-ed25519"};
    const std::span<const std::string_view> allow = role_ == core::role::server
                                                        ? std::span<const std::string_view>{allow_ed25519}
                                                        : std::span<const std::string_view>{};
    algs_.emplace(p_, cfg_, role_, false, false, allow);
    const auto names = algs_->names();
    wire::detail::kexinit msg;
    REQUIRE_FALSE(p_.random_bytes(msg.cookie));
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
    our_kexinit_.assign(payload.data().begin(), payload.data().end());
    send(our_kexinit_);
    kex_running_ = true;
}

inline void scripted_peer::on_payload(std::span<const std::byte> payload) {
    REQUIRE(!payload.empty());
    seen_ids_.push_back(std::to_integer<std::uint8_t>(payload[0]));
    const auto id = static_cast<wire::msg>(std::to_integer<std::uint8_t>(payload[0]));
    if (id == wire::msg::kexinit) {
        on_kexinit(payload);
        return;
    }
    if (id == wire::msg::kex_ecdh_init) {
        on_ecdh_init(payload);
        return;
    }
    if (id == wire::msg::kex_ecdh_reply) {
        on_ecdh_reply(payload);
        return;
    }
    if (id == wire::msg::newkeys) {
        on_newkeys();
        return;
    }
    if (id == wire::msg::ext_info) return;
    received_.emplace_back(payload.begin(), payload.end());
}

inline void scripted_peer::on_kexinit(std::span<const std::byte> payload) {
    peer_kexinit_.assign(payload.begin(), payload.end());
    if (!kex_running_) send_kexinit();

    wire::reader peer_r{peer_kexinit_};
    wire::detail::kexinit peer_msg;
    REQUIRE(peer_msg.decode(peer_r));
    REQUIRE(peer_r.empty());

    wire::reader our_r{our_kexinit_};
    wire::detail::kexinit our_msg;
    REQUIRE(our_msg.decode(our_r));
    REQUIRE(our_r.empty());

    const wire::detail::kexinit& client_msg = (role_ == core::role::client) ? our_msg : peer_msg;
    const wire::detail::kexinit& server_msg = (role_ == core::role::client) ? peer_msg : our_msg;
    REQUIRE_FALSE(core::detail::negotiate(p_, role_, client_msg, server_msg, negotiated_));
    kx_.emplace(p_, negotiated_, role_);
    if (role_ == core::role::client) {
        wire::writer w;
        REQUIRE_FALSE(kx_->start(w));
        send(w.data());
    }
}

inline void scripted_peer::on_ecdh_init(std::span<const std::byte> payload) {
    REQUIRE(role_ == core::role::server);
    REQUIRE(kx_.has_value());
    REQUIRE(host_ != nullptr);
    REQUIRE(static_cast<bool>(signer_));
    wire::writer w;
    std::span<const std::byte> hash;
    REQUIRE_FALSE(kx_->accept_init(make_exchange_context(), payload, host_->blob, signer_, w, hash));
    send(w.data());
    finish_kex(hash);
}

inline void scripted_peer::on_ecdh_reply(std::span<const std::byte> payload) {
    REQUIRE(role_ == core::role::client);
    REQUIRE(kx_.has_value());
    core::detail::host_key_view view;
    std::span<const std::byte> hash;
    REQUIRE_FALSE(kx_->accept_reply(make_exchange_context(), payload, view, hash));
    finish_kex(hash);
}

inline void scripted_peer::on_newkeys() {
    REQUIRE(newkeys_in_pending_);
    // Match connection::on_newkeys: the reader has already consumed NEWKEYS,
    // so the installed inbound state continues at the post-increment sequence.
    pending_in_.sequence_number = reader_.sequence_number();
    reader_.install(std::move(pending_in_));
    if (negotiated_.strict_kex) reader_.reset_sequence();
    newkeys_in_pending_ = false;
    kex_running_ = false;
}

inline void scripted_peer::finish_kex(std::span<const std::byte> hash) {
    hash_.assign(hash.begin(), hash.end());
    if (session_id_.empty()) session_id_ = hash_;

    crypto::secure_bytes kbuf;
    {
        wire::writer enc;
        kx_->write_shared_secret(enc);
        kbuf.assign(enc.data());
        auto held = enc.take();
        crypto::secure_zero(std::span<std::byte>{held});
    }
    kx_->consume_shared_secret();

    core::detail::direction_state outbound;
    core::detail::direction_state inbound;
    REQUIRE_FALSE(core::detail::make_direction_states(p_, negotiated_, kbuf.span(), hash_, session_id_, role_,
                                                      outbound, inbound));

    const std::byte newkeys_byte{static_cast<std::byte>(wire::msg::newkeys)};
    send(std::span<const std::byte>{&newkeys_byte, 1});

    // NEWKEYS itself went out under the previous keys. The next outbound
    // packet continues the sequence, matching finish_kex_and_send_newkeys.
    outbound.sequence_number = writer_.sequence_number();
    writer_.install(std::move(outbound));
    if (negotiated_.strict_kex) writer_.reset_sequence();

    pending_in_ = std::move(inbound);
    newkeys_in_pending_ = true;
}

inline core::detail::exchange_context scripted_peer::make_exchange_context() const {
    const bool we_client = role_ == core::role::client;
    const std::string_view v_c = we_client ? vx_.local_identification() : vx_.peer_identification();
    const std::string_view v_s = we_client ? vx_.peer_identification() : vx_.local_identification();
    const std::span<const std::byte> i_c = we_client ? std::span<const std::byte>{our_kexinit_}
                                                     : std::span<const std::byte>{peer_kexinit_};
    const std::span<const std::byte> i_s = we_client ? std::span<const std::byte>{peer_kexinit_}
                                                     : std::span<const std::byte>{our_kexinit_};
    return {v_c, v_s, i_c, i_s};
}

inline peer_session::peer_session(core::role sut_role, const core::config& cfg,
                                  std::pmr::memory_resource* mr)
    : p{prov()}
    , hm{make_ed25519_host(p)}
    , sut{sut_role, p, cfg, mr}
    , peer{sut_role == core::role::client ? core::role::server : core::role::client, p,
           sut_role == core::role::client ? &hm : nullptr} {
    if (sut_role == core::role::server) configure_server(sut, hm);
}

inline peer_channel open_confirmed(peer_session& s, std::uint32_t window, std::uint32_t max_packet,
                                   std::uint32_t peer_id) {
    channels::channel_open_spec spec{};
    core::channel_ref ref{};
    REQUIRE_FALSE(s.sut.conn.open_channel(spec, nullptr, ref));
    REQUIRE_FALSE(s.peer.exchange(s.sut));
    const auto raw = s.peer.take(wire::msg::channel_open);
    REQUIRE(raw);
    wire::reader reader{*raw};
    wire::detail::channel_open opened;
    REQUIRE(opened.decode(reader));
    peer_channel ch;
    ch.local = ref;
    ch.sut_id = opened.sender;
    ch.peer_id = peer_id;
    REQUIRE(ch.sut_id == ref.index);

    wire::detail::channel_open_confirmation conf;
    conf.recipient = ch.sut_id;
    conf.sender = peer_id;
    conf.window = window;
    conf.max_packet = max_packet;
    s.peer.send_msg(conf);
    REQUIRE_FALSE(s.peer.exchange(s.sut));
    bool saw_opened = false;
    for (const auto& ev : s.sut.handler.events) {
        if (std::holds_alternative<recording_handler::channel_opened>(ev)) saw_opened = true;
    }
    REQUIRE(saw_opened);
    s.sut.handler.events.clear();
    return ch;
}

}  // namespace yanterm::ssh::testing
