#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/detail/error.hpp>
#include <yanterm-ssh/core/detail/auth_state.hpp>
#include <yanterm-ssh/core/detail/channel_codec.hpp>
#include <yanterm-ssh/core/detail/channel_slots.hpp>
#include <yanterm-ssh/core/config.hpp>
#include <yanterm-ssh/kex/algorithms.hpp>
#include <yanterm-ssh/core/detail/kex_negotiation.hpp>
#include <yanterm-ssh/core/detail/kex_exchange.hpp>
#include <yanterm-ssh/core/detail/host_key.hpp>
#include <yanterm-ssh/memory/detail/pages.hpp>
#include <yanterm-ssh/core/types.hpp>
#include <yanterm-ssh/core/detail/packet.hpp>
#include <yanterm-ssh/core/detail/version_exchange.hpp>
#include <yanterm-ssh/wire/message_ids.hpp>
#include <yanterm-ssh/wire/types.hpp>
#include <yanterm-ssh/crypto/provider.hpp>
#include <yanterm-ssh/crypto/secure_buffer.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <memory>
#include <memory_resource>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

namespace yanterm::ssh::core {

class connection {
    struct installed_host_key {
        std::vector<std::byte> blob;
        crypto::secure_bytes seed;
        std::vector<std::byte> public_key;
        std::vector<std::byte> n;
        std::vector<std::byte> e;
        crypto::secure_bytes d;
        crypto::secure_bytes p;
        crypto::secure_bytes q;
        crypto::secure_bytes iqmp;
        crypto::sig_id algorithm{};
        std::string type_name;
    };

public:
    // `mr` supplies fixed-size page blocks (default_page_size) for decrypted
    // payloads and outbound ciphertext. Blocks go back to `mr` as soon as their
    // last slice dies; nothing is cached per connection. The default is the
    // process-wide locking page resource.
    connection(role r, crypto::provider p, const config& cfg, handler& h,
               std::pmr::memory_resource* mr = memory::default_page_resource());

    struct host_key_spec {
        std::span<const std::byte> blob;
        crypto::private_key_material priv;
    };

    // Server only: replace the host-key ring with a single key.
    std::error_code set_host_key(std::span<const std::byte> blob,
                                 const crypto::private_key_material& priv);

    // Server only: replace the host-key ring. Same public-key type: first wins.
    // Empty is the same as never installing a host key.
    std::error_code set_host_keys(std::span<const host_key_spec> keys);

    // --- byte plumbing ---
    // In-place parse. `accepted` is the number of bytes consumed; anything
    // beyond it stays owned by the caller and must be presented again. The core
    // never retains `in`.
    std::error_code feed(std::span<const std::byte> in, std::size_t& accepted);

    // Vector write: fills `out` from the front and returns how many segments
    // were written. A return value equal to out.size() means there may be more.
    std::size_t pending_output(std::span<std::span<const std::byte>> out) const;

    // First segment only. Not an overload of pending_output: the return value
    // means something different.
    [[nodiscard]] std::span<const std::byte> pending_output0() const noexcept {
        if (out_segments_.empty()) return {};
        return out_segments_.front().bytes();
    }

    [[nodiscard]] std::size_t pending_output_bytes() const noexcept { return out_bytes_; }

    void consume_output(std::size_t n);

    // True when feed() will not consume another complete unit until the
    // application resolve()s a host-key verify or a server auth verdict.
    // Incomplete packets are not a stall (the caller should read more
    // bytes). Dead / failed is not a stall either.
    [[nodiscard]] bool inbound_requests_stalled() const noexcept {
        return phase_ == phase::await_host_key || (auth_ && auth_->waiting_verdict());
    }

    [[nodiscard]] static channel_ref channel_ref_of(open_ticket t) noexcept { return t.ref_; }

    [[nodiscard]] static channel_ref channel_ref_of(channel_request_ticket t) noexcept {
        return t.ref_;
    }

    [[nodiscard]] static std::uint64_t seq_of(channel_request_ticket t) noexcept { return t.seq_; }

    [[nodiscard]] static std::uint64_t seq_of(global_request_ticket t) noexcept { return t.seq_; }

    // --- external verdicts ---
    std::error_code resolve(host_key_ticket ticket, host_key_verdict v);

    std::error_code resolve(auth_ticket ticket, const auth::auth_verdict& v);

    std::error_code resolve(kbdint_ticket ticket, std::span<const std::string_view> responses);

    std::error_code auth_none(std::string_view user);

    std::error_code auth_password(std::string_view user, std::string_view password);

    std::error_code send_auth_banner(std::string_view text, std::string_view language = {});

    std::error_code auth_publickey(std::string_view user, std::span<const std::byte> public_blob,
                                   const crypto::private_key_material& priv);

    // Picks the signature algorithm and appends the RFC 4252 section 7 data to
    // sign to `out` without sending or changing state.
    std::error_code auth_publickey_sign_request(std::string_view user,
                                                std::span<const std::byte> public_blob,
                                                publickey_sign_request& req,
                                                wire::writer& out) const;

    // `signature` is an SSH signature blob (string algorithm, string signature).
    std::error_code auth_publickey_signed(std::string_view user,
                                          std::span<const std::byte> public_blob,
                                          std::span<const std::byte> signature);

    // Sends the unsigned request with the algorithm auth_publickey_sign_request would choose.
    std::error_code auth_publickey_query(std::string_view user, std::span<const std::byte> public_blob);

    std::error_code auth_keyboard_interactive(std::string_view user,
                                              std::string_view language = {},
                                              std::span<const std::string_view> submethods = {});

    std::error_code resolve(open_ticket ticket, const channels::channel_open_verdict& v,
                            void* user = nullptr);

    std::error_code resolve(channel_request_ticket ticket, bool success);

    std::error_code resolve(global_request_ticket ticket, bool success,
                            std::span<const std::byte> response_payload = {});

    std::error_code open_channel(const channels::channel_open_spec& spec, void* user, channel_ref& out);

    std::error_code abandon_open(channel_ref ch);

    std::error_code channel_eof(channel_ref ch);

    std::error_code channel_close(channel_ref ch);

    std::error_code channel_write(channel_ref ch,
                                  std::span<const std::span<const std::byte>> fragments,
                                  std::size_t& accepted);

    std::error_code channel_write_extended(channel_ref ch, std::uint32_t ext_type,
                                           std::span<const std::span<const std::byte>> fragments,
                                           std::size_t& accepted);

    std::size_t channel_read(channel_ref ch, std::uint32_t ext_type, std::span<std::byte> dst);

    void set_user_data(channel_ref ch, void* user);

    std::error_code channel_request(channel_ref ch, const channels::channel_request_spec& spec);

    std::error_code request_pty(channel_ref ch, const channels::pty_spec& spec);

    std::error_code request_shell(channel_ref ch);

    std::error_code request_exec(channel_ref ch, std::string_view command);

    std::error_code request_subsystem(channel_ref ch, std::string_view name);

    std::error_code request_env(channel_ref ch, std::string_view name, std::string_view value);

    std::error_code request_window_change(channel_ref ch, const channels::window_size& size);

    std::error_code request_signal(channel_ref ch, std::string_view name);

    std::error_code send_exit_status(channel_ref ch, std::uint32_t status);

    std::error_code send_exit_signal(channel_ref ch, const channels::exit_signal& sig);

    std::error_code request_x11(channel_ref ch, const channels::x11_req_spec& spec);

    std::error_code send_global_request(std::string_view type, std::span<const std::byte> payload,
                                        bool want_reply);

    std::error_code request_tcpip_forward(std::string_view addr, std::uint32_t port);

    std::error_code cancel_tcpip_forward(std::string_view addr, std::uint32_t port);

    std::error_code request_streamlocal_forward(std::string_view socket_path);

    std::error_code cancel_streamlocal_forward(std::string_view socket_path);

    // --- actions (synchronous enqueue) ---
    std::error_code send_ignore(std::span<const std::byte> data);

    std::error_code send_debug(bool always_display, std::string_view text);

    std::error_code disconnect(wire::disconnect_reason reason, std::string_view description);

    std::error_code rekey();

    [[nodiscard]] std::string_view peer_identification() const noexcept {
        return version_.peer_identification();
    }
    [[nodiscard]] const ::yanterm::ssh::kex::negotiated* negotiated() const noexcept {
        return negotiated_ready_ ? &negotiated_ : nullptr;
    }
    [[nodiscard]] std::span<const std::byte> session_id() const noexcept { return session_id_; }
    [[nodiscard]] std::string_view server_sig_algs() const noexcept { return server_sig_algs_; }

    // Outbound binary-packet sequence (post-increment next-to-use). Exposed for
    // strict-KEX sequence-reset assertions; mirrors packet_writer::sequence_number().
    [[nodiscard]] std::uint32_t outbound_sequence_number() const noexcept {
        return writer_.sequence_number();
    }
    [[nodiscard]] std::error_code failure() const noexcept { return failure_; }
    [[nodiscard]] std::string_view failure_detail() const noexcept { return failure_detail_; }

private:
    enum class phase : std::uint8_t {
        version,
        wait_kexinit,
        wait_kex_msg,
        await_host_key,
        wait_newkeys,
        established,
        dead,
    };

    std::error_code fail(std::error_code ec, std::string detail = {});

    std::error_code fail_and_disconnect(std::error_code ec, wire::disconnect_reason reason,
                                        std::string detail = {});

    [[nodiscard]] detail::exchange_context make_exchange_context() const noexcept;

    void commit_encrypted_packet(memory::detail::page_slice slice);

    std::error_code write_packet(std::span<const std::byte> payload);

    [[nodiscard]] std::uint32_t depth() const noexcept { return depth_; }

    // `pending` is the former host::notify snapshot; it does not change control flow.
    template <class Fn>
    void notify(Fn&& fn) {
        ++depth_;
        const int pending = std::uncaught_exceptions();
        try {
            fn(app_, *this);
        } catch (...) {
            --depth_;
            (void)pending;
            on_unwind();
            throw;
        }
        --depth_;
    }

    void on_unwind() noexcept;

    struct fragment_cursor {
        std::span<const std::span<const std::byte>> frags{};
        std::size_t index = 0;
        std::size_t offset = 0;

        [[nodiscard]] std::size_t peek_size(std::size_t limit) const noexcept;

        template <class Fn>
        void consume(std::size_t n, Fn&& fn) {
            while (n > 0 && index < frags.size()) {
                if (offset >= frags[index].size()) {
                    ++index;
                    offset = 0;
                    continue;
                }
                const auto take = std::min(frags[index].size() - offset, n);
                fn(frags[index].subspan(offset, take));
                offset += take;
                n -= take;
            }
        }

        void commit(std::size_t n) noexcept;

        template <class Fn>
        void copy_prefix(std::size_t n, Fn&& fn) const {
            fragment_cursor snap = *this;
            snap.consume(n, std::forward<Fn>(fn));
        }
    };

    static void store_be32_at(std::span<std::byte> hdr, std::size_t off, std::uint32_t v) noexcept;

    // DATA path: fragments go through write_streamed into the final page.
    // Remote window / accepted / packet counters commit only after finish
    // succeeds. Rekey pauses this path (available=0) instead of deferring DATA.
    std::error_code write_channel_fragments(channel_ref ch, std::uint32_t ext_type,
                                            std::span<const std::span<const std::byte>> fragments,
                                            std::size_t& accepted);

    template <class Msg>
    std::error_code write_encoded(const Msg& msg) {
        wire::writer w;
        msg.encode(w);
        return write_control_packet(w.data());
    }

    std::error_code on_channel_payload(memory::detail::page_slice& pkt);
    std::error_code on_channel_open(std::span<const std::byte> bytes);
    std::error_code on_channel_confirmation(std::span<const std::byte> bytes);
    std::error_code on_channel_failure(std::span<const std::byte> bytes);
    std::error_code on_channel_window_adjust(std::span<const std::byte> bytes);
    std::error_code on_channel_data(memory::detail::page_slice& pkt, std::span<const std::byte> bytes,
                                    bool ext);
    std::error_code on_channel_eof(std::span<const std::byte> bytes);
    std::error_code on_channel_close(std::span<const std::byte> bytes);
    std::error_code on_channel_request(std::span<const std::byte> bytes);
    std::error_code on_channel_reply(std::span<const std::byte> bytes, bool success);
    std::error_code on_global_request(std::span<const std::byte> bytes);
    std::error_code on_global_reply(std::span<const std::byte> bytes, bool success);
    std::error_code channel_begin_write(channel_ref ref, bool has_data, detail::outbound_data_window& out);
    std::error_code channel_commit_write(channel_ref ref, std::uint32_t bytes);
    void release_channel(channel_ref ref);
    void notify_readable(const detail::channel& c, std::uint32_t ext_type);
    [[nodiscard]] detail::channel* find_open_channel(channels::channel_id local) noexcept;
    void resume_writes();
    [[nodiscard]] static bool can_send_data(const detail::channel& c) noexcept;

    // OPEN/ADJUST/EOF/CLOSE/request defer during rekey and flush after
    // rekey_done. DATA never enters this queue.
    std::error_code write_control_packet(std::span<const std::byte> payload);

    std::error_code flush_deferred_control();

    // Copies raw bytes (only used for the version banner) into a page so the
    // outbound path has a single shape.
    void push_output_bytes(std::span<const std::byte> in);

    // Appends a segment, merging with the tail when both live in the same page
    // and are physically adjacent. Keeps the segment count low so vector writes
    // stay small.
    void push_output_slice(memory::detail::page_slice slice);

    void reset_traffic_counters() noexcept;

    void maybe_auto_rekey();

    std::error_code begin_rekey();

    std::error_code enqueue_disconnect(wire::disconnect_reason reason,
                                       std::string_view description);

    std::error_code on_peer_identification();

    std::error_code send_kexinit();

    [[nodiscard]] bool in_initial_kex() const noexcept;

    std::error_code dispatch_payload(memory::detail::page_slice& pkg);

    std::error_code send_unimplemented();

    [[nodiscard]] static bool is_recognized(wire::msg id) noexcept;

    void note_inbound_packet(bool allow_auto_rekey = true);

    std::error_code on_peer_rekey_kexinit(std::span<const std::byte> payload);

    std::error_code on_kexinit(std::span<const std::byte> payload);

    std::error_code on_client_kex_reply(std::span<const std::byte> payload);

    crypto::private_key_material owned_host_priv(const installed_host_key& hk,
                                                 crypto::sig_id sig) const;

    const installed_host_key* select_host_key(crypto::sig_id sig) const;

    std::error_code on_server_kex_init(std::span<const std::byte> payload);

    std::error_code send_ext_info();

    std::error_code finish_kex_and_send_newkeys(std::span<const std::byte> hash);

    std::error_code emit_handshake_done();

    std::error_code emit_rekey_done();

    std::error_code apply_ext_info(std::span<const std::byte> payload);

    std::error_code on_newkeys();

    [[nodiscard]] static bool is_userauth_or_service(wire::msg id) noexcept;

    [[nodiscard]] bool app_traffic_ok() const noexcept;

    [[nodiscard]] bool channels_active() const noexcept;

    [[nodiscard]] bool authenticated() const noexcept {
        return authenticated_ || (auth_ && auth_->authenticated());
    }

    std::error_code send_service_request();
    std::error_code on_service_message(wire::msg id, std::span<const std::byte> payload);

    // invalid_state and unsupported_algorithm leave the connection usable.
    template <class Fn>
    [[nodiscard]] std::error_code auth_client_start(std::string_view method, bool query, Fn&& send) {
        if (!auth_ || !service_ready_ || !app_traffic_ok()) return code::invalid_state;
        if (role_ != role::client || auth_->phase != detail::auth_phase::ready) {
            return code::invalid_state;
        }
        if (auto ec = send()) {
            if (ec != code::invalid_state && ec != code::unsupported_algorithm) {
                fail(ec);
                phase_ = phase::dead;
            }
            return ec;
        }
        auth_->method.assign(method.begin(), method.end());
        auth_->publickey_query = query;
        auth_->phase = detail::auth_phase::wait_userauth_reply;
        return {};
    }

    std::error_code auth_select_publickey_sig(std::span<const std::byte> public_blob,
                                              publickey_sign_request& req) const;
    std::error_code auth_send_failure(std::string_view methods, bool partial);
    void auth_notify_result();
    std::error_code auth_on_payload(std::span<const std::byte> payload,
                                    memory::detail::page_slice* page);
    std::error_code auth_on_client_payload(wire::msg id, std::span<const std::byte> payload,
                                           memory::detail::page_slice* page);
    std::error_code auth_on_server_payload(wire::msg id, std::span<const std::byte> payload,
                                           memory::detail::page_slice* page);
    std::error_code auth_take_info_request(std::span<const std::byte> payload);
    std::error_code auth_take_info_response(std::span<const std::byte> payload,
                                            memory::detail::page_slice* page);
    std::error_code auth_resolve_verdict(std::uint64_t seq, const auth::auth_verdict& v);
    std::error_code auth_resolve_kbdint(std::uint64_t seq,
                                        std::span<const std::string_view> responses);
    static std::error_code auth_bump_seq(std::uint64_t& seq);

    [[nodiscard]] static bool is_connection_layer(wire::msg id) noexcept;

    std::error_code dispatch_app(std::span<const std::byte> payload, memory::detail::page_slice* pkt_page);

    handler& app_;
    std::uint32_t depth_ = 0;

    role role_;
    // Declared early so it outlives out_segments_ (page_slice returns to pool).
    memory::detail::page_pool pool_;
    crypto::provider p_;
    config cfg_;

    detail::version_exchange version_;
    detail::packet_reader reader_;
    detail::packet_writer writer_;

    phase phase_ = phase::version;
    std::error_code failure_{};
    std::string failure_detail_;

    std::deque<memory::detail::page_slice> out_segments_;
    std::size_t out_bytes_ = 0;
    // ssh-userauth accepted (client: SERVICE_ACCEPT seen; server: ACCEPT
    // written). Orthogonal to phase_ because a peer rekey may run between the
    // first NEWKEYS and this point.
    bool service_ready_ = false;

    struct kex_round {
        std::optional<detail::local_algorithms> local_algs;
        std::vector<std::byte> our_kexinit;
        std::vector<std::byte> peer_kexinit;
        std::optional<detail::key_exchange> exchange;
        std::vector<std::byte> cached_reply;
        detail::direction_state pending_outbound{};
        detail::direction_state pending_inbound{};
    };
    std::unique_ptr<kex_round> round_;
    bool advertised_ssh_rsa_ = false;

    kex_round& ensure_round();
    void finish_round() noexcept;

    ::yanterm::ssh::kex::negotiated negotiated_{};
    bool negotiated_ready_ = false;
    bool strict_kex_active_ = false;
    bool strict_kex_session_ = false;  // sticky after first negotiation
    bool rekeying_ = false;
    std::vector<crypto::secure_bytes> deferred_control_;
    // Server only: the packet right after the client's first NEWKEYS has been
    // seen, so no further client EXT_INFO is accepted.
    bool ext_info_closed_ = false;
    bool traffic_armed_ = false;  // count volume only after the first inbound NEWKEYS

    bool advertised_ssh_rsa() const noexcept;

    bool host_key_set_ = false;
    std::vector<installed_host_key> host_keys_;
    crypto::signing_key signer_;

    std::vector<std::byte> peer_host_key_blob_;
    std::vector<std::byte> first_host_key_blob_;  // first K_S; rekey must match
    detail::host_key_view peer_host_key_{};
    std::uint64_t host_key_round_ = 0;
    bool host_key_pending_ = false;
    crypto::sig_id sm2_userauth_sig_ = crypto::sig_id::sm2_za;
    std::unique_ptr<detail::auth_state> auth_;
    bool authenticated_ = false;
    detail::channel_slots slots_;
    bool writes_paused_ = false;
    detail::inbound_seq global_inbound_{};
    std::uint32_t global_outstanding_ = 0;

    std::vector<std::byte> session_id_;
    std::string server_sig_algs_;
    std::string ext_info_sig_algs_wire_;
    std::uint64_t bytes_sent_ = 0;
    std::uint64_t bytes_recv_ = 0;
    std::uint64_t packets_sent_ = 0;
    std::uint64_t packets_recv_ = 0;
};

}  // namespace yanterm::ssh::core

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/core/impl/connection_lifecycle.ipp>
#include <yanterm-ssh/core/impl/connection_transport.ipp>
#include <yanterm-ssh/core/impl/connection_kex.ipp>
#include <yanterm-ssh/core/impl/connection_auth.ipp>
#include <yanterm-ssh/core/impl/connection_channels.ipp>
#include <yanterm-ssh/core/impl/connection_handler.ipp>
#endif
