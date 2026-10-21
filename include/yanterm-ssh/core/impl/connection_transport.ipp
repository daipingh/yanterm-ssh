#pragma once

#include <yanterm-ssh/core/connection.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/core/impl/connection_transport.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/detail/error.hpp>
#include <yanterm-ssh/core/detail/detail_format.hpp>

#include <cassert>
#include <cstring>

namespace yanterm::ssh::core {

YANTERM_SSH_INLINE std::error_code connection::feed(std::span<const std::byte> in, std::size_t& accepted) {
    assert(depth() == 0);
    accepted = 0;
    if (auth_ && auth_->authenticated()) {
        auth_.reset();
        authenticated_ = true;
    }
    if (failure_ && phase_ != phase::await_host_key) return failure_;
    if (phase_ == phase::dead) {
        return failure_ ? failure_ : code::invalid_state;
    }

    if (!version_.done()) {
        std::size_t n = 0;
        std::error_code ec = version_.feed(in, n);
        accepted += n;
        if (ec) return fail(ec);
        if (!version_.done()) return {};

        if (auto err = on_peer_identification()) return fail(err);
    }

    std::error_code result;
    for (;;) {
        // Stall before reading the next unit so the packet that paused feed
        // is consumed, then not one more byte. While stalled, DATA / ADJUST /
        // CLOSE behind the head of the connection stream are also held
        // (connection-level HOL blocking). Bare core users must resolve;
        if (phase_ == phase::dead || inbound_requests_stalled()) {
            break;
        }

        std::size_t n = 0;
        memory::detail::page_slice payload;
        std::error_code ec = reader_.read(in.subspan(accepted), n, pool_, payload);
        accepted += n;
        if (ec) {
            result = fail(ec, detail::format_phase_detail(static_cast<std::uint8_t>(phase_)));
            break;
        }
        if (payload.empty()) {
            if (traffic_armed_) bytes_recv_ += n;
            break;
        }

        if (auto err = dispatch_payload(payload)) {
            result = fail(err);
            break;
        }
        if (traffic_armed_) bytes_recv_ += n;
    }

    if (traffic_armed_) maybe_auto_rekey();
    return result;
}

YANTERM_SSH_INLINE std::size_t connection::pending_output(std::span<std::span<const std::byte>> out) const {
    std::size_t n = 0;
    for (const auto& seg : out_segments_) {
        if (n == out.size()) break;
        out[n++] = seg.bytes();
    }
    return n;
}

YANTERM_SSH_INLINE void connection::consume_output(std::size_t n) {
    if (n == 0) return;
    if (n > out_bytes_) n = out_bytes_;
    const std::size_t consumed = n;

    out_bytes_ -= consumed;
    std::size_t left = consumed;
    while (left > 0 && !out_segments_.empty()) {
        memory::detail::page_slice& front = out_segments_.front();
        if (front.size() <= left) {
            left -= front.size();
            out_segments_.pop_front();
            continue;
        }
        front.advance(left);
        left = 0;
    }

    // Only now is the queue consistent: auto-rekey may append new packets.
    if (traffic_armed_) {
        bytes_sent_ += consumed;
        maybe_auto_rekey();
    }
}

YANTERM_SSH_INLINE void connection::commit_encrypted_packet(memory::detail::page_slice slice) {
    push_output_slice(std::move(slice));
    if (traffic_armed_) {
        ++packets_sent_;
        maybe_auto_rekey();
    }
}

YANTERM_SSH_INLINE std::error_code connection::write_packet(std::span<const std::byte> payload) {
    memory::detail::page_slice slice;
    if (auto ec = writer_.write(payload, pool_, slice)) return ec;
    commit_encrypted_packet(std::move(slice));
    return {};
}

YANTERM_SSH_INLINE std::error_code connection::write_control_packet(std::span<const std::byte> payload) {
    if (rekeying_) {
        crypto::secure_bytes held;
        held.assign(payload);
        deferred_control_.push_back(std::move(held));
        return {};
    }
    return write_packet(payload);
}

YANTERM_SSH_INLINE std::error_code connection::flush_deferred_control() {
    std::vector<crypto::secure_bytes> pending;
    pending.swap(deferred_control_);
    for (const auto& pkt : pending) {
        if (auto ec = write_control_packet(pkt.span())) {
            fail(ec);
            phase_ = phase::dead;
            return ec;
        }
    }
    return {};
}

YANTERM_SSH_INLINE void connection::push_output_bytes(std::span<const std::byte> in) {
    if (in.empty()) return;
    memory::detail::page_slice slice = pool_.allocate(in.size());
    auto dst = slice.mutable_bytes();
    if (dst.size() != in.size()) return;
    std::memcpy(dst.data(), in.data(), in.size());
    push_output_slice(std::move(slice));
}

YANTERM_SSH_INLINE void connection::push_output_slice(memory::detail::page_slice slice) {
    if (slice.empty()) return;
    out_bytes_ += slice.size();
    if (!out_segments_.empty()) {
        memory::detail::page_slice& tail = out_segments_.back();
        if (tail.try_merge(slice)) {
            return;
        }
    }
    out_segments_.push_back(std::move(slice));
}

}  // namespace yanterm::ssh::core
