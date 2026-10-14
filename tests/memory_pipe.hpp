#pragma once

#include "test_loop.hpp"

#include <auv/error.hpp>
#include <auv/stream.hpp>
#include <corral/ParkingLot.h>
#include <corral/Task.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <memory>
#include <system_error>
#include <utility>
#include <vector>

namespace yanterm::ssh::testing::memory_pipe {

struct state {
    std::vector<std::byte> a2b;
    std::vector<std::byte> b2a;
    bool a_closed = false;
    bool b_closed = false;
    bool a_shut = false;
    bool b_shut = false;
    bool stall_a_reads = false;
    bool stall_b_reads = false;
    corral::ParkingLot a_rd;
    corral::ParkingLot b_rd;
    corral::ParkingLot a_wr;
    corral::ParkingLot b_wr;
};

// Copyable handle so tests can toggle stall after `end` is moved into a stream.
struct stall_reads_flag {
    std::shared_ptr<state> st;
    bool is_a = false;

    stall_reads_flag& operator=(bool v) {
        set(v);
        return *this;
    }

    void set(bool v) {
        if (!st) return;
        bool& flag = is_a ? st->stall_a_reads : st->stall_b_reads;
        flag = v;
        if (!v) {
            (is_a ? st->a_rd : st->b_rd).unparkAll();
            (is_a ? st->b_wr : st->a_wr).unparkAll();
        }
    }

    explicit operator bool() const {
        if (!st) return false;
        return is_a ? st->stall_a_reads : st->stall_b_reads;
    }
};

class end {
public:
    end(TestLoop* loop, std::shared_ptr<state> st, bool is_a)
        : loop_(loop), st_(std::move(st)), is_a_(is_a) {}

    end(const end&) = delete;
    end& operator=(const end&) = delete;

    end(end&& o) noexcept : loop_(o.loop_), st_(std::move(o.st_)), is_a_(o.is_a_) {
        o.loop_ = nullptr;
        o.st_.reset();
    }

    end& operator=(end&& o) noexcept {
        if (this != &o) {
            close_now();
            loop_ = o.loop_;
            st_ = std::move(o.st_);
            is_a_ = o.is_a_;
            o.loop_ = nullptr;
            o.st_.reset();
        }
        return *this;
    }

    ~end() { close_now(); }

    // Survives moving `*this` into `auv::stream::own`.
    [[nodiscard]] stall_reads_flag stall_reads() const { return {st_, is_a_}; }

    corral::Task<auv::read_result> read(auv::read_allocator alloc_cb, void* alloc_arg) {
        if (!st_ || closed_flag()) {
            co_return {auv::make_error_code(auv::errc::eof), 0};
        }
        auto& in = inbox();
        auto& lot = rd();
        while ((stall_flag() || in.empty()) && !peer_fin() && !closed_flag()) {
            co_await lot.park();
        }
        if (!st_ || closed_flag()) {
            co_return {auv::make_error_code(auv::errc::eof), 0};
        }
        if (in.empty()) {
            co_return {auv::make_error_code(auv::errc::eof), 0};
        }
        auv::buffer buf = alloc_cb(alloc_arg);
        if (buf.data() == nullptr || buf.size() == 0) {
            co_return {std::make_error_code(std::errc::no_buffer_space), 0};
        }
        const std::size_t n = std::min(in.size(), buf.size());
        std::memcpy(buf.data(), in.data(), n);
        in.erase(in.begin(), in.begin() + static_cast<std::ptrdiff_t>(n));
        co_return {std::error_code{}, n};
    }

    // Callers must pass std::size_t for the buffer-count argument; a literal 1
    // selects auv::stream's variadic just|then write overload.
    corral::Task<std::error_code> write(const auv::buffer* bufs, std::size_t nbufs) {
        if (!st_ || closed_flag() || shut_flag()) {
            co_return std::make_error_code(std::errc::not_connected);
        }
        while (peer_stall_reads() && !peer_closed() && !closed_flag() && !shut_flag()) {
            co_await wr().park();
        }
        if (!st_ || closed_flag() || shut_flag()) {
            co_return std::make_error_code(std::errc::not_connected);
        }
        if (peer_closed()) {
            co_return std::make_error_code(std::errc::broken_pipe);
        }
        auto& out = outbox();
        for (std::size_t i = 0; i < nbufs; ++i) {
            const auto* p = reinterpret_cast<const std::byte*>(bufs[i].data());
            out.insert(out.end(), p, p + bufs[i].size());
        }
        wake_peer();
        co_return std::error_code{};
    }

    corral::Task<std::error_code> shutdown() {
        if (st_ && !closed_flag() && !shut_flag()) {
            shut_flag() = true;
            wake_peer();
        }
        return corral::just(std::error_code{});
    }

    corral::Task<void> close() {
        if (st_ && !closed_flag()) {
            closed_flag() = true;
            shut_flag() = true;
            rd().unparkAll();
            wr().unparkAll();
            wake_peer();
        }
        return corral::noop();
    }

    // auv::stream::own(stream_like) passes get() and std::move(owner) as
    // function arguments; GCC evaluates them right-to-left, so get() would
    // see a moved-from owner and yield an empty stream. Route own() through
    // this conversion, which captures the pointer before the move.
    explicit operator auv::stream() && {
        auto owner = auv::detail::lifetime_owner::emplace<end>(
            std::pmr::get_default_resource(), std::move(*this));
        end* p = owner.get<end>();
        return auv::stream::construct(p, auv::detail::stream_model<end>::vtable(), std::move(owner));
    }

private:
    std::vector<std::byte>& inbox() { return is_a_ ? st_->b2a : st_->a2b; }
    std::vector<std::byte>& outbox() { return is_a_ ? st_->a2b : st_->b2a; }
    corral::ParkingLot& rd() { return is_a_ ? st_->a_rd : st_->b_rd; }
    corral::ParkingLot& wr() { return is_a_ ? st_->a_wr : st_->b_wr; }
    bool peer_closed() const { return is_a_ ? st_->b_closed : st_->a_closed; }
    bool peer_shut() const { return is_a_ ? st_->b_shut : st_->a_shut; }
    bool peer_fin() const { return peer_closed() || peer_shut(); }
    bool stall_flag() const { return is_a_ ? st_->stall_a_reads : st_->stall_b_reads; }
    bool peer_stall_reads() const { return is_a_ ? st_->stall_b_reads : st_->stall_a_reads; }
    bool& closed_flag() { return is_a_ ? st_->a_closed : st_->b_closed; }
    bool& shut_flag() { return is_a_ ? st_->a_shut : st_->b_shut; }

    void close_now() {
        if (!st_ || closed_flag()) return;
        closed_flag() = true;
        shut_flag() = true;
        wake_peer();
    }

    void wake_peer() {
        if (!loop_ || !st_) return;
        loop_->post([st = st_, is_a = is_a_] {
            (is_a ? st->b_rd : st->a_rd).unparkAll();
            (is_a ? st->b_wr : st->a_wr).unparkAll();
        });
    }

    TestLoop* loop_ = nullptr;
    std::shared_ptr<state> st_;
    bool is_a_ = false;
};

inline std::pair<end, end> make(TestLoop& loop) {
    auto st = std::make_shared<state>();
    return {end{&loop, st, true}, end{&loop, st, false}};
}

static_assert(auv::detail::stream_like<end>);

}  // namespace yanterm::ssh::testing::memory_pipe
