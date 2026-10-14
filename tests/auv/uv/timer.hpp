#ifndef AUV_TIMER_HPP_
#define AUV_TIMER_HPP_

#include <chrono>

#include <corral/Executor.h>
#include <corral/ParkingLot.h>

#include "core.hpp"

namespace auv {

namespace detail {
template <typename T>
concept DurationCastable = requires(T d) {
    { std::chrono::duration_cast<std::chrono::milliseconds>(d) };
};
} // namespace detail

struct Timer {
  public:
    Timer(uv_loop_t *loop) : handle_(resource_timer(loop)) {}
    Timer(uv_loop_t *loop, uint64_t timeout, uint64_t repeat = 0) : handle_(resource_timer(loop)) {
        start(timeout, repeat);
    }
    template <detail::DurationCastable T1, detail::DurationCastable T2 = std::chrono::milliseconds>
    Timer(uv_loop_t *loop, T1 timeout, T2 repeat = T2()) : handle_(resource_timer(loop)) {
        start(
            std::chrono::duration_cast<std::chrono::milliseconds>(timeout).count(),
            std::chrono::duration_cast<std::chrono::milliseconds>(repeat).count());
    }
    Timer(const Timer &) = delete;
    Timer(Timer &&) = delete;
    Timer &operator=(const Timer &) = delete;
    Timer &operator=(Timer &&) = delete;
    ~Timer() { stop(); }

    uv_timer_t *raw() const noexcept { return handle_.get(); }

    Timer &start(uint64_t timeout, uint64_t repeat = 0) {
        auto r = uv_timer_start(
            raw(),
            [](uv_timer_t *handle) {
                auto &t = *static_cast<Timer *>(handle->data);
                if (!uv_is_active(reinterpret_cast<uv_handle_t *>(handle))) {
                    t.active_ = false;
                    t.handle_->data = nullptr;
                }
                if (t.cond_.empty()) {
                    t.ready_ = true;
                    return;
                }
                t.cond_.unparkAll();
            },
            timeout,
            repeat);

        if (!r) {
            handle_->data = this;
            active_ = true;
            ready_ = false;
        }
        return *this;
    }

    template <detail::DurationCastable T1, detail::DurationCastable T2 = std::chrono::milliseconds>
    Timer &start(T1 timeout, T2 repeat = T2()) {
        return start(
            std::chrono::duration_cast<std::chrono::milliseconds>(timeout).count(),
            std::chrono::duration_cast<std::chrono::milliseconds>(repeat).count());
    }

    Timer &again() {
        auto repeat = uv_timer_get_repeat(raw());
        if (repeat) {
            start(repeat, repeat);
        }
        return *this;
    }

    void stop() {
        if (active_) {
            uv_timer_stop(raw());
            ready_ = false;
            active_ = false;
            handle_->data = nullptr;
        }
    }

    bool active() const noexcept { return active_; }
    bool ready() const noexcept { return ready_; }
    uint64_t due_in() const noexcept {
        if (ready_) {
            return 0;
        }
        if (!active_) {
            return UINT64_MAX;
        }
        return uv_timer_get_due_in(raw());
    }

    auto get() noexcept {
        struct Awaiter {
            Awaiter(Timer &t) : t_(t), parked_(t.cond_.park()) {}

            bool await_ready() const noexcept { return std::exchange(t_.ready_, false); }
            void await_suspend(std::coroutine_handle<> h) noexcept { parked_.await_suspend(h); }
            void await_resume() noexcept { parked_.await_resume(); }
            auto await_cancel(std::coroutine_handle<> h) noexcept { return parked_.await_cancel(h); }

            Timer &t_;
            corral::ParkingLot::Awaiter parked_;
        };

        return Awaiter{*this};
    }

    auto operator co_await() noexcept { return get(); }

  private:
    std::unique_ptr<uv_timer_t, handle_deleter> handle_;
    corral::ParkingLot cond_;
    bool ready_{};
    bool active_{};
};

template <RawTypeCastable<uv_timer_t *> TimerPtr, typename R, typename P>
corral::Awaitable<void> auto sleep_for(TimerPtr &&handle, std::chrono::duration<R, P> delay) {
    return sleep_for(
        std::forward<TimerPtr>(handle), std::chrono::duration_cast<std::chrono::milliseconds>(delay).count());
}

template <typename R, typename P>
corral::Awaitable<void> auto sleep_for(uv_loop_t *loop, std::chrono::duration<R, P> delay) {
    return sleep_for(loop, std::chrono::duration_cast<std::chrono::milliseconds>(delay).count());
}

template <typename D>
corral::Awaitable<void> auto sleep_for(Timer &t, D delay) {
    return t.start(std::forward<D>(delay)).get();
}

} // namespace auv
#endif
