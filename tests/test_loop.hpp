#pragma once

#include <corral/defs.h>
#include <corral/run.h>

#include <deque>
#include <functional>
#include <utility>

namespace yanterm::ssh::testing {

struct TestLoop {
    void post(std::function<void()> fn) { q_.push_back(std::move(fn)); }

    void run() {
        running_ = true;
        stopped_ = false;
        while (!stopped_) {
            if (q_.empty()) break;
            auto fn = std::move(q_.front());
            q_.pop_front();
            fn();
        }
        running_ = false;
    }

    void stop() { stopped_ = true; }

    [[nodiscard]] bool running() const noexcept { return running_; }

private:
    std::deque<std::function<void()>> q_;
    bool running_ = false;
    bool stopped_ = false;
};

}  // namespace yanterm::ssh::testing

namespace corral {
template <>
struct EventLoopTraits<yanterm::ssh::testing::TestLoop> {
    static EventLoopID eventLoopID(yanterm::ssh::testing::TestLoop& loop) {
        return EventLoopID(&loop);
    }
    static void run(yanterm::ssh::testing::TestLoop& loop) { loop.run(); }
    static void stop(yanterm::ssh::testing::TestLoop& loop) { loop.stop(); }
    static bool isRunning(yanterm::ssh::testing::TestLoop& loop) noexcept {
        return loop.running();
    }
};
}  // namespace corral
