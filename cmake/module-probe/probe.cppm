module;
#include <coroutine>

export module yanterm.ssh.probe;

struct ProbeTask {
    struct promise_type {
        ProbeTask get_return_object() { return {}; }
        std::suspend_always initial_suspend() noexcept { return {}; }
        std::suspend_always final_suspend() noexcept { return {}; }
        void return_void() {}
        void unhandled_exception() {}
    };
    bool await_ready() noexcept { return false; }
    void await_suspend(std::coroutine_handle<>) noexcept {}
    void await_resume() noexcept {}
};

export struct ProbeMini {
    int v = 0;
    ProbeTask go();
};

inline ProbeTask ProbeMini::go() {
    auto fn = []() -> ProbeTask {
        co_await std::suspend_always{};
    };
    co_await fn();
}
