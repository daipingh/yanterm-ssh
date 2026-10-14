#ifndef AUV_CORE_HPP_
#define AUV_CORE_HPP_

#include <memory>
#include <string>

#include <corral/utility.h>
#include <uv.h>

namespace auv {

template <typename T, typename From>
struct RawType;

template <typename T, typename From>
    requires std::convertible_to<From, T>
struct RawType<T, From> {
    static T cast(From &&from) { return static_cast<T>(std::forward<From>(from)); }
};

template <typename T, typename From>
    requires(!std::convertible_to<From, T> && std::convertible_to<decltype(&*std::declval<From>()), T>)
struct RawType<T, From> {
    static T cast(From &&from) { return static_cast<T>(&*from); }
};

template <typename From, typename To>
concept RawTypeCastable0 = requires(From &&from) {
    { RawType<To, From>::cast(std::forward<From>(from)) } -> std::same_as<To>;
};

template <typename From, typename To>
concept RawTypeCastable1 = requires(From &&from) {
    { RawType<std::remove_cvref_t<To>, std::remove_cvref_t<From>>::cast(std::forward<From>(from)) } -> std::same_as<To>;
};

template <typename From, typename To>
concept RawTypeCastable = RawTypeCastable0<From, To> || RawTypeCastable1<From, To>;

template <typename T, typename From>
    requires RawTypeCastable0<From, T>
T raw_type(From &&from) {
    return RawType<T, From>::cast(std::forward<From>(from));
}

template <typename T, typename From>
    requires(!RawTypeCastable0<From, T> && RawTypeCastable1<From, T>)
T raw_type(From &&from) {
    return RawType<std::remove_cvref_t<T>, std::remove_cvref_t<From>>::cast(std::forward<From>(from));
}

template <>
struct RawType<uv_buf_t, std::string_view> {
    static uv_buf_t cast(std::string_view sv) {
        return uv_buf_init(const_cast<char *>(sv.data()), static_cast<unsigned int>(sv.size()));
    }
};

#define AUV_MAKE_CASTABLE(TO, FROM)                                                                                    \
    template <typename Ptr>                                                                                            \
        requires std::convertible_to<decltype(&*std::declval<Ptr>()), FROM *>                                          \
    struct RawType<TO *, Ptr> {                                                                                        \
        static auto cast(Ptr &&from) {                                                                                 \
            return reinterpret_cast<TO *>(RawType<FROM *, Ptr>::cast(std::forward<Ptr>(from)));                        \
        }                                                                                                              \
    };

AUV_MAKE_CASTABLE(uv_handle_t, uv_async_t)
AUV_MAKE_CASTABLE(uv_handle_t, uv_check_t)
AUV_MAKE_CASTABLE(uv_handle_t, uv_fs_event_t)
AUV_MAKE_CASTABLE(uv_handle_t, uv_fs_poll_t)
AUV_MAKE_CASTABLE(uv_handle_t, uv_idle_t)
AUV_MAKE_CASTABLE(uv_handle_t, uv_pipe_t)
AUV_MAKE_CASTABLE(uv_handle_t, uv_poll_t)
AUV_MAKE_CASTABLE(uv_handle_t, uv_prepare_t)
AUV_MAKE_CASTABLE(uv_handle_t, uv_process_t)
AUV_MAKE_CASTABLE(uv_handle_t, uv_stream_t)
AUV_MAKE_CASTABLE(uv_handle_t, uv_tcp_t)
AUV_MAKE_CASTABLE(uv_handle_t, uv_timer_t)
AUV_MAKE_CASTABLE(uv_handle_t, uv_tty_t)
AUV_MAKE_CASTABLE(uv_handle_t, uv_udp_t)
AUV_MAKE_CASTABLE(uv_handle_t, uv_signal_t)

AUV_MAKE_CASTABLE(uv_stream_t, uv_tcp_t)
AUV_MAKE_CASTABLE(uv_stream_t, uv_pipe_t)
AUV_MAKE_CASTABLE(uv_stream_t, uv_tty_t)

AUV_MAKE_CASTABLE(sockaddr, sockaddr_in)
AUV_MAKE_CASTABLE(sockaddr, sockaddr_in6)
AUV_MAKE_CASTABLE(sockaddr, sockaddr_storage)

struct handle_deleter {
    template <typename T>
        requires RawTypeCastable<T *, uv_handle_t *>
    void operator()(T *handle) const noexcept {
        if (!uv_is_closing(reinterpret_cast<uv_handle_t *>(handle))) {
            uv_close(reinterpret_cast<uv_handle_t *>(handle), [](uv_handle_t *handle) {
                delete reinterpret_cast<T *>(handle);
            });
            return;
        }
        delete handle;
    }
};

inline auto resource_prepare(uv_loop_t *loop) {
    auto handle = new uv_prepare_t{};
    uv_prepare_init(loop, handle);
    return std::unique_ptr<uv_prepare_t, handle_deleter>(handle);
}

inline auto resource_idle(uv_loop_t *loop) {
    auto handle = new uv_idle_t{};
    uv_idle_init(loop, handle);
    return std::unique_ptr<uv_idle_t, handle_deleter>(handle);
}

inline auto resource_timer(uv_loop_t *loop) {
    auto handle = new uv_timer_t{};
    uv_timer_init(loop, handle);
    return std::unique_ptr<uv_timer_t, handle_deleter>(handle);
}

inline auto resource_poll(uv_loop_t *loop, int fd) {
    auto handle = new uv_poll_t{};
    uv_poll_init(loop, handle, fd);
    return std::unique_ptr<uv_poll_t, handle_deleter>(handle);
}

inline auto resource_tcp(uv_loop_t *loop, unsigned int flags = 0) {
    auto handle = new uv_tcp_t{};
    uv_tcp_init_ex(loop, handle, flags);
    return std::unique_ptr<uv_tcp_t, handle_deleter>(handle);
}

inline auto resource_pipe(uv_loop_t *loop, int ipc = 0) {
    auto handle = new uv_pipe_t{};
    uv_pipe_init(loop, handle, ipc);
    return std::unique_ptr<uv_pipe_t, handle_deleter>(handle);
}

namespace detail {

// uv_close
struct CloseAwaiter {
  public:
    template <RawTypeCastable<uv_handle_t *> HandlePtr>
    CloseAwaiter(HandlePtr &&handle) : handle_(raw_type<uv_handle_t *>(std::forward<HandlePtr>(handle))) {}
    CloseAwaiter(const CloseAwaiter &) = delete;
    CloseAwaiter(CloseAwaiter &&) = delete;
    CloseAwaiter &operator=(const CloseAwaiter &) = delete;
    CloseAwaiter &operator=(CloseAwaiter &&) = delete;

    bool await_ready() const noexcept { return std::false_type{}; }
    void await_suspend(std::coroutine_handle<> h) noexcept {
        uv_close(handle_, [](uv_handle_t *handle) {
            auto &self = *static_cast<CloseAwaiter *>(handle->data);
            self.handle_->data = nullptr;
            self.parent_.resume();
        });
        handle_->data = this;
        parent_ = h;
    }
    void await_resume() noexcept {}

  private:
    uv_handle_t *handle_;
    std::coroutine_handle<> parent_{};
};

// uv_tcp_close_reset
struct TcpCloseAwaiter {
  public:
    template <RawTypeCastable<uv_tcp_t *> HandlePtr>
    TcpCloseAwaiter(HandlePtr &&handle, bool reset)
        : handle_(raw_type<uv_tcp_t *>(std::forward<HandlePtr>(handle))), reset_(reset) {}
    TcpCloseAwaiter(const TcpCloseAwaiter &) = delete;
    TcpCloseAwaiter(TcpCloseAwaiter &&) = delete;
    TcpCloseAwaiter &operator=(const TcpCloseAwaiter &) = delete;
    TcpCloseAwaiter &operator=(TcpCloseAwaiter &&) = delete;

    bool await_ready() const noexcept { return std::false_type{}; }
    void await_suspend(std::coroutine_handle<> h) noexcept {
        auto cb = [](uv_handle_t *handle) {
            auto &self = *static_cast<TcpCloseAwaiter *>(handle->data);
            self.handle_->data = nullptr;
            self.parent_.resume();
        };

        if (!reset_ || uv_tcp_close_reset(handle_, cb) < 0)
            uv_close(reinterpret_cast<uv_handle_t *>(handle_), cb);

        handle_->data = this;
        parent_ = h;
    }
    void await_resume() noexcept {}

  private:
    uv_tcp_t *handle_;
    std::coroutine_handle<> parent_{};
    bool reset_{};
};

} // namespace detail

template <RawTypeCastable<uv_handle_t *> HandlePtr>
corral::Awaitable<void> auto close(HandlePtr &&handle) {
    return corral::makeAwaitable<detail::CloseAwaiter, HandlePtr>(std::forward<HandlePtr>(handle));
}

template <RawTypeCastable<uv_tcp_t *> HandlePtr>
corral::Awaitable<void> auto tcp_close(HandlePtr &&handle, bool reset = false) {
    return corral::makeAwaitable<detail::TcpCloseAwaiter, HandlePtr>(std::forward<HandlePtr>(handle), reset);
}

namespace detail {

// sleep_for
struct SleepAwaiter {
  public:
    template <RawTypeCastable<uv_timer_t *> TimerPtr>
    SleepAwaiter(TimerPtr &&handle, uint64_t delay)
        : handle_(raw_type<uv_timer_t *>(std::forward<TimerPtr>(handle))), delay_(delay) {}
    SleepAwaiter(const SleepAwaiter &) = delete;
    SleepAwaiter(SleepAwaiter &&) = delete;
    SleepAwaiter &operator=(const SleepAwaiter &) = delete;
    SleepAwaiter &operator=(SleepAwaiter &&) = delete;

    bool await_ready() const noexcept { return std::false_type{}; }
    void await_suspend(std::coroutine_handle<> h) noexcept {
        auto r = uv_timer_start(
            handle_,
            [](uv_timer_t *handle) {
                auto &self = *static_cast<SleepAwaiter *>(handle->data);
                self.handle_->data = nullptr;
                self.parent_.resume();
            },
            delay_,
            0);

        if (r < 0) {
            h.resume();
            return;
        }
        handle_->data = this;
        parent_ = h;
    }
    void await_resume() noexcept {}
    auto await_cancel(std::coroutine_handle<>) noexcept {
        uv_timer_stop(handle_);
        handle_->data = nullptr;
        return std::true_type{};
    }

  private:
    uv_timer_t *handle_;
    std::coroutine_handle<> parent_{};
    uint64_t delay_{};
};

} // namespace detail

template <RawTypeCastable<uv_timer_t *> TimerPtr>
corral::Awaitable<void> auto sleep_for(TimerPtr &&handle, uint64_t delay) {
    return corral::makeAwaitable<detail::SleepAwaiter, TimerPtr>(std::forward<TimerPtr>(handle), delay);
}

inline corral::Awaitable<void> auto sleep_for(uv_loop_t *loop, uint64_t delay) {
    return corral::makeAwaitable<detail::SleepAwaiter>(resource_timer(loop), delay);
}

namespace detail {

// uv_tcp_connect
struct TcpConnectAwaiter {
  public:
    template <RawTypeCastable<uv_tcp_t *> StreamPtr, typename SockAddr>
    TcpConnectAwaiter(StreamPtr &&handle, SockAddr &&sa)
        : handle_(raw_type<uv_tcp_t *>(std::forward<StreamPtr>(handle))), sa_(sa.get()) {}
    TcpConnectAwaiter(const TcpConnectAwaiter &) = delete;
    TcpConnectAwaiter(TcpConnectAwaiter &&) = delete;
    TcpConnectAwaiter &operator=(const TcpConnectAwaiter &) = delete;
    TcpConnectAwaiter &operator=(TcpConnectAwaiter &&) = delete;

    bool await_ready() const noexcept { return std::false_type{}; }
    void await_suspend(std::coroutine_handle<> h) noexcept {
        auto r = uv_tcp_connect(&req_, handle_, sa_, [](uv_connect_t *req, int status) {
            auto &self = *static_cast<TcpConnectAwaiter *>(req->data);
            self.status_ = status;
            self.parent_.resume();
        });
        if (r < 0) {
            status_ = r;
            h.resume();
            return;
        }
        req_.data = this;
        parent_ = h;
    }
    int await_resume() noexcept { return status_; }

  private:
    uv_tcp_t *handle_;
    std::coroutine_handle<> parent_{};
    union {
        uv_connect_t req_;
        int status_;
    };
    const sockaddr *sa_;
};

// uv_pipe_connect
struct PipeConnectAwaiter {
  public:
    template <RawTypeCastable<uv_pipe_t *> StreamPtr>
    PipeConnectAwaiter(StreamPtr &&handle, std::string_view name, unsigned int flags = 0)
        : handle_(raw_type<uv_pipe_t *>(std::forward<StreamPtr>(handle))), name_(name), flags_(flags) {}
    PipeConnectAwaiter(const PipeConnectAwaiter &) = delete;
    PipeConnectAwaiter(PipeConnectAwaiter &&) = delete;
    PipeConnectAwaiter &operator=(const PipeConnectAwaiter &) = delete;
    PipeConnectAwaiter &operator=(PipeConnectAwaiter &&) = delete;

    bool await_ready() const noexcept { return std::false_type{}; }
    void await_suspend(std::coroutine_handle<> h) noexcept {
        auto r =
            uv_pipe_connect2(&req_, handle_, name_.data(), name_.size(), flags_, [](uv_connect_t *req, int status) {
                auto &self = *static_cast<PipeConnectAwaiter *>(req->data);
                self.status_ = status;
                self.parent_.resume();
            });
        if (r < 0) {
            status_ = r;
            h.resume();
            return;
        }
        req_.data = this;
        parent_ = h;
    }
    int await_resume() noexcept { return status_; }

  private:
    uv_pipe_t *handle_;
    std::coroutine_handle<> parent_{};
    union {
        uv_connect_t req_;
        int status_;
    };
    std::string_view name_;
    unsigned int flags_;
};

template <typename T>
auto buffer_first(const T &t) {
    auto &[a, b] = t;
    return a;
}

template <typename T>
auto buffer_second(const T &t) {
    auto &[a, b] = t;
    return b;
}

template <typename P>
concept BufferPointer = std::same_as<P, char *> || std::same_as<P, unsigned char *>;

template <typename T>
concept BufferCastable = requires(T t) {
    { buffer_first(t) } -> BufferPointer;
    { buffer_second(t) } -> std::integral;
};

template <typename F>
concept AllocInvocable0 = std::invocable<F, size_t> && RawTypeCastable<std::invoke_result_t<F, size_t>, uv_buf_t>;
template <typename F>
concept AllocInvocable1 = std::invocable<F> && RawTypeCastable<std::invoke_result_t<F>, uv_buf_t>;
template <typename F>
concept AllocInvocable2 = std::invocable<F, size_t> && BufferCastable<std::invoke_result_t<F, size_t>>;
template <typename F>
concept AllocInvocable3 = std::invocable<F> && BufferCastable<std::invoke_result_t<F>>;

template <typename F>
concept AllocInvocable =
    (AllocInvocable0<F> || AllocInvocable1<F> || AllocInvocable2<F> || AllocInvocable3<F> ||
     std::invocable<F, size_t, uv_buf_t *>);

// uv_read_start but once
template <typename AllocCb>
struct ReadAwaiter {
  public:
    template <RawTypeCastable<uv_stream_t *> StreamPtr>
    ReadAwaiter(StreamPtr &&handle, AllocCb &&alloc_cb)
        : handle_(raw_type<uv_stream_t *>(std::forward<StreamPtr>(handle))),
          alloc_cb_(std::forward<AllocCb>(alloc_cb)) {}
    ReadAwaiter(const ReadAwaiter &) = delete;
    ReadAwaiter(ReadAwaiter &&) = delete;
    ReadAwaiter &operator=(const ReadAwaiter &) = delete;
    ReadAwaiter &operator=(ReadAwaiter &&) = delete;

    bool await_ready() const noexcept { return std::false_type{}; }
    void await_suspend(std::coroutine_handle<> h) noexcept {
        auto handle_data = std::exchange(handle_->data, this);
        auto r = uv_read_start(
            handle_,
            [](uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
                auto &self = *static_cast<ReadAwaiter *>(handle->data);
                if (!self.allocated_buf_.base) {
                    if constexpr (AllocInvocable0<AllocCb>) {
                        self.allocated_buf_ = raw_type<uv_buf_t>(self.alloc_cb_(suggested_size));
                    }
                    else if constexpr (AllocInvocable1<AllocCb>) {
                        self.allocated_buf_ = raw_type<uv_buf_t>(self.alloc_cb_());
                    }
                    else if constexpr (AllocInvocable2<AllocCb>) {
                        auto [base, size] = self.alloc_cb_(suggested_size);
                        self.allocated_buf_ = uv_buf_init((char *)base, (unsigned int)size);
                    }
                    else if constexpr (AllocInvocable3<AllocCb>) {
                        auto [base, size] = self.alloc_cb_();
                        self.allocated_buf_ = uv_buf_init((char *)base, (unsigned int)size);
                    }
                    else if constexpr (std::invocable<AllocCb, size_t, uv_buf_t *>) {
                        self.alloc_cb_(suggested_size, &self.allocated_buf_);
                    }
                }
                *buf = self.allocated_buf_;
            },
            [](uv_stream_t *handle, ssize_t nread, const uv_buf_t *) {
                auto &self = *static_cast<ReadAwaiter *>(handle->data);
                // libuv: nread == 0 is EAGAIN/EWOULDBLOCK, not EOF (EOF is UV_EOF).
                if (nread == 0) return;
                uv_read_stop(handle);
                self.nread_ = nread;
                self.parent_.resume();
            });

        if (r < 0) {
            handle_->data = handle_data;
            nread_ = r;
            h.resume();
            return;
        }
        parent_ = h;
    }
    ssize_t await_resume() noexcept { return nread_; }
    auto await_cancel(std::coroutine_handle<>) noexcept {
        uv_read_stop(handle_);
        handle_->data = nullptr;
        return std::true_type{};
    }

  private:
    uv_stream_t *handle_;
    std::coroutine_handle<> parent_{};
    ssize_t nread_{};
    uv_buf_t allocated_buf_{};
    AllocCb alloc_cb_;
};

// uv_write
struct WriteAwaiter {
  public:
    template <RawTypeCastable<uv_stream_t *> StreamPtr, RawTypeCastable<uv_stream_t *> StreamPtr2 = uv_stream_t *>
    WriteAwaiter(StreamPtr &&handle, const uv_buf_t *bufs, size_t nbufs, StreamPtr2 &&send_handle = nullptr)
        : handle_(raw_type<uv_stream_t *>(std::forward<StreamPtr>(handle))), bufs_(bufs), nbufs_(nbufs),
          send_handle_(raw_type<uv_stream_t *>(std::forward<StreamPtr2>(send_handle))) {}
    template <RawTypeCastable<uv_stream_t *> StreamPtr, RawTypeCastable<uv_stream_t *> StreamPtr2 = uv_stream_t *>
    WriteAwaiter(StreamPtr &&handle, const uv_buf_t &buf, StreamPtr2 &&send_handle = nullptr)
        : handle_(raw_type<uv_stream_t *>(std::forward<StreamPtr>(handle))), bufs_(&buf), nbufs_(1),
          send_handle_(raw_type<uv_stream_t *>(std::forward<StreamPtr2>(send_handle))) {}
    WriteAwaiter(const WriteAwaiter &) = delete;
    WriteAwaiter(WriteAwaiter &&) = delete;
    WriteAwaiter &operator=(const WriteAwaiter &) = delete;
    WriteAwaiter &operator=(WriteAwaiter &&) = delete;

    bool await_ready() const noexcept { return std::false_type{}; }
    void await_suspend(std::coroutine_handle<> h) noexcept {
        auto r = uv_write2(&req_, handle_, bufs_, (unsigned int)nbufs_, send_handle_, [](uv_write_t *req, int status) {
            auto &self = *static_cast<WriteAwaiter *>(req->data);
            self.status_ = status;
            self.parent_.resume();
        });
        if (r < 0) {
            status_ = r;
            h.resume();
            return;
        }
        req_.data = this;
        parent_ = h;
    }
    int await_resume() noexcept { return status_; }

  private:
    uv_stream_t *handle_;
    std::coroutine_handle<> parent_{};
    union {
        uv_write_t req_;
        int status_;
    };
    const uv_buf_t *bufs_;
    size_t nbufs_;
    uv_stream_t *send_handle_;
};

struct ShutdownAwaiter {
  public:
    template <RawTypeCastable<uv_stream_t *> StreamPtr>
    ShutdownAwaiter(StreamPtr &&handle) : handle_(raw_type<uv_stream_t *>(std::forward<StreamPtr>(handle))) {}
    ShutdownAwaiter(const ShutdownAwaiter &) = delete;
    ShutdownAwaiter(ShutdownAwaiter &&) = delete;
    ShutdownAwaiter &operator=(const ShutdownAwaiter &) = delete;
    ShutdownAwaiter &operator=(ShutdownAwaiter &&) = delete;

    bool await_ready() const noexcept { return std::false_type{}; }
    void await_suspend(std::coroutine_handle<> h) noexcept {
        auto r = uv_shutdown(&req_, handle_, [](uv_shutdown_t *req, int status) {
            auto &self = *static_cast<ShutdownAwaiter *>(req->data);
            self.status_ = status;
            self.parent_.resume();
        });
        if (r < 0) {
            status_ = r;
            h.resume();
            return;
        }
        req_.data = this;
        parent_ = h;
    }
    int await_resume() noexcept { return status_; }

  private:
    uv_stream_t *handle_;
    std::coroutine_handle<> parent_{};
    union {
        uv_shutdown_t req_;
        int status_;
    };
};

} // namespace detail

struct sockaddr_in46 {
  private:
    union {
        sockaddr raw;
        sockaddr_in in4;
        sockaddr_in6 in6;
    } addr_{};

  public:
    sockaddr_in46() noexcept {}

    auto set(const char *ip, int port) noexcept {
        addr_.in6 = sockaddr_in6{};
        if (uv_ip4_addr(ip, port, &addr_.in4) < 0 && uv_ip6_addr(ip, port, &addr_.in6) < 0) {
            addr_.in6 = sockaddr_in6{};
        }
        return *this;
    }

    auto set(const std::string &ip, int port) noexcept {
        addr_.in6 = sockaddr_in6{};
        if (uv_ip4_addr(ip.c_str(), port, &addr_.in4) < 0 && uv_ip6_addr(ip.c_str(), port, &addr_.in6) < 0) {
            addr_.in6 = sockaddr_in6{};
        }
        return *this;
    }

    auto set(const sockaddr *sa) noexcept {
        auto sa_family = sa ? sa->sa_family : 0;
        addr_.in6 = sockaddr_in6{};
        if (sa_family == AF_INET) {
            addr_.in4 = *reinterpret_cast<const sockaddr_in *>(sa);
        }
        else if (sa_family == AF_INET6) {
            addr_.in6 = *reinterpret_cast<const sockaddr_in6 *>(sa);
        }
        return *this;
    }

    auto set(const sockaddr *sa, int port) {
        auto sa_family = sa ? sa->sa_family : 0;
        addr_.in6 = sockaddr_in6{};
        if (sa_family == AF_INET) {
            addr_.in4 = *reinterpret_cast<const sockaddr_in *>(sa);
            addr_.in4.sin_port = htons((uint16_t)port);
        }
        else if (sa_family == AF_INET6) {
            addr_.in6 = *reinterpret_cast<const sockaddr_in6 *>(sa);
            addr_.in6.sin6_port = htons((uint16_t)port);
        }
        return *this;
    }

    sockaddr_in46(const char *ip, int port) noexcept { set(ip, port); }
    sockaddr_in46(const std::string &ip, int port) noexcept { set(ip, port); }
    sockaddr_in46(const sockaddr *sa) noexcept { set(sa); }
    sockaddr_in46(const sockaddr *sa, int port) noexcept { set(sa, port); }
    sockaddr_in46(const sockaddr_storage &ss) noexcept { set(reinterpret_cast<const sockaddr *>(&ss)); }
    sockaddr_in46(const sockaddr_storage &ss, int port) noexcept { set(reinterpret_cast<const sockaddr *>(&ss), port); }
    sockaddr_in46(const sockaddr_in &in4) noexcept {
        if (in4.sin_family == AF_INET) {
            addr_.in4 = in4;
        }
    }
    sockaddr_in46(const sockaddr_in &in4, int port) noexcept {
        if (in4.sin_family == AF_INET) {
            addr_.in4 = in4;
            addr_.in4.sin_port = htons((uint16_t)port);
        }
    }
    sockaddr_in46(const sockaddr_in6 &in6) noexcept {
        if (in6.sin6_family == AF_INET6) {
            addr_.in6 = in6;
        }
    }
    sockaddr_in46(const sockaddr_in6 &in6, int port) noexcept {
        if (in6.sin6_family == AF_INET6) {
            addr_.in6 = in6;
            addr_.in6.sin6_port = htons((uint16_t)port);
        }
    }

    bool is_in4() const noexcept { return addr_.raw.sa_family == AF_INET; }
    bool is_in6() const noexcept { return addr_.raw.sa_family == AF_INET6; }
    operator bool() const noexcept { return is_in4() || is_in6(); }

    auto &in4() const noexcept { return addr_.in4; }
    auto &in6() const noexcept { return addr_.in6; }
    auto &in4() noexcept { return addr_.in4; }
    auto &in6() noexcept { return addr_.in6; }

    const sockaddr *get() const noexcept { return reinterpret_cast<const sockaddr *>(&addr_); }
    sockaddr *get() noexcept { return reinterpret_cast<sockaddr *>(&addr_); }

    size_t size() const noexcept {
        if (is_in4()) {
            return sizeof(sockaddr_in);
        }
        else if (is_in6()) {
            return sizeof(sockaddr_in6);
        }
        return 0;
    }

    std::string name() const noexcept {
        char buf[INET6_ADDRSTRLEN]{};
        if (is_in4()) {
            uv_ip4_name(&addr_.in4, buf, sizeof(buf));
        }
        else if (is_in6()) {
            uv_ip6_name(&addr_.in6, buf, sizeof(buf));
        }
        return std::string(buf);
    }

    int port() const noexcept {
        if (is_in4()) {
            return ntohs(addr_.in4.sin_port);
        }
        else if (is_in6()) {
            return ntohs(addr_.in6.sin6_port);
        }
        return 0;
    }
};

template <typename T>
struct SockAddrRefOrValue {
    using type = sockaddr_in46;
};
template <>
struct SockAddrRefOrValue<const sockaddr_in46 &> {
    using type = const sockaddr_in46 &;
};
template <typename T>
using SockAddrType = SockAddrRefOrValue<T>::type;

template <RawTypeCastable<uv_tcp_t *> StreamPtr, typename SockAddr>
    requires std::convertible_to<SockAddr, sockaddr_in46>
corral::Awaitable<int> auto connect(StreamPtr &&handle, SockAddr &&sa) {
    return corral::makeAwaitable<detail::TcpConnectAwaiter, StreamPtr, SockAddrType<SockAddr>>(
        std::forward<StreamPtr>(handle), std::forward<SockAddr>(sa));
}

template <RawTypeCastable<uv_pipe_t *> StreamPtr>
corral::Awaitable<int> auto connect(StreamPtr &&handle, std::string_view name, unsigned int flags = 0) {
    return corral::makeAwaitable<detail::PipeConnectAwaiter, StreamPtr>(std::forward<StreamPtr>(handle), name, flags);
}

template <RawTypeCastable<uv_stream_t *> StreamPtr, detail::AllocInvocable AllocCb>
corral::Awaitable<ssize_t> auto read(StreamPtr &&handle, AllocCb &&alloc_cb) {
    return corral::makeAwaitable<detail::ReadAwaiter<AllocCb>, StreamPtr, AllocCb>(
        std::forward<StreamPtr>(handle), std::forward<AllocCb>(alloc_cb));
}

template <
    RawTypeCastable<uv_stream_t *> StreamPtr,
    typename Buf,
    RawTypeCastable<uv_stream_t *> StreamPtr2 = uv_stream_t *>
    requires std::convertible_to<Buf *, uv_buf_t *> && (sizeof(Buf) == sizeof(uv_buf_t))
corral::Awaitable<ssize_t> auto write(
    StreamPtr &&handle, const Buf *bufs, size_t nbufs, StreamPtr2 &&send_handle = nullptr) {
    return corral::makeAwaitable<detail::WriteAwaiter, StreamPtr, const uv_buf_t *, size_t, StreamPtr2>(
        std::forward<StreamPtr>(handle), bufs, nbufs, std::forward<StreamPtr2>(send_handle));
}

template <
    RawTypeCastable<uv_stream_t *> StreamPtr,
    typename Buf,
    RawTypeCastable<uv_stream_t *> StreamPtr2 = uv_stream_t *>
    requires RawTypeCastable<Buf, uv_buf_t>
corral::Awaitable<ssize_t> auto write(StreamPtr &&handle, Buf &&buf, StreamPtr2 &&send_handle = nullptr) {
    return corral::makeAwaitable<detail::WriteAwaiter, StreamPtr, uv_buf_t, StreamPtr2>(
        std::forward<StreamPtr>(handle),
        raw_type<uv_buf_t>(std::forward<Buf>(buf)),
        std::forward<StreamPtr2>(send_handle));
}

template <RawTypeCastable<uv_stream_t *> StreamPtr>
corral::Awaitable<int> auto shutdown(StreamPtr &&handle) {
    return corral::makeAwaitable<detail::ShutdownAwaiter, StreamPtr>(std::forward<StreamPtr>(handle));
}

namespace detail {

// uv_queue_work
template <typename WorkCb>
    requires std::invocable<WorkCb>
struct WorkAwaiter {
  public:
    WorkAwaiter(uv_loop_t *loop, WorkCb &&work_cb) : loop_(loop), work_cb_(std::forward<WorkCb>(work_cb)) {}
    WorkAwaiter(const WorkAwaiter &) = delete;
    WorkAwaiter(WorkAwaiter &&) = delete;
    WorkAwaiter &operator=(const WorkAwaiter &) = delete;
    WorkAwaiter &operator=(WorkAwaiter &&) = delete;

    bool await_ready() const noexcept { return std::false_type{}; }
    void await_suspend(std::coroutine_handle<> h) noexcept {
        req_.data = this;
        parent_ = h;
        auto r = uv_queue_work(
            loop_,
            &req_,
            [](uv_work_t *req) {
                auto &self = *static_cast<WorkAwaiter *>(req->data);
                self.work_cb_();
            },
            [](uv_work_t *req, int status) {
                auto &self = *static_cast<WorkAwaiter *>(req->data);
                self.status_ = status;
                self.parent_.resume();
            });
        if (r < 0) {
            status_ = r;
            parent_.resume();
        }
    }
    int await_resume() noexcept { return status_; }
    auto await_cancel(std::coroutine_handle<>) noexcept {
        uv_cancel(reinterpret_cast<uv_req_t *>(&req_));
        return false; // FIXME: return std::false_type{};
    }
    auto await_must_resume() const noexcept { return status_ != UV_ECANCELED; }

  private:
    uv_loop_t *loop_;
    std::coroutine_handle<> parent_{};
    union {
        uv_work_t req_;
        int status_;
    };
    WorkCb work_cb_;
};

// TODO: uv_getaddrinfo
// TODO: uv_getnameinfo

} // namespace detail

template <typename WorkCb>
    requires std::invocable<WorkCb>
corral::Awaitable<int> auto queue_work(uv_loop_t *loop, WorkCb &&work_cb) {
    return corral::makeAwaitable<detail::WorkAwaiter<WorkCb>, uv_loop_t *, WorkCb>(loop, std::forward<WorkCb>(work_cb));
}

} // namespace auv

namespace corral {
template <>
struct EventLoopTraits<uv_loop_t> {
    static void run(uv_loop_t &loop) { uv_run(&loop, UV_RUN_DEFAULT); }
    static void stop(uv_loop_t &loop) { uv_stop(&loop); }

    static EventLoopID eventLoopID(uv_loop_t &loop) { return EventLoopID(&loop); }
};
} // namespace corral
#endif
