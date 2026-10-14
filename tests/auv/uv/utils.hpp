#ifndef AUV_UTILS_HPP_
#define AUV_UTILS_HPP_

#include <corral/Executor.h>
#include <corral/Nursery.h>
#include <corral/ParkingLot.h>
#include <corral/wait.h>

#include "core.hpp"

namespace auv {

template <class T>
using _StorageType = std::conditional_t<
    std::is_lvalue_reference_v<T>,
    T,                           // lvalue reference
    std::remove_reference_t<T>>; // value

#if 1
template <class... _Types>
constexpr std::tuple<_StorageType<_Types>...> make_storage(_Types &&..._Args) noexcept {
    return std::tuple<_StorageType<_Types>...>(std::forward<_Types>(_Args)...);
}

template <class... _Types, class... _Types2>
    requires(
        (std::convertible_to<_Types2, _StorageType<_Types>> && ...) &&
        !(std::same_as<_Types2, _StorageType<_Types>> && ...))
constexpr std::tuple<_StorageType<_Types>...> make_storage(_Types2 &&..._Args) noexcept {
    return std::tuple<_StorageType<_Types>...>(std::forward<_Types2>(_Args)...);
}

#else
template <class... _Types>
    requires(std::same_as<_StorageType<_Types>, _Types> && ...)
constexpr std::tuple<_Types...> make_storage(_Types &&..._Args) noexcept {
    return std::tuple<_Types...>(std::forward<_Types>(_Args)...);
}

template <class... _Types, class... _Types2>
    requires((std::convertible_to<_Types2, _StorageType<_Types>> && ...) && !(std::same_as<_Types2, _Types> && ...))
constexpr std::tuple<_StorageType<_Types>...> make_storage(_Types2 &&..._Args) noexcept {
    return std::tuple<_StorageType<_Types>...>(std::forward<_Types2>(_Args)...);
}

#endif

inline int close_handle(uv_os_fd_t fd) {
#ifdef _WIN32
    if (!CloseHandle(fd))
        return -1;
#else
    if (::close(fd))
        return -1;
#endif
    return 0;
}

inline int close_socket(uv_os_sock_t fd) {
#ifdef _WIN32
    if (closesocket(fd))
        return -1;
#else
    if (::close(fd))
        return -1;
#endif
    return 0;
}

inline int socketpair(
    uv_loop_t *loop,
    std::unique_ptr<uv_tcp_t, auv::handle_deleter> &s0,
    std::unique_ptr<uv_tcp_t, auv::handle_deleter> &s1) {
    int err;
    uv_os_sock_t sock[2];

    err = uv_socketpair(
        SOCK_STREAM,
        0,
        sock,
        UV_READABLE_PIPE | UV_WRITABLE_PIPE | UV_NONBLOCK_PIPE,
        UV_READABLE_PIPE | UV_WRITABLE_PIPE | UV_NONBLOCK_PIPE);

    if (err < 0)
        return err;

    auto tcp0 = auv::resource_tcp(loop);
    auto tcp1 = auv::resource_tcp(loop);

    err = uv_tcp_open(tcp0.get(), sock[0]);
    if (err < 0) {
        auv::close_socket(sock[0]);
        auv::close_socket(sock[1]);
        return err;
    }

    err = uv_tcp_open(tcp1.get(), sock[1]);
    if (err < 0) {
        auv::close_socket(sock[1]);
        return err;
    }

    s0 = std::move(tcp0);
    s1 = std::move(tcp1);
    return 0;
}

class acceptor {
  public:
    acceptor(uv_loop_t *loop) : loop(loop) {}

    template <typename T>
    acceptor(uv_loop_t *loop, int port, T &&host) : loop(loop) {
        bind(port, std::forward<T>(host));
    }

    acceptor(uv_loop_t *loop, int port) : loop(loop) { bind(port); }
    acceptor(uv_loop_t *loop, const std::string &unix_socket) : loop(loop) { bind(unix_socket); }

    template <typename T>
    acceptor &bind(int port, T &&host) & {
        if (!server && !n) {
            auto tcp = auv::resource_tcp(loop);
            uv_tcp_bind(tcp.get(), auv::sockaddr_in46(std::forward<T>(host), port).get(), 0);
            server.reset(reinterpret_cast<uv_stream_t *>(tcp.release()));
        }
        return *this;
    }

    acceptor &bind(int port) & { return bind(port, "::ffff:127.0.0.1"); }
    acceptor &bind(const std::string &unix_socket) & {
        if (!server && !n) {
            auto pipe = auv::resource_pipe(loop);
            uv_pipe_bind(pipe.get(), unix_socket.data());
            server.reset(reinterpret_cast<uv_stream_t *>(pipe.release()));
        }
        return *this;
    }

    int listen(int backlog = 100) {
        if (n < 0 || !server) {
            return n < 0 ? n : UV_EINVAL;
        }
        server->data = this;

        return uv_listen(server.get(), backlog, [](uv_stream_t *server, int status) {
            auto &self = *static_cast<acceptor *>(server->data);
            if (status < 0) {
                self.server.reset();
                self.n = status;
                self.cond.unparkAll();
                return;
            }
            self.n += 1;
            self.cond.unparkOne();
        });
    }

    corral::Awaitable<int> auto accept(uv_stream_t *client) {
        struct ready_or_suspend_forever {
            ready_or_suspend_forever(bool ready) : ready_(ready) {}
            bool ready_;
            bool await_ready() const noexcept { return ready_; }
            void await_suspend(std::coroutine_handle<>) noexcept {}
            void await_resume() noexcept {}
            auto await_cancel(std::coroutine_handle<>) noexcept { return std::true_type{}; }
        };
        return corral::anyOf(ready_or_suspend_forever(!server), cond.park()) | corral::then([this, client]() {
                   int r = n < 0 ? n : UV_EINVAL;
                   if (n > 0) {
                       n -= 1;
                       r = uv_accept(server.get(), client);
                   }
                   return corral::just(r);
               });
    }

  private:
    uv_loop_t *loop = nullptr;
    std::unique_ptr<uv_stream_t, auv::handle_deleter> server;
    int n{0};
    corral::ParkingLot cond;
};

} // namespace auv
#endif
