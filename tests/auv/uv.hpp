#ifndef AUV_STREAM_UV_HPP_
#define AUV_STREAM_UV_HPP_

#include <memory_resource>
#include <tuple>
#include <type_traits>
#include <utility>

#include "error.hpp"
#include "stream.hpp"
#include "uv/core.hpp"

namespace auv {
namespace detail {

template <class T, class... Rest>
struct last_type {
    using type = typename last_type<Rest...>::type;
};

template <class T>
struct last_type<T> {
    using type = T;
};

template <class... Types>
using last_type_t = typename last_type<Types...>::type;

} // namespace detail

struct uv_error_category : std::error_category {
    const char *name() const noexcept override { return "uv"; }
    std::string message(int err) const override { return uv_strerror(err); }

    std::error_condition default_error_condition(int ev) const noexcept override {
        if (ev >= 0) return std::error_condition{};
        if (ev == UV_EOF) return make_error_condition(errc::eof);
        if (ev == UV_ESHUTDOWN) return std::make_error_condition(std::errc::not_connected);
        switch (ev) {
        case UV_ENOBUFS: return std::make_error_condition(std::errc::no_buffer_space);
        case UV_ENOMEM: return std::make_error_condition(std::errc::not_enough_memory);
        case UV_EPIPE: return std::make_error_condition(std::errc::broken_pipe);
        case UV_ECONNRESET: return std::make_error_condition(std::errc::connection_reset);
        case UV_ECONNREFUSED: return std::make_error_condition(std::errc::connection_refused);
        case UV_ECONNABORTED: return std::make_error_condition(std::errc::connection_aborted);
        case UV_ENOTCONN: return std::make_error_condition(std::errc::not_connected);
        case UV_ETIMEDOUT: return std::make_error_condition(std::errc::timed_out);
        case UV_ECANCELED: return std::make_error_condition(std::errc::operation_canceled);
        case UV_EAGAIN: return std::make_error_condition(std::errc::resource_unavailable_try_again);
#if defined(UV_EWOULDBLOCK) && UV_EWOULDBLOCK != UV_EAGAIN
        case UV_EWOULDBLOCK: return std::make_error_condition(std::errc::resource_unavailable_try_again);
#endif
        case UV_EPROTO: return std::make_error_condition(std::errc::protocol_error);
        case UV_EINVAL: return std::make_error_condition(std::errc::invalid_argument);
        case UV_ENOENT: return std::make_error_condition(std::errc::no_such_file_or_directory);
        case UV_EACCES: return std::make_error_condition(std::errc::permission_denied);
        case UV_EADDRINUSE: return std::make_error_condition(std::errc::address_in_use);
        case UV_EADDRNOTAVAIL: return std::make_error_condition(std::errc::address_not_available);
        case UV_EAFNOSUPPORT: return std::make_error_condition(std::errc::address_family_not_supported);
        case UV_ENETUNREACH: return std::make_error_condition(std::errc::network_unreachable);
        case UV_ENETDOWN: return std::make_error_condition(std::errc::network_down);
        case UV_EHOSTUNREACH: return std::make_error_condition(std::errc::host_unreachable);
        case UV_EMFILE: return std::make_error_condition(std::errc::too_many_files_open);
        case UV_ENOSPC: return std::make_error_condition(std::errc::no_space_on_device);
        case UV_EPERM: return std::make_error_condition(std::errc::operation_not_permitted);
        case UV_ENOSYS: return std::make_error_condition(std::errc::function_not_supported);
        case UV_EEXIST: return std::make_error_condition(std::errc::file_exists);
        case UV_EIO: return std::make_error_condition(std::errc::io_error);
        case UV_EINTR: return std::make_error_condition(std::errc::interrupted);
        case UV_EISDIR: return std::make_error_condition(std::errc::is_a_directory);
        case UV_ENOTDIR: return std::make_error_condition(std::errc::not_a_directory);
        case UV_EMSGSIZE: return std::make_error_condition(std::errc::message_size);
        case UV_ENOTSOCK: return std::make_error_condition(std::errc::not_a_socket);
        default: return std::error_condition(ev, *this);
        }
    }

    static const uv_error_category &instance() {
        static const uv_error_category category;
        return category;
    }
};

inline std::error_code make_uv_error_code(int err) {
    return std::error_code(err < 0 ? err : 0, uv_error_category::instance());
}

inline std::error_code make_uv_error_code(ssize_t err) {
    return std::error_code(
        err < 0 ? (static_cast<int>(err) < 0 ? static_cast<int>(err) : UV_UNKNOWN) : 0, uv_error_category::instance());
}

inline std::error_code make_uv_error_code(uv_errno_t err) {
    return std::error_code(static_cast<int>(err), uv_error_category::instance());
}

class uv_stream {
  public:
    uv_stream() noexcept = default;
    uv_stream(uv_stream_t *stream, std::pmr::memory_resource *resource = std::pmr::get_default_resource()) noexcept
        : stream_(stream), owner_() {
        (void)resource;
    }

    uv_stream(uv_stream_t *stream, std::pmr::memory_resource *resource, detail::lifetime_owner owner) noexcept
        : stream_(stream), owner_(std::move(owner)) {
        (void)resource;
    }

    uv_stream(const uv_stream &) = delete;
    uv_stream &operator=(const uv_stream &) = delete;
    uv_stream(uv_stream &&) noexcept = default;
    uv_stream &operator=(uv_stream &&) noexcept = default;

    uv_stream_t *native_handle() const noexcept { return stream_; }

    operator stream() & { return stream::construct(stream_, erased_vtable(), {}); }
    operator stream() && { return stream::construct(stream_, erased_vtable(), std::move(owner_)); }

    // alloc_cb must be valid until read is completed
    template <typename Allocator>
        requires detail::read_allocator_callable<std::remove_reference_t<Allocator>>
    auto read(Allocator &&alloc_cb) {
        return read(
            [](void *p) {
                auto &cb = *static_cast<std::remove_reference_t<Allocator> *>(p);
                return static_cast<buffer>(cb());
            },
            &alloc_cb);
    }

    auto read(buffer dest) {
        return corral::just(dest) | corral::then([&](auto &buf) {
                   return read([](void *p) { return *static_cast<buffer *>(p); }, &buf);
               });
    }

    template <typename... Args>
    auto write(Args &&...args) {
        return corral::just(make_buffer_sequence(std::forward<Args>(args)...)) |
               corral::then([&](auto &buffers) { return write(buffers.data(), buffers.size()); });
    }

    template <typename... Args>
        requires std::same_as<std::remove_cvref_t<detail::last_type_t<Args...>>, uv_stream_t *>
    auto write2(Args &&...args) {
        auto tuple = std::make_tuple(std::forward<Args>(args)...);
        return [&]<std::size_t... Is>(std::index_sequence<Is...>) {
            auto seq = make_buffer_sequence(std::get<Is>(tuple)...);
            auto *send_handle = std::get<sizeof...(Is)>(tuple);
            return corral::just(std::move(seq)) | corral::then([this, send_handle](auto &buffers) {
                       return write2(buffers.data(), buffers.size(), send_handle);
                   });
        }(std::make_index_sequence<sizeof...(Args) - 1>{});
    }

    corral::Task<read_result> read(read_allocator alloc_cb, void *alloc_arg) {
        auto n = co_await auv::read(stream_, [=]() {
            auto buf = alloc_cb(alloc_arg);
            return uv_buf_init(buf.data(), static_cast<unsigned int>(buf.size()));
        });
        if (n < 0) co_return read_result{make_uv_error_code(n), 0};
        co_return read_result{std::error_code{}, static_cast<size_t>(n)};
    }

    corral::Task<std::error_code> write(const buffer *bufs, size_t nbufs) {
        auto err = co_await auv::write(stream_, reinterpret_cast<const uv_buf_t *>(bufs), nbufs);
        co_return make_uv_error_code(err);
    }

    corral::Task<std::error_code> write2(const buffer *bufs, size_t nbufs, uv_stream_t *send_handle) {
        auto err = co_await auv::write(stream_, reinterpret_cast<const uv_buf_t *>(bufs), nbufs, send_handle);
        co_return make_uv_error_code(err);
    }

    corral::Task<std::error_code> shutdown() {
        auto err = co_await auv::shutdown(stream_);
        co_return make_uv_error_code(err);
    }

    corral::Task<void> close() { co_await auv::close(stream_); }

  private:
    static const stream_vtable *erased_vtable() {
        static const stream_vtable vtable{
            [](void *self, read_allocator alloc_cb, void *alloc_arg) -> corral::Task<read_result> {
                auto n = co_await auv::read(static_cast<uv_stream_t *>(self), [=]() {
                    auto buf = alloc_cb(alloc_arg);
                    return uv_buf_init(buf.data(), static_cast<unsigned int>(buf.size()));
                });
                if (n < 0) co_return read_result{make_uv_error_code(n), 0};
                co_return read_result{std::error_code{}, static_cast<size_t>(n)};
            },
            [](void *self, const buffer *bufs, size_t nbufs) -> corral::Task<std::error_code> {
                auto err = co_await auv::write(
                    static_cast<uv_stream_t *>(self), reinterpret_cast<const uv_buf_t *>(bufs), nbufs);
                co_return make_uv_error_code(err);
            },
            [](void *self) -> corral::Task<std::error_code> {
                auto err = co_await auv::shutdown(static_cast<uv_stream_t *>(self));
                co_return make_uv_error_code(err);
            },
            [](void *self) -> corral::Task<void> { co_await auv::close(static_cast<uv_stream_t *>(self)); },
        };
        return &vtable;
    }

    uv_stream_t *stream_ = nullptr;
    detail::lifetime_owner owner_{};
};

template <typename S>
    requires auv::RawTypeCastable<S, uv_stream_t *>
uv_stream make_uv_stream(S &&stream, std::pmr::memory_resource *resource = std::pmr::get_default_resource()) {
    using type = std::remove_cvref_t<S>;
    if constexpr (std::is_pointer_v<type> || std::is_lvalue_reference_v<S>) {
        return uv_stream(auv::raw_type<uv_stream_t *>(stream), resource);
    }
    else {
        auto owner = detail::lifetime_owner::emplace<type>(resource, std::forward<S>(stream));
        auto *stored = owner.template get<type>();
        return uv_stream(auv::raw_type<uv_stream_t *>(*stored), resource, std::move(owner));
    }
}

} // namespace auv

#endif
