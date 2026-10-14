#ifndef AUV_STREAM_HPP_
#define AUV_STREAM_HPP_

#include <memory>
#include <memory_resource>
#include <system_error>
#include <tuple>
#include <type_traits>
#include <utility>

#include <corral/Executor.h>
#include <corral/Nursery.h>
#include <corral/Task.h>
#include <corral/wait.h>

#include "buffer.hpp"

namespace auv {

using read_allocator = buffer (*)(void *);
using read_result = std::tuple<std::error_code, size_t>;

struct stream_vtable {
    corral::Task<read_result> (*read)(void *self, read_allocator alloc_cb, void *alloc_arg);
    corral::Task<std::error_code> (*write)(void *self, const buffer *bufs, size_t nbufs);
    corral::Task<std::error_code> (*shutdown)(void *self);
    corral::Task<void> (*close)(void *self);
};

class stream;

namespace detail {

struct owned_block_base {
    void (*destroy)(owned_block_base *) noexcept = nullptr;
};

template <typename T>
struct owned_block final : owned_block_base {
    template <typename... Args>
    owned_block(std::pmr::memory_resource *resource, Args &&...args)
        : resource(resource), value(std::forward<Args>(args)...) {
        this->destroy = &destroy_self;
    }

    static void destroy_self(owned_block_base *base) noexcept {
        auto *self = static_cast<owned_block *>(base);
        auto *resource = self->resource;
        std::pmr::polymorphic_allocator<owned_block> alloc(resource);
        std::destroy_at(self);
        alloc.deallocate(self, 1);
    }

    std::pmr::memory_resource *resource;
    T value;
};

template <typename T, typename... Args>
owned_block<T> *allocate_owned_block(std::pmr::memory_resource *resource, Args &&...args) {
    std::pmr::polymorphic_allocator<owned_block<T>> alloc(resource);
    auto *block = alloc.allocate(1);
    try {
        std::construct_at(block, resource, std::forward<Args>(args)...);
    }
    catch (...) {
        alloc.deallocate(block, 1);
        throw;
    }
    return block;
}

template <typename T>
concept read_allocator_callable = requires(T &t) { static_cast<buffer>(t()); };

template <typename T>
concept stream_like = requires(T &t, read_allocator alloc_cb, void *alloc_arg, const buffer *bufs, size_t nbufs) {
    { t.read(alloc_cb, alloc_arg) } -> std::same_as<corral::Task<read_result>>;
    { t.write(bufs, nbufs) } -> std::same_as<corral::Task<std::error_code>>;
    { t.shutdown() } -> std::same_as<corral::Task<std::error_code>>;
    { t.close() } -> std::same_as<corral::Task<void>>;
};

template <typename T>
concept lvalue_stream_castable = requires(T &t) {
    { static_cast<stream>(t) } -> std::same_as<stream>;
};

template <typename T>
concept rvalue_stream_castable = requires(T &&t) {
    { static_cast<stream>(std::move(t)) } -> std::same_as<stream>;
};

template <typename T>
struct stream_model {
    static corral::Task<read_result> read(void *self, read_allocator alloc_cb, void *alloc_arg) {
        return static_cast<T *>(self)->read(alloc_cb, alloc_arg);
    }

    static corral::Task<std::error_code> write(void *self, const buffer *bufs, size_t nbufs) {
        return static_cast<T *>(self)->write(bufs, nbufs);
    }

    static corral::Task<std::error_code> shutdown(void *self) { return static_cast<T *>(self)->shutdown(); }

    static corral::Task<void> close(void *self) { return static_cast<T *>(self)->close(); }

    static const stream_vtable *vtable() {
        static const stream_vtable vt{
            &read,
            &write,
            &shutdown,
            &close,
        };
        return &vt;
    }
};

class lifetime_owner {
  public:
    lifetime_owner() noexcept = default;
    lifetime_owner(const lifetime_owner &) = delete;
    lifetime_owner &operator=(const lifetime_owner &) = delete;

    lifetime_owner(lifetime_owner &&other) noexcept : block_(std::exchange(other.block_, nullptr)) {}

    lifetime_owner &operator=(lifetime_owner &&other) noexcept {
        if (this != &other) {
            reset();
            block_ = std::exchange(other.block_, nullptr);
        }
        return *this;
    }

    ~lifetime_owner() { reset(); }

    template <typename T, typename... Args>
    static lifetime_owner emplace(std::pmr::memory_resource *resource, Args &&...args) {
        lifetime_owner owner;
        owner.block_ = allocate_owned_block<T>(resource, std::forward<Args>(args)...);
        return owner;
    }

    template <typename T>
    T *get() const noexcept {
        if (!block_) {
            return nullptr;
        }
        return std::addressof(static_cast<owned_block<T> *>(block_)->value);
    }

    explicit operator bool() const noexcept { return block_ != nullptr; }

    void reset() noexcept {
        if (block_) {
            block_->destroy(block_);
            block_ = nullptr;
        }
    }

  private:
    owned_block_base *block_ = nullptr;
};

} // namespace detail

class stream {
  public:
    stream() noexcept = default;

    stream(const stream &) = delete;
    stream &operator=(const stream &) = delete;

    stream(stream &&other) noexcept
        : self_(std::exchange(other.self_, nullptr)), vtable_(std::exchange(other.vtable_, nullptr)),
          owner_(std::move(other.owner_)) {}

    stream &operator=(stream &&other) noexcept {
        if (this != &other) {
            reset();
            self_ = std::exchange(other.self_, nullptr);
            vtable_ = std::exchange(other.vtable_, nullptr);
            owner_ = std::move(other.owner_);
        }
        return *this;
    }

    ~stream() { reset(); }

    explicit operator bool() const noexcept { return self_ != nullptr; }

    void reset() noexcept {
        owner_.reset();
        self_ = nullptr;
        vtable_ = nullptr;
    }

    static stream construct(void *self, const stream_vtable *vtable, detail::lifetime_owner owner) noexcept {
        return stream(self, vtable, std::move(owner));
    }

    static stream borrow(stream &other) noexcept { return stream(other.self_, other.vtable_, {}); }

    template <typename T>
        requires(!std::same_as<std::remove_cvref_t<T>, stream> && detail::lvalue_stream_castable<T>)
    static stream borrow(T &obj) {
        return static_cast<stream>(obj);
    }

    template <typename T>
        requires(
            !std::same_as<std::remove_cvref_t<T>, stream> && !detail::lvalue_stream_castable<T> &&
            detail::stream_like<T>)
    static stream borrow(T &obj) noexcept {
        return stream(std::addressof(obj), detail::stream_model<T>::vtable(), {});
    }

    static stream own(stream &&other) noexcept { return std::move(other); }

    template <typename T>
        requires(
            !std::is_lvalue_reference_v<T> && !std::same_as<std::remove_cvref_t<T>, stream> &&
            detail::rvalue_stream_castable<T>)
    static stream own(T &&obj, std::pmr::memory_resource * = std::pmr::get_default_resource()) {
        return static_cast<stream>(std::forward<T>(obj));
    }

    template <typename T>
        requires(
            !std::is_lvalue_reference_v<T> && !std::same_as<std::remove_cvref_t<T>, stream> &&
            !detail::rvalue_stream_castable<T> && detail::stream_like<std::remove_cvref_t<T>>)
    static stream own(T &&obj, std::pmr::memory_resource *resource = std::pmr::get_default_resource()) {
        using type = std::remove_cvref_t<T>;
        auto owner = detail::lifetime_owner::emplace<type>(resource, std::forward<T>(obj));
        type *self = owner.template get<type>();
        return construct(self, detail::stream_model<type>::vtable(), std::move(owner));
    }

    template <typename T, typename... Args>
        requires detail::stream_like<T>
    static stream emplace(Args &&...args) {
        return emplace_with_resource<T>(std::pmr::get_default_resource(), std::forward<Args>(args)...);
    }

    template <typename T, typename... Args>
        requires detail::stream_like<T>
    static stream emplace_with_resource(std::pmr::memory_resource *resource, Args &&...args) {
        auto owner = detail::lifetime_owner::emplace<T>(resource, std::forward<Args>(args)...);
        T *self = owner.template get<T>();
        return construct(self, detail::stream_model<T>::vtable(), std::move(owner));
    }

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

    corral::Task<read_result> read(read_allocator alloc_cb, void *alloc_arg) {
        if (!*this) {
            return corral::just(read_result{std::make_error_code(std::errc::not_connected), 0});
        }
        return vtable_->read(self_, alloc_cb, alloc_arg);
    }

    corral::Task<std::error_code> write(const buffer *bufs, size_t nbufs) {
        if (!*this) {
            return corral::just(std::make_error_code(std::errc::not_connected));
        }
        return vtable_->write(self_, bufs, nbufs);
    }

    corral::Task<std::error_code> shutdown() {
        if (!*this) {
            return corral::just(std::make_error_code(std::errc::not_connected));
        }
        return vtable_->shutdown(self_);
    }

    corral::Task<void> close() {
        if (!*this) {
            return corral::noop();
        }
        return vtable_->close(self_);
    }

  private:
    stream(void *self, const stream_vtable *vtable, detail::lifetime_owner owner) noexcept
        : self_(self), vtable_(vtable), owner_(std::move(owner)) {}

    void *self_ = nullptr;
    const stream_vtable *vtable_ = nullptr;
    detail::lifetime_owner owner_{};
};

} // namespace auv

#endif
