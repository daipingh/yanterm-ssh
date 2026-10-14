#pragma once

#include <yanterm-ssh/crypto/algorithms.hpp>

#include <array>
#include <cstddef>
#include <memory>
#include <span>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace yanterm::ssh::crypto {

// Frees through std::allocator after overwriting the whole block. std::vector
// growth and destruction both release memory here, so a reallocation cannot
// leave the previous secret behind.
template <class T>
class wiping_allocator {
public:
    using value_type = T;
    using is_always_equal = std::true_type;
    using propagate_on_container_move_assignment = std::true_type;

    wiping_allocator() noexcept = default;

    template <class U>
    wiping_allocator(const wiping_allocator<U>&) noexcept {}

    [[nodiscard]] T* allocate(std::size_t n) { return std::allocator<T>{}.allocate(n); }

    static void prepare_release(T* p, std::size_t n) noexcept {
        if (p == nullptr || n == 0) return;
        secure_zero(std::span<std::byte>{reinterpret_cast<std::byte*>(p), n * sizeof(T)});
    }

    void deallocate(T* p, std::size_t n) noexcept {
        prepare_release(p, n);
        if (p != nullptr) std::allocator<T>{}.deallocate(p, n);
    }

    friend bool operator==(const wiping_allocator&, const wiping_allocator&) noexcept { return true; }
    friend bool operator!=(const wiping_allocator&, const wiping_allocator&) noexcept { return false; }
};

// Heap buffer with no small-object optimization. Move steals the allocation.
// wipe() overwrites the live bytes and clear()s, but keeps the block so an
// existing view of the previous contents still sees zeros.
template <class T, class Allocator = wiping_allocator<T>>
class basic_secure_buffer {
public:
    basic_secure_buffer() = default;
    explicit basic_secure_buffer(std::size_t n) : v_(n) {}

    ~basic_secure_buffer() { wipe(); }

    basic_secure_buffer(const basic_secure_buffer&) = delete;
    basic_secure_buffer& operator=(const basic_secure_buffer&) = delete;

    basic_secure_buffer(basic_secure_buffer&& other) noexcept : v_(std::move(other.v_)) {}

    basic_secure_buffer& operator=(basic_secure_buffer&& other) noexcept {
        if (this != &other) {
            wipe();
            v_ = std::move(other.v_);
        }
        return *this;
    }

    void assign(std::span<const T> src) {
        wipe();
        if (!src.empty()) v_.assign(src.begin(), src.end());
    }

    void append(std::span<const T> src) {
        if (!src.empty()) v_.insert(v_.end(), src.begin(), src.end());
    }

    void reserve(std::size_t n) { v_.reserve(n); }

    // Zeros the allocated block, then drops the size. The storage stays so a
    // view taken before wipe() still addresses those zeros.
    void wipe() noexcept {
        if (v_.capacity() != 0 && v_.data() != nullptr) {
            secure_zero(std::span<std::byte>{reinterpret_cast<std::byte*>(v_.data()),
                                             v_.capacity() * sizeof(T)});
        }
        v_.clear();
    }

    [[nodiscard]] T* data() noexcept { return v_.data(); }
    [[nodiscard]] const T* data() const noexcept { return v_.data(); }
    [[nodiscard]] std::size_t size() const noexcept { return v_.size(); }
    [[nodiscard]] bool empty() const noexcept { return v_.empty(); }

    [[nodiscard]] std::span<T> span() noexcept { return {v_.data(), v_.size()}; }
    [[nodiscard]] std::span<const T> span() const noexcept { return {v_.data(), v_.size()}; }

private:
    std::vector<T, Allocator> v_;
};

using secure_bytes = basic_secure_buffer<std::byte>;

// Password and keyboard-interactive answers. Not a std::string: libstdc++
// moves of a short string leave the secret in the source object's SSO buffer.
class secure_string {
public:
    secure_string() = default;
    secure_string(const secure_string&) = delete;
    secure_string& operator=(const secure_string&) = delete;
    secure_string(secure_string&&) noexcept = default;
    secure_string& operator=(secure_string&&) noexcept = default;

    void assign(std::string_view s) {
        buf_.assign(std::span<const char>{s.data(), s.size()});
    }

    void wipe() noexcept { buf_.wipe(); }

    [[nodiscard]] std::string_view view() const noexcept {
        if (buf_.empty()) return {};
        return {buf_.data(), buf_.size()};
    }

    [[nodiscard]] std::size_t size() const noexcept { return buf_.size(); }
    [[nodiscard]] bool empty() const noexcept { return buf_.empty(); }

    friend bool operator==(const secure_string& a, std::string_view b) noexcept {
        return a.view() == b;
    }
    friend bool operator==(std::string_view a, const secure_string& b) noexcept {
        return b.view() == a;
    }
    friend bool operator!=(const secure_string& a, std::string_view b) noexcept {
        return !(a == b);
    }
    friend bool operator!=(std::string_view a, const secure_string& b) noexcept {
        return !(b == a);
    }

private:
    basic_secure_buffer<char> buf_;
};

// Fixed stack secret. Move copies the bytes, then wipes the source.
template <std::size_t N>
class secure_array {
public:
    secure_array() = default;
    ~secure_array() { secure_zero(std::span<std::byte>{bytes_}); }

    secure_array(const secure_array&) = delete;
    secure_array& operator=(const secure_array&) = delete;

    secure_array(secure_array&& other) noexcept : bytes_(other.bytes_) {
        secure_zero(std::span<std::byte>{other.bytes_});
    }

    secure_array& operator=(secure_array&& other) noexcept {
        if (this != &other) {
            secure_zero(std::span<std::byte>{bytes_});
            bytes_ = other.bytes_;
            secure_zero(std::span<std::byte>{other.bytes_});
        }
        return *this;
    }

    [[nodiscard]] std::span<std::byte> span() noexcept { return bytes_; }
    [[nodiscard]] std::span<const std::byte> span() const noexcept { return bytes_; }

private:
    std::array<std::byte, N> bytes_{};
};

}  // namespace yanterm::ssh::crypto
