#ifndef AUV_BUFFER_HPP_
#define AUV_BUFFER_HPP_

#include <cstddef>
#include <memory_resource>
#include <type_traits>
#include <utility>
#include <variant>

#include <array>
#include <span>
#include <vector>

namespace auv {

namespace detail {
template <typename T>
concept Char8Castable = std::integral<T> && sizeof(T) == 1;

template <typename P>
concept BufferPointerB = std::is_pointer_v<P> && Char8Castable<std::remove_pointer_t<P>>;

template <typename T>
concept BufferPairLike = requires {
    requires std::tuple_size<T>::value == 2;
    requires BufferPointerB<std::tuple_element_t<0, T>>;
    requires std::integral<std::tuple_element_t<1, T>>;
};

template <typename T>
concept BufferViewLike = requires(T t) {
    { t.data() } -> BufferPointerB;
    { t.size() } -> std::integral;
};

struct any_type_holder {
    template <typename T>
    operator T() const {
        return std::declval<T>();
    }
};

template <typename T>
auto structure_first(const T &t) {
    auto &[a, b] = t;
    return a;
}

template <typename T>
auto structure_second(const T &t) {
    auto &[a, b] = t;
    return b;
}

template <typename T>
concept StructureBufferLike = requires(T t) {
    requires std::is_aggregate_v<T> && /* only for aggregate classes */
                 std::constructible_from<T, char *, unsigned int> &&
                 !std::constructible_from<T, char *, unsigned int, any_type_holder>;
    { structure_first(t) } -> BufferPointerB;
    { structure_second(t) } -> std::integral;
};

} // namespace detail

struct native_iovec {
#if defined(_WIN32)
    // WSABUF
    unsigned long len;
    char *base;
#else
    // iovec
    char *base;
    size_t len;
#endif

    char *data() const { return base; }
    size_t size() const { return base != nullptr ? len : 0; }
};

template <detail::Char8Castable CharT, std::integral SizeT>
native_iovec make_native_iovec(CharT *data, SizeT size) {
    native_iovec b{};
    b.base = reinterpret_cast<char *>(data);
    b.len = static_cast<unsigned long>(size);
    return b;
}

struct buffer : native_iovec {
    buffer() : native_iovec({}) {}

    template <detail::Char8Castable CharT, std::integral SizeT>
    buffer(CharT *data, SizeT size) : native_iovec(make_native_iovec(data, size)) {}

    template <detail::Char8Castable CharT, std::integral SizeT>
    buffer(const CharT *data, SizeT size) : buffer(const_cast<CharT *>(data), size) {}

    template <detail::BufferViewLike T>
    buffer(const T &t) : buffer(t.data(), t.size()) {}

    template <detail::BufferPairLike T>
        requires(!detail::BufferViewLike<T>)
    buffer(const T &t) : buffer(std::get<0>(t), std::get<1>(t)) {}

    template <detail::StructureBufferLike T>
        requires(!detail::BufferViewLike<T> && !detail::BufferPairLike<T>)
    buffer(const T &t) : buffer(detail::structure_first(t), detail::structure_second(t)) {}
};

struct buffer_sequence {
    using value_type = buffer;

    struct static_sequence {
        buffer bufs[8];
        size_t nbufs;
    };

    buffer_sequence(std::pmr::memory_resource *res = std::pmr::get_default_resource())
        : storage(static_sequence{}), res_(res) {}

    template <typename BufferSequence>
    buffer_sequence(const BufferSequence &seq) {
        if (seq.size() <= 8) {
            static_sequence sseq{};
            sseq.nbufs = seq.size();
            size_t i = 0;
            for (auto &&b : seq) {
                sseq.bufs[i++] = static_cast<buffer>(b);
            }
            storage = sseq;
        }
        else {
            // Construct in place. A local pmr vector's destructor is instantiated
            // from this function and trips Clang on polymorphic_allocator::destroy.
            auto &bufs = storage.emplace<heap_vector>(res_);
            bufs.reserve(seq.size());
            for (auto &&b : seq) {
                bufs.push_back(static_cast<buffer>(b));
            }
        }
    }

    const buffer *data() const {
        return std::visit(
            [](const auto &s) -> const buffer * {
                if constexpr (std::same_as<std::remove_cvref_t<decltype(s)>, static_sequence>) {
                    return s.bufs;
                }
                else {
                    return s.data();
                }
            },
            storage);
    }

    buffer *data() {
        return std::visit(
            [](auto &s) -> buffer * {
                if constexpr (std::same_as<std::remove_cvref_t<decltype(s)>, static_sequence>) {
                    return s.bufs;
                }
                else {
                    return s.data();
                }
            },
            storage);
    }

    size_t size() const {
        return std::visit(
            [](const auto &s) -> size_t {
                if constexpr (std::same_as<std::remove_cvref_t<decltype(s)>, static_sequence>) {
                    return s.nbufs;
                }
                else {
                    return s.size();
                }
            },
            storage);
    }

    bool empty() const { return size() == 0; }

    void reserve(size_t n) {
        if (n > 8) {
            if (std::holds_alternative<static_sequence>(storage)) {
                static_sequence old = std::get<static_sequence>(storage);
                auto &bufs = storage.emplace<heap_vector>(res_);
                bufs.reserve(n);
                for (size_t i = 0; i < old.nbufs; ++i) {
                    bufs.push_back(old.bufs[i]);
                }
            }
            else {
                std::get<heap_vector>(storage).reserve(n);
            }
        }
    }

    void push_back(const buffer &b) {
        if (std::holds_alternative<static_sequence>(storage)) {
            auto &sseq = std::get<static_sequence>(storage);
            if (sseq.nbufs < 8) {
                sseq.bufs[sseq.nbufs++] = b;
            }
            else {
                static_sequence old = sseq;
                auto &bufs = storage.emplace<heap_vector>(res_);
                bufs.reserve(16);
                for (size_t i = 0; i < old.nbufs; ++i) {
                    bufs.push_back(old.bufs[i]);
                }
                bufs.push_back(b);
            }
        }
        else {
            std::get<heap_vector>(storage).push_back(b);
        }
    }

    template <typename T>
        requires(std::convertible_to<T, buffer> && !std::same_as<std::remove_cvref_t<T>, buffer>)
    void push_back(T &&b) {
        push_back(static_cast<buffer>(std::forward<T>(b)));
    }

    template <typename... Args>
    void emplace_back(Args &&...args) {
        push_back(buffer(std::forward<Args>(args)...));
    }

    const buffer &operator[](size_t idx) const {
        return std::visit(
            [idx](const auto &s) -> const buffer & {
                if constexpr (std::same_as<std::remove_cvref_t<decltype(s)>, static_sequence>) {
                    return s.bufs[idx];
                }
                else {
                    return s[idx];
                }
            },
            storage);
    }

    buffer &operator[](size_t idx) {
        return std::visit(
            [idx](auto &s) -> buffer & {
                if constexpr (std::same_as<std::remove_cvref_t<decltype(s)>, static_sequence>) {
                    return s.bufs[idx];
                }
                else {
                    return s[idx];
                }
            },
            storage);
    }

    const buffer &back() const { return (*this)[size() - 1]; }

    buffer &back() { return (*this)[size() - 1]; }

    // 迭代器支持
    const buffer *begin() const { return data(); }
    buffer *begin() { return data(); }
    const buffer *end() const { return data() + size(); }
    buffer *end() { return data() + size(); }

  private:
    using heap_vector = std::pmr::vector<buffer>;

    std::variant<heap_vector, static_sequence> storage;
    std::pmr::memory_resource *res_;
};

inline auto make_buffer_sequence(const buffer &b) { return std::span<const buffer>(&b, 1); }

inline auto make_buffer_sequence(const buffer *bufs, size_t nbufs) { return std::span<const buffer>(bufs, nbufs); }

template <typename T>
    requires std::convertible_to<T, buffer>
auto make_buffer_sequence(T &&t) {
    return std::array<buffer, 1>{buffer(std::forward<T>(t))};
}

template <typename C, typename I>
    requires std::constructible_from<buffer, C *, I>
auto make_buffer_sequence(C *data, I size) {
    return std::array<buffer, 1>{buffer(data, size)};
}

template <typename BufferSequence>
    requires std::same_as<std::remove_cv_t<typename BufferSequence::value_type>, buffer>
auto make_buffer_sequence(const BufferSequence &seq) {
    return std::span<const buffer>(seq.data(), seq.size());
}

template <typename BufferSequence>
    requires(
        !std::same_as<std::remove_cv_t<typename BufferSequence::value_type>, buffer> &&
        std::convertible_to<typename BufferSequence::value_type, buffer>)
auto make_buffer_sequence(const BufferSequence &seq) {
    return buffer_sequence(seq);
}

template <std::convertible_to<buffer>... Args>
auto make_buffer_sequence(Args &&...args) -> std::array<buffer, sizeof...(Args)> {
    return std::array<buffer, sizeof...(Args)>{buffer(std::forward<Args>(args))...};
}

} // namespace auv

#endif
