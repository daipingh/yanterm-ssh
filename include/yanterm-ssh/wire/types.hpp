#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/error.hpp>

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <span>
#include <string_view>
#include <system_error>
#include <vector>

namespace yanterm::ssh::wire {

// A borrowed, comma-separated list of US-ASCII names (RFC 4251 section 5).
// Validation happens in reader::read_name_list; by the time a name_list exists
// its contents are known to be well formed.
class name_list {
public:
    class iterator {
    public:
        using value_type = std::string_view;
        using difference_type = std::ptrdiff_t;
        using iterator_category = std::forward_iterator_tag;

        iterator() = default;
        iterator(std::string_view raw, std::size_t pos) noexcept : raw_{raw}, pos_{pos} {
            advance();
        }

        [[nodiscard]] std::string_view operator*() const noexcept {
            return raw_.substr(pos_, end_ - pos_);
        }
        iterator& operator++() noexcept {
            pos_ = (end_ >= raw_.size()) ? npos_ : end_ + 1;
            advance();
            return *this;
        }
        iterator operator++(int) noexcept { iterator tmp = *this; ++*this; return tmp; }

        [[nodiscard]] friend bool operator==(const iterator& a, const iterator& b) noexcept {
            return a.pos_ == b.pos_;
        }

    private:
        void advance() noexcept {
            if (pos_ == npos_ || pos_ > raw_.size()) { pos_ = npos_; end_ = npos_; return; }
            const std::size_t comma = raw_.find(',', pos_);
            end_ = (comma == std::string_view::npos) ? raw_.size() : comma;
        }

        static constexpr std::size_t npos_ = static_cast<std::size_t>(-1);
        std::string_view raw_{};
        std::size_t pos_ = npos_;
        std::size_t end_ = npos_;
    };

    name_list() = default;
    explicit name_list(std::string_view raw) noexcept : raw_{raw} {}

    [[nodiscard]] std::string_view raw() const noexcept { return raw_; }
    [[nodiscard]] bool empty() const noexcept { return raw_.empty(); }

    [[nodiscard]] iterator begin() const noexcept;
    [[nodiscard]] iterator end() const noexcept { return iterator{}; }

    [[nodiscard]] bool contains(std::string_view name) const noexcept;

private:
    std::string_view raw_{};
};

class reader {
public:
    explicit reader(std::span<const std::byte> in) noexcept : in_{in} {}

    [[nodiscard]] bool ok() const noexcept { return !ec_; }
    [[nodiscard]] std::error_code error() const noexcept { return ec_; }
    [[nodiscard]] std::size_t offset() const noexcept { return pos_; }
    [[nodiscard]] std::span<const std::byte> remaining() const noexcept { return in_.subspan(pos_); }
    [[nodiscard]] bool empty() const noexcept { return pos_ >= in_.size(); }

    bool read_bytes(std::span<const std::byte>& out, std::size_t n) noexcept;
    bool read_byte(std::uint8_t& out) noexcept;
    bool read_bool(bool& out) noexcept;
    bool read_uint32(std::uint32_t& out) noexcept;
    bool read_uint64(std::uint64_t& out) noexcept;
    bool read_string(std::span<const std::byte>& out) noexcept;
    bool read_string(std::string_view& out) noexcept;
    // Yields the canonical big-endian magnitude with leading zeros removed.
    // Negative and non-canonically encoded values are rejected.
    bool read_mpint(std::span<const std::byte>& out) noexcept;
    bool read_name_list(name_list& out) noexcept;

    // Sticky error setter for message decoders (see wire/detail/messages.hpp expect_id).
    bool fail(std::error_code e) noexcept;

private:
    static bool valid_name_list(std::string_view raw) noexcept;

    std::span<const std::byte> in_;
    std::size_t pos_ = 0;
    std::error_code ec_{};
};

class writer {
public:
    writer() = default;

    void write_byte(std::uint8_t v) { buf_.push_back(static_cast<std::byte>(v)); }
    void write_bool(bool v) { write_byte(v ? 1u : 0u); }

    void write_uint32(std::uint32_t v);
    void write_uint64(std::uint64_t v);
    void write_bytes(std::span<const std::byte> v);
    void write_string(std::span<const std::byte> v);
    void write_string(std::string_view v);
    // Takes a big-endian magnitude of a non-negative integer and emits the
    // canonical SSH mpint encoding.
    void write_mpint(std::span<const std::byte> magnitude);
    void write_name_list(std::span<const std::string_view> names);

    [[nodiscard]] std::span<const std::byte> data() const noexcept { return buf_; }
    [[nodiscard]] std::size_t size() const noexcept { return buf_.size(); }
    std::vector<std::byte> take() noexcept;
    void clear() noexcept { buf_.clear(); }
    void reserve(std::size_t n);

private:
    std::vector<std::byte> buf_;
};

// Byte sizes of the encodings writer emits. Callers that put a secret into a
// writer reserve this much first so a later insert cannot free an earlier copy.
[[nodiscard]] inline std::size_t encoded_string_size(std::size_t n) noexcept {
    return 4u + n;
}

[[nodiscard]] inline std::size_t encoded_mpint_size(std::span<const std::byte> magnitude) noexcept {
    std::size_t begin = 0;
    while (begin < magnitude.size() && magnitude[begin] == std::byte{0}) ++begin;
    const std::size_t n = magnitude.size() - begin;
    if (n == 0) return 4u;
    const bool pad = (std::to_integer<std::uint8_t>(magnitude[begin]) & 0x80u) != 0;
    return 4u + n + (pad ? 1u : 0u);
}

}  // namespace yanterm::ssh::wire

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/wire/impl/types.ipp>
#endif
