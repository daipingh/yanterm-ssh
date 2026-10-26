#pragma once

#include <yanterm-ssh/wire/types.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/wire/impl/types.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/detail/error.hpp>

namespace yanterm::ssh::wire {

YANTERM_SSH_INLINE name_list::iterator name_list::begin() const noexcept {
    return raw_.empty() ? end() : iterator{raw_, 0};
}

YANTERM_SSH_INLINE bool name_list::contains(std::string_view name) const noexcept {
    if (name.empty()) return false;
    for (std::string_view n : *this) {
        if (n == name) return true;
    }
    return false;
}

YANTERM_SSH_INLINE bool reader::read_bytes(std::span<const std::byte>& out, std::size_t n) noexcept {
    if (!ok()) return false;
    if (in_.size() - pos_ < n) return fail(code::truncated_input);
    out = in_.subspan(pos_, n);
    pos_ += n;
    return true;
}

YANTERM_SSH_INLINE bool reader::read_byte(std::uint8_t& out) noexcept {
    if (!ok()) return false;
    if (in_.size() - pos_ < 1) return fail(code::truncated_input);
    out = std::to_integer<std::uint8_t>(in_[pos_++]);
    return true;
}

YANTERM_SSH_INLINE bool reader::read_bool(bool& out) noexcept {
    std::uint8_t v = 0;
    if (!read_byte(v)) return false;
    out = (v != 0);
    return true;
}

YANTERM_SSH_INLINE bool reader::read_uint32(std::uint32_t& out) noexcept {
    if (!ok()) return false;
    if (in_.size() - pos_ < 4) return fail(code::truncated_input);
    out = (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in_[pos_ + 0])) << 24)
        | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in_[pos_ + 1])) << 16)
        | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in_[pos_ + 2])) << 8)
        | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in_[pos_ + 3])));
    pos_ += 4;
    return true;
}

YANTERM_SSH_INLINE bool reader::read_uint64(std::uint64_t& out) noexcept {
    std::uint32_t hi = 0;
    std::uint32_t lo = 0;
    if (!read_uint32(hi) || !read_uint32(lo)) return false;
    out = (static_cast<std::uint64_t>(hi) << 32) | lo;
    return true;
}

YANTERM_SSH_INLINE bool reader::read_string(std::span<const std::byte>& out) noexcept {
    std::uint32_t len = 0;
    if (!read_uint32(len)) return false;
    return read_bytes(out, len);
}

YANTERM_SSH_INLINE bool reader::read_string(std::string_view& out) noexcept {
    std::span<const std::byte> s;
    if (!read_string(s)) return false;
    out = std::string_view{reinterpret_cast<const char*>(s.data()), s.size()};
    return true;
}

YANTERM_SSH_INLINE bool reader::read_mpint(std::span<const std::byte>& out) noexcept {
    std::span<const std::byte> s;
    if (!read_string(s)) return false;
    if (s.empty()) { out = s; return true; }
    const auto first = std::to_integer<std::uint8_t>(s[0]);
    if (first & 0x80u) return fail(code::invalid_mpint);
    if (first == 0x00u) {
        if (s.size() == 1) return fail(code::invalid_mpint);
        if ((std::to_integer<std::uint8_t>(s[1]) & 0x80u) == 0) {
            return fail(code::invalid_mpint);
        }
        out = s.subspan(1);
        return true;
    }
    out = s;
    return true;
}

YANTERM_SSH_INLINE bool reader::read_name_list(name_list& out) noexcept {
    std::string_view raw;
    if (!read_string(raw)) return false;
    if (!valid_name_list(raw)) return fail(code::invalid_name_list);
    out = name_list{raw};
    return true;
}

YANTERM_SSH_INLINE bool reader::fail(std::error_code e) noexcept {
    if (!ec_) ec_ = e;
    return false;
}

YANTERM_SSH_INLINE bool reader::valid_name_list(std::string_view raw) noexcept {
    if (raw.empty()) return true;
    std::size_t run = 0;
    for (char c : raw) {
        if (c == ',') {
            if (run == 0) return false;  // empty name
            run = 0;
            continue;
        }
        const auto u = static_cast<unsigned char>(c);
        if (u <= 0x20u || u >= 0x7fu) return false;  // printable US-ASCII only
        ++run;
    }
    return run != 0;  // rejects a trailing comma
}

YANTERM_SSH_INLINE void writer::write_uint32(std::uint32_t v) {
    write_byte(static_cast<std::uint8_t>(v >> 24));
    write_byte(static_cast<std::uint8_t>(v >> 16));
    write_byte(static_cast<std::uint8_t>(v >> 8));
    write_byte(static_cast<std::uint8_t>(v));
}

YANTERM_SSH_INLINE void writer::write_uint64(std::uint64_t v) {
    write_uint32(static_cast<std::uint32_t>(v >> 32));
    write_uint32(static_cast<std::uint32_t>(v));
}

YANTERM_SSH_INLINE void writer::write_bytes(std::span<const std::byte> v) {
    buf_.insert(buf_.end(), v.begin(), v.end());
}

YANTERM_SSH_INLINE void writer::write_string(std::span<const std::byte> v) {
    write_uint32(static_cast<std::uint32_t>(v.size()));
    write_bytes(v);
}

YANTERM_SSH_INLINE void writer::write_string(std::string_view v) {
    write_string(std::span<const std::byte>{
        reinterpret_cast<const std::byte*>(v.data()), v.size()});
}

YANTERM_SSH_INLINE void writer::write_mpint(std::span<const std::byte> magnitude) {
    std::size_t begin = 0;
    while (begin < magnitude.size() && magnitude[begin] == std::byte{0}) ++begin;
    const auto mag = magnitude.subspan(begin);
    if (mag.empty()) { write_uint32(0); return; }
    const bool pad = (std::to_integer<std::uint8_t>(mag[0]) & 0x80u) != 0;
    write_uint32(static_cast<std::uint32_t>(mag.size() + (pad ? 1u : 0u)));
    if (pad) write_byte(0x00);
    write_bytes(mag);
}

YANTERM_SSH_INLINE void writer::write_name_list(std::span<const std::string_view> names) {
    std::size_t total = 0;
    for (std::string_view n : names) total += n.size();
    if (!names.empty()) total += names.size() - 1;
    write_uint32(static_cast<std::uint32_t>(total));
    bool first = true;
    for (std::string_view n : names) {
        if (!first) write_byte(static_cast<std::uint8_t>(','));
        first = false;
        write_bytes(std::span<const std::byte>{
            reinterpret_cast<const std::byte*>(n.data()), n.size()});
    }
}

YANTERM_SSH_INLINE void writer::reserve(std::size_t n) { buf_.reserve(n); }

YANTERM_SSH_INLINE std::vector<std::byte> writer::take() noexcept {
    return std::move(buf_);
}

}  // namespace yanterm::ssh::wire
