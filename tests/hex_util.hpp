#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yanterm::ssh::testing {

inline std::vector<std::byte> unhex(std::string_view s) {
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return c - 'A' + 10;
    };
    std::vector<std::byte> out;
    out.reserve(s.size() / 2);
    for (std::size_t i = 0; i + 1 < s.size(); i += 2) {
        out.push_back(static_cast<std::byte>(nibble(s[i]) * 16 + nibble(s[i + 1])));
    }
    return out;
}

inline std::string hex(std::span<const std::byte> in) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(in.size() * 2);
    for (std::byte b : in) {
        out.push_back(kDigits[std::to_integer<unsigned>(b) >> 4]);
        out.push_back(kDigits[std::to_integer<unsigned>(b) & 0x0Fu]);
    }
    return out;
}

inline std::span<const std::byte> bytes_of(std::string_view s) {
    return {reinterpret_cast<const std::byte*>(s.data()), s.size()};
}

}  // namespace yanterm::ssh::testing
