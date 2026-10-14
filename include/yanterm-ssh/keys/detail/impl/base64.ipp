#pragma once

#include <yanterm-ssh/keys/detail/base64.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/keys/detail/impl/base64.ipp is an implementation file, not a public header."
#endif

#include <array>

namespace yanterm::ssh::keys::detail {

YANTERM_SSH_INLINE std::string base64_encode(std::span<const std::byte> in, bool pad) {
    static constexpr char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);

    for (std::size_t i = 0; i < in.size(); i += 3) {
        const unsigned b0 = std::to_integer<unsigned>(in[i]);
        const unsigned b1 = (i + 1 < in.size()) ? std::to_integer<unsigned>(in[i + 1]) : 0u;
        const unsigned b2 = (i + 2 < in.size()) ? std::to_integer<unsigned>(in[i + 2]) : 0u;
        const unsigned v = (b0 << 16) | (b1 << 8) | b2;

        out.push_back(kAlphabet[(v >> 18) & 0x3Fu]);
        out.push_back(kAlphabet[(v >> 12) & 0x3Fu]);
        if (i + 1 < in.size()) {
            out.push_back(kAlphabet[(v >> 6) & 0x3Fu]);
        }
        if (i + 2 < in.size()) {
            out.push_back(kAlphabet[v & 0x3Fu]);
        }
    }

    if (pad) {
        const std::size_t rem = in.size() % 3;
        if (rem == 1) {
            out.append("==");
        } else if (rem == 2) {
            out.push_back('=');
        }
    }

    return out;
}

YANTERM_SSH_INLINE bool base64_decode(std::string_view in, std::vector<std::byte>& out) {
    static constexpr int kInvalid = -1;
    static constexpr auto kDecode = [] {
        std::array<int, 256> table{};
        table.fill(kInvalid);
        for (int i = 0; i < 26; ++i) {
            table[static_cast<unsigned char>('A' + i)] = i;
            table[static_cast<unsigned char>('a' + i)] = 26 + i;
        }
        for (int i = 0; i < 10; ++i) {
            table[static_cast<unsigned char>('0' + i)] = 52 + i;
        }
        table[static_cast<unsigned char>('+')] = 62;
        table[static_cast<unsigned char>('/')] = 63;
        return table;
    }();

    std::string cleaned;
    cleaned.reserve(in.size());
    for (char c : in) {
        if (c == '\n' || c == '\r' || c == ' ') {
            continue;
        }
        cleaned.push_back(c);
    }

    if (cleaned.empty()) {
        out.clear();
        return true;
    }

    std::size_t pad = 0;
    while (pad < cleaned.size() && cleaned[cleaned.size() - 1 - pad] == '=') {
        ++pad;
    }
    if (pad > 2) {
        return false;
    }

    const std::size_t data_len = cleaned.size() - pad;
    if (data_len % 4 == 1) {
        return false;
    }

    out.clear();
    out.reserve((data_len * 3) / 4);

    for (std::size_t i = 0; i < cleaned.size();) {
        int vals[4] = {};
        int n = 0;
        for (; n < 4 && i < cleaned.size(); ++n, ++i) {
            const char c = cleaned[i];
            if (c == '=') {
                break;
            }
            const int v = kDecode[static_cast<unsigned char>(c)];
            if (v == kInvalid) {
                return false;
            }
            vals[n] = v;
        }

        if (n >= 2) {
            out.push_back(static_cast<std::byte>((vals[0] << 2) | (vals[1] >> 4)));
        }
        if (n >= 3) {
            out.push_back(static_cast<std::byte>(((vals[1] & 0x0F) << 4) | (vals[2] >> 2)));
        }
        if (n == 4) {
            out.push_back(static_cast<std::byte>(((vals[2] & 0x03) << 6) | vals[3]));
        }

        while (i < cleaned.size() && cleaned[i] == '=') {
            ++i;
        }
    }

    return true;
}

}  // namespace yanterm::ssh::keys::detail
