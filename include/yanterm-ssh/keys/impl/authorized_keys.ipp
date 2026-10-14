#pragma once

#include <yanterm-ssh/keys/authorized_keys.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/keys/impl/authorized_keys.ipp is an implementation file, not a public header."
#endif

#include <utility>

namespace yanterm::ssh::keys {

namespace detail {

YANTERM_SSH_INLINE bool find_authorized_key_type(std::string_view s, std::size_t& type_off,
                                                   std::string_view& options) noexcept {
    options = {};
    type_off = std::string_view::npos;

    auto first_rest = s;
    std::string_view first;
    if (!take_token(first_rest, first)) return false;
    if (is_known_authorized_key_type(first)) {
        type_off = static_cast<std::size_t>(first.data() - s.data());
        return true;
    }

    bool in_quotes = false;
    std::size_t i = 0;
    while (i < s.size()) {
        const char c = s[i];
        if (in_quotes) {
            if (c == '\\' && i + 1 < s.size() && s[i + 1] == '"') {
                i += 2;
                continue;
            }
            if (c == '"') in_quotes = false;
            ++i;
            continue;
        }
        if (c == '"') {
            in_quotes = true;
            ++i;
            continue;
        }
        if (!is_ascii_space(c)) {
            ++i;
            continue;
        }

        std::size_t j = i;
        while (j < s.size() && is_ascii_space(s[j])) ++j;
        if (j >= s.size()) break;

        std::size_t k = j;
        while (k < s.size() && !is_ascii_space(s[k])) ++k;
        const auto tok = s.substr(j, k - j);
        if (is_known_authorized_key_type(tok)) {
            type_off = j;
            options = rtrim_ws(s.substr(0, i));
            return true;
        }
        i = j;
    }
    return false;
}

YANTERM_SSH_INLINE std::string reconstruct_authorized_line(const authorized_key_line& line) {
    if (!line.raw.empty() || !line.key) return line.raw;
    std::string out;
    if (!line.options.empty()) {
        out += line.options;
        out += ' ';
    }
    out += line.key->to_line(line.comment);
    return out;
}

YANTERM_SSH_INLINE void parse_one_authorized_line(std::string_view line, std::vector<authorized_key_line>& out) {
    authorized_key_line entry;
    entry.raw = std::string{line};

    auto rest = ltrim_ws(line);
    if (rest.empty() || rest.front() == '#') {
        out.push_back(std::move(entry));
        return;
    }

    std::size_t type_off = std::string_view::npos;
    std::string_view options;
    if (!find_authorized_key_type(rest, type_off, options) ||
        type_off == std::string_view::npos || type_off >= rest.size()) {
        out.push_back(std::move(entry));
        return;
    }

    public_key pk;
    std::string comment;
    if (public_key::parse_line(rest.substr(type_off), pk, &comment)) {
        out.push_back(std::move(entry));
        return;
    }

    entry.options = std::string{options};
    entry.key = std::move(pk);
    entry.comment = std::move(comment);
    out.push_back(std::move(entry));
}

}  // namespace detail

YANTERM_SSH_INLINE std::error_code authorized_keys::parse(std::string_view text, authorized_keys& out) {
    authorized_keys tmp;
    std::size_t i = 0;
    while (i < text.size()) {
        const std::size_t start = i;
        while (i < text.size() && text[i] != '\n') ++i;
        auto line = text.substr(start, i - start);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        detail::parse_one_authorized_line(line, tmp.lines_);
        if (i < text.size()) ++i;
    }
    out = std::move(tmp);
    return {};
}

YANTERM_SSH_INLINE std::string authorized_keys::serialize() const {
    std::string out;
    for (const auto& line : lines_) {
        out += detail::reconstruct_authorized_line(line);
        out += '\n';
    }
    return out;
}

}  // namespace yanterm::ssh::keys
