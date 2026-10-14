#pragma once

#include <yanterm-ssh/keys/known_hosts.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/keys/impl/known_hosts.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/crypto/algorithms.hpp>
#include <yanterm-ssh/keys/detail/base64.hpp>

#include <array>
#include <utility>

namespace yanterm::ssh::keys {

namespace detail {

YANTERM_SSH_INLINE std::string host_with_port_form(std::string_view hostname,
                                                     std::uint16_t port) {
    if (port == 22) return std::string{hostname};
    return "[" + std::string{hostname} + "]:" + std::to_string(port);
}

YANTERM_SSH_INLINE bool match_glob(std::string_view s, std::string_view pat) noexcept {
    while (!pat.empty()) {
        if (pat.front() == '*') {
            pat.remove_prefix(1);
            if (pat.empty()) return true;
            for (std::size_t i = 0; i <= s.size(); ++i) {
                if (match_glob(s.substr(i), pat)) return true;
            }
            return false;
        }
        if (s.empty()) return false;
        if (pat.front() != '?' && pat.front() != s.front()) return false;
        pat.remove_prefix(1);
        s.remove_prefix(1);
    }
    return s.empty();
}

YANTERM_SSH_INLINE bool hashed_host_eq(crypto::provider p, std::string_view host_form,
                                         std::string_view item) {
    constexpr std::string_view kPrefix = "|1|";
    if (item.size() < kPrefix.size() || !item.starts_with(kPrefix)) return false;
    const auto rest = item.substr(kPrefix.size());
    const auto bar = rest.find('|');
    if (bar == std::string_view::npos || bar == 0 || bar + 1 >= rest.size()) return false;

    std::vector<std::byte> salt;
    std::vector<std::byte> mac;
    if (!base64_decode(rest.substr(0, bar), salt)) return false;
    if (!base64_decode(rest.substr(bar + 1), mac)) return false;
    if (salt.empty() || mac.empty()) return false;

    auto hmac = p.new_hmac(crypto::hash_id::sha1, salt);
    if (!hmac) return false;
    hmac.update({reinterpret_cast<const std::byte*>(host_form.data()), host_form.size()});
    std::array<std::byte, 20> out{};
    if (!hmac.final_into(out)) return false;
    return p.constant_time_eq(mac, std::span<const std::byte>{out}.first(out.size()));
}

YANTERM_SSH_INLINE bool host_pattern_matches(crypto::provider p, std::string_view pattern,
                                               std::string_view host_form) {
    bool positive = false;
    std::size_t i = 0;
    while (i < pattern.size()) {
        while (i < pattern.size() && pattern[i] == ',') ++i;
        if (i >= pattern.size()) break;
        const auto comma = pattern.find(',', i);
        const auto item = pattern.substr(i, comma == std::string_view::npos ? std::string_view::npos
                                                                           : comma - i);
        i = (comma == std::string_view::npos) ? pattern.size() : comma + 1;
        if (item.empty()) continue;

        bool negated = false;
        auto tok = item;
        if (tok.front() == '!') {
            negated = true;
            tok.remove_prefix(1);
            if (tok.empty()) continue;
        }

        const bool hit = tok.starts_with("|1|") ? hashed_host_eq(p, host_form, tok)
                                                : match_glob(host_form, tok);
        if (hit && negated) return false;
        if (hit) positive = true;
    }
    return positive;
}

YANTERM_SSH_INLINE bool line_key_hit(crypto::provider p, const known_host_line& line,
                                       std::string_view hostname, std::uint16_t port,
                                       const public_key& key) {
    if (!line.key) return false;
    const auto host_form = host_with_port_form(hostname, port);
    if (!host_pattern_matches(p, line.pattern, host_form)) return false;
    return blobs_equal(*line.key, key);
}

YANTERM_SSH_INLINE std::string reconstruct_line(const known_host_line& line) {
    if (!line.raw.empty()) return line.raw;
    if (!line.key) return {};
    std::string out;
    if (line.marker == host_marker::revoked) {
        out += "@revoked ";
    } else if (line.marker == host_marker::cert_authority) {
        out += "@cert-authority ";
    }
    out += line.pattern;
    out += ' ';
    out += line.key->to_line(line.comment);
    return out;
}

YANTERM_SSH_INLINE void parse_one_line(std::string_view line, std::vector<known_host_line>& out) {
    known_host_line entry;
    entry.raw = std::string{line};

    auto rest = ltrim_ws(line);
    if (rest.empty() || rest.front() == '#') {
        out.push_back(std::move(entry));
        return;
    }

    std::string_view tok;
    if (!take_token(rest, tok)) {
        out.push_back(std::move(entry));
        return;
    }

    auto marker = host_marker::none;
    if (tok == "@revoked") {
        marker = host_marker::revoked;
        if (!take_token(rest, tok)) {
            out.push_back(std::move(entry));
            return;
        }
    } else if (tok == "@cert-authority") {
        marker = host_marker::cert_authority;
        if (!take_token(rest, tok)) {
            out.push_back(std::move(entry));
            return;
        }
    }

    const auto pattern = tok;
    public_key pk;
    std::string comment;
    if (public_key::parse_line(rest, pk, &comment)) {
        out.push_back(std::move(entry));
        return;
    }

    entry.marker = marker;
    entry.pattern = std::string{pattern};
    entry.key = std::move(pk);
    entry.comment = std::move(comment);
    out.push_back(std::move(entry));
}

}  // namespace detail

YANTERM_SSH_INLINE std::error_code known_hosts::parse(std::string_view text, known_hosts& out) {
    known_hosts tmp;
    std::size_t i = 0;
    while (i < text.size()) {
        const std::size_t start = i;
        while (i < text.size() && text[i] != '\n') ++i;
        auto line = text.substr(start, i - start);
        if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
        detail::parse_one_line(line, tmp.lines_);
        if (i < text.size()) ++i;
    }
    out = std::move(tmp);
    return {};
}

YANTERM_SSH_INLINE std::string known_hosts::serialize() const {
    std::string out;
    for (const auto& line : lines_) {
        out += detail::reconstruct_line(line);
        out += '\n';
    }
    return out;
}

YANTERM_SSH_INLINE host_key_match known_hosts::match(crypto::provider p, std::string_view hostname,
                                         std::uint16_t port, const public_key& key) const {
    auto result = host_key_match::none;
    for (const auto& line : lines_) {
        if (!detail::line_key_hit(p, line, hostname, port, key)) continue;
        if (line.marker == host_marker::revoked) return host_key_match::revoked;
        if (line.marker == host_marker::cert_authority) continue;
        result = host_key_match::found;
    }
    return result;
}

YANTERM_SSH_INLINE void known_hosts::append(known_host_line line) { lines_.push_back(std::move(line)); }

YANTERM_SSH_INLINE std::size_t known_hosts::erase_matching(crypto::provider p, std::string_view hostname,
                                               std::uint16_t port, const public_key& key) {
    const auto before = lines_.size();
    std::erase_if(lines_, [&](const known_host_line& line) {
        return detail::line_key_hit(p, line, hostname, port, key);
    });
    return before - lines_.size();
}

}  // namespace yanterm::ssh::keys
