#pragma once

#include <yanterm-ssh/keys/public_key.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/keys/impl/public_key.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/detail/error.hpp>
#include <yanterm-ssh/keys/detail/base64.hpp>

#include <utility>

namespace yanterm::ssh::keys {

YANTERM_SSH_INLINE void public_key::apply_parsed(const detail::parsed_pubkey& parsed) {
    algorithm_ = parsed.algorithm;
    const auto owned = std::span<const std::byte>{blob_};
    const auto name_bytes = std::span<const std::byte>{
        reinterpret_cast<const std::byte*>(parsed.name.data()), parsed.name.size()};
    name_off_ = detail::span_off(owned, name_bytes);
    name_len_ = static_cast<std::uint32_t>(parsed.name.size());
    a_off_ = detail::span_off(owned, parsed.a);
    a_len_ = static_cast<std::uint32_t>(parsed.a.size());
    b_off_ = detail::span_off(owned, parsed.b);
    b_len_ = static_cast<std::uint32_t>(parsed.b.size());
}

YANTERM_SSH_INLINE std::error_code public_key::parse_blob(std::span<const std::byte> blob, public_key& out) {
    public_key tmp;
    tmp.blob_.assign(blob.begin(), blob.end());
    detail::parsed_pubkey parsed{};
    if (auto ec = detail::parse_pubkey_blob(tmp.blob_, parsed)) return ec;
    tmp.apply_parsed(parsed);
    out = std::move(tmp);
    return {};
}

YANTERM_SSH_INLINE std::error_code public_key::from_material(const crypto::public_key_material& m,
                                                 public_key& out) {
    wire::writer w;
    if (auto ec = detail::encode_pubkey_material(m, w)) return ec;
    return parse_blob(w.data(), out);
}

YANTERM_SSH_INLINE std::error_code public_key::parse_authorized_key_body(std::string_view type_and_b64,
                                                             public_key& out) {
    std::string_view rest = type_and_b64;
    std::string_view type;
    std::string_view b64;
    if (!detail::take_token(rest, type) || !detail::take_token(rest, b64)) {
        return code::invalid_format;
    }
    std::vector<std::byte> raw;
    if (!detail::base64_decode(b64, raw)) return code::invalid_format;
    if (auto ec = parse_blob(raw, out)) return ec;
    if (out.algorithm_name() != type) return code::invalid_format;
    return {};
}

YANTERM_SSH_INLINE std::error_code public_key::parse_line(std::string_view line, public_key& out,
                                              std::string* comment) {
    std::string_view rest = line;
    std::string_view type;
    std::string_view b64;
    if (!detail::take_token(rest, type) || !detail::take_token(rest, b64)) {
        return code::invalid_format;
    }
    if (comment) *comment = std::string{detail::trim_ws(rest)};
    return parse_authorized_key_body(line, out);
}

YANTERM_SSH_INLINE std::string public_key::to_line(std::string_view comment) const {
    std::string line;
    line += algorithm_name();
    line += ' ';
    line += detail::base64_encode(blob(), true);
    const auto c = detail::trim_ws(comment);
    if (!c.empty()) {
        line += ' ';
        line += c;
    }
    return line;
}

}  // namespace yanterm::ssh::keys
