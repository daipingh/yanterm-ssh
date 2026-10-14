#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/keys/detail/wire_key.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace yanterm::ssh::keys {

class public_key {
public:
    static std::error_code parse_blob(std::span<const std::byte> blob, public_key& out);
    static std::error_code from_material(const crypto::public_key_material& m, public_key& out);
    static std::error_code parse_authorized_key_body(std::string_view type_and_b64,
                                                     public_key& out);
    // OpenSSH one-line: "ssh-ed25519 AAAAC3… comment"
    static std::error_code parse_line(std::string_view line, public_key& out,
                                      std::string* comment = nullptr);
    [[nodiscard]] std::string to_line(std::string_view comment = {}) const;
    [[nodiscard]] std::span<const std::byte> blob() const noexcept;
    [[nodiscard]] std::string_view algorithm_name() const noexcept;  // wire type, RSA → "ssh-rsa"
    [[nodiscard]] crypto::sig_id algorithm() const noexcept;
    [[nodiscard]] crypto::public_key_material material() const noexcept;  // spans into blob_

private:
    std::vector<std::byte> blob_;
    crypto::sig_id algorithm_{};
    std::uint32_t name_off_{};
    std::uint32_t name_len_{};
    std::uint32_t a_off_{};
    std::uint32_t a_len_{};
    std::uint32_t b_off_{};
    std::uint32_t b_len_{};

    void apply_parsed(const detail::parsed_pubkey& parsed);
};

namespace detail {

[[nodiscard]] inline bool is_ascii_space(char c) noexcept {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

[[nodiscard]] inline std::string_view ltrim_ws(std::string_view s) noexcept {
    while (!s.empty() && is_ascii_space(s.front())) s.remove_prefix(1);
    return s;
}

[[nodiscard]] inline std::string_view rtrim_ws(std::string_view s) noexcept {
    while (!s.empty() && is_ascii_space(s.back())) s.remove_suffix(1);
    return s;
}

[[nodiscard]] inline std::string_view trim_ws(std::string_view s) noexcept {
    return rtrim_ws(ltrim_ws(s));
}

inline bool take_token(std::string_view& rest, std::string_view& tok) noexcept {
    rest = ltrim_ws(rest);
    if (rest.empty()) return false;
    std::size_t n = 0;
    while (n < rest.size() && !is_ascii_space(rest[n])) ++n;
    tok = rest.substr(0, n);
    rest.remove_prefix(n);
    return true;
}

[[nodiscard]] inline std::uint32_t span_off(std::span<const std::byte> blob,
                                            std::span<const std::byte> part) noexcept {
    if (part.empty() || part.data() == nullptr) return 0;
    return static_cast<std::uint32_t>(part.data() - blob.data());
}

}  // namespace detail

inline std::span<const std::byte> public_key::blob() const noexcept { return blob_; }

inline std::string_view public_key::algorithm_name() const noexcept {
    if (name_len_ == 0 || name_off_ + name_len_ > blob_.size()) return {};
    return std::string_view{reinterpret_cast<const char*>(blob_.data() + name_off_), name_len_};
}

inline crypto::sig_id public_key::algorithm() const noexcept { return algorithm_; }

inline crypto::public_key_material public_key::material() const noexcept {
    crypto::public_key_material m;
    m.algorithm = algorithm_;
    if (a_len_ != 0 && a_off_ + a_len_ <= blob_.size()) {
        m.a = std::span<const std::byte>{blob_.data() + a_off_, a_len_};
    }
    if (b_len_ != 0 && b_off_ + b_len_ <= blob_.size()) {
        m.b = std::span<const std::byte>{blob_.data() + b_off_, b_len_};
    }
    return m;
}

}  // namespace yanterm::ssh::keys

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/keys/impl/public_key.ipp>
#endif
