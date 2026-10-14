#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/wire/types.hpp>
#include <yanterm-ssh/crypto/provider.hpp>
#include <yanterm-ssh/crypto/secure_buffer.hpp>
#include <yanterm-ssh/keys/public_key.hpp>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace yanterm::ssh::keys {

struct private_key_info {
    bool encrypted = false;
    std::string cipher;  // owning: "none" / "aes256-ctr" / …
    std::string kdf;     // owning: "none" / "bcrypt"
    std::uint32_t bcrypt_rounds = 0;
};

namespace detail {

struct private_key_layout {
    crypto::sig_id algorithm{};
    std::uint32_t seed_off = 0, seed_len = 0;
    std::uint32_t pub_off = 0, pub_len = 0;
    std::uint32_t n_off = 0, n_len = 0;
    std::uint32_t e_off = 0, e_len = 0;
    std::uint32_t d_off = 0, d_len = 0;
    std::uint32_t p_off = 0, p_len = 0;
    std::uint32_t q_off = 0, q_len = 0;
    std::uint32_t iqmp_off = 0, iqmp_len = 0;
};

}  // namespace detail

class private_key {
public:
    static private_key_info inspect(std::span<const std::byte> file);
    static std::error_code parse(std::span<const std::byte> file,
                                 crypto::provider p,
                                 std::span<const std::byte> passphrase,
                                 private_key& out);
    std::error_code serialize(crypto::provider p,
                              std::span<const std::byte> passphrase,
                              std::string_view cipher_name,
                              std::vector<std::byte>& out) const;
    static std::error_code generate(crypto::provider p,
                                    crypto::sig_id id,
                                    std::uint32_t bits,
                                    std::string_view comment,
                                    private_key& out);

    const public_key& pub() const noexcept;
    crypto::private_key_material material() const noexcept;  // spans into secure storage
    std::string_view comment() const noexcept;

private:
    crypto::secure_bytes storage_;
    public_key pub_;
    std::string comment_;
    detail::private_key_layout layout_{};

    [[nodiscard]] std::span<const std::byte> field(std::uint32_t off, std::uint32_t len) const noexcept;
};

namespace detail {

inline constexpr std::string_view openssh_armor_begin = "-----BEGIN OPENSSH PRIVATE KEY-----";
inline constexpr std::string_view openssh_armor_end = "-----END OPENSSH PRIVATE KEY-----";
inline constexpr char openssh_key_v1_magic[] = "openssh-key-v1";  // includes trailing NUL
inline constexpr std::size_t openssh_key_v1_magic_size = sizeof(openssh_key_v1_magic);
inline constexpr std::size_t openssh_none_block_size = 8;
inline constexpr std::size_t openssh_armor_wrap = 70;

[[nodiscard]] inline bool starts_with_text(std::span<const std::byte> file,
                                           std::string_view prefix) noexcept {
    if (file.size() < prefix.size()) return false;
    return std::string_view{reinterpret_cast<const char*>(file.data()), prefix.size()} == prefix;
}

[[nodiscard]] inline bool is_openssh_armor(std::span<const std::byte> file) noexcept {
    return starts_with_text(file, openssh_armor_begin);
}

[[nodiscard]] inline bool is_traditional_pem(std::span<const std::byte> file) noexcept {
    if (is_openssh_armor(file)) return false;
    return starts_with_text(file, "-----BEGIN RSA PRIVATE KEY-----")
        || starts_with_text(file, "-----BEGIN EC PRIVATE KEY-----")
        || starts_with_text(file, "-----BEGIN PRIVATE KEY-----");
}

[[nodiscard]] inline bool has_openssh_magic(std::span<const std::byte> inner) noexcept {
    if (inner.size() < openssh_key_v1_magic_size) return false;
    return std::memcmp(inner.data(), openssh_key_v1_magic, openssh_key_v1_magic_size) == 0;
}

bool unwrap_openssh_armor(std::span<const std::byte> file, std::vector<std::byte>& inner);

std::error_code decode_openssh_file(std::span<const std::byte> file,
                                    std::vector<std::byte>& decoded,
                                    std::span<const std::byte>& inner);

void wrap_openssh_armor(std::span<const std::byte> inner, std::vector<std::byte>& out);

void append_field(std::vector<std::byte>& buf, std::span<const std::byte> s,
                  std::uint32_t& off, std::uint32_t& len);

[[nodiscard]] inline bool valid_openssh_padding(std::span<const std::byte> pad) noexcept {
    for (std::size_t i = 0; i < pad.size(); ++i) {
        if (std::to_integer<unsigned>(pad[i]) != static_cast<unsigned>((i + 1u) & 0xffu)) {
            return false;
        }
    }
    return true;
}

std::error_code parse_private_body(wire::reader& r, const public_key& pub,
                                   std::vector<std::byte>& fields,
                                   private_key_layout& layout);

std::error_code encode_private_body(const public_key& pub,
                                    const crypto::private_key_material& m,
                                    wire::writer& w);

inline bool read_header_fields(wire::reader& r, std::string_view& cipher, std::string_view& kdf,
                               std::span<const std::byte>& kdfoptions) noexcept {
    return r.read_string(cipher) && r.read_string(kdf) && r.read_string(kdfoptions);
}

inline std::uint32_t bcrypt_rounds_from_options(std::span<const std::byte> kdfoptions) noexcept {
    wire::reader kr{kdfoptions};
    std::span<const std::byte> salt;
    std::uint32_t rounds = 0;
    if (!kr.read_string(salt) || !kr.read_uint32(rounds) || !kr.empty()) return 0;
    return rounds;
}

inline bool parse_bcrypt_options(std::span<const std::byte> kdfoptions,
                                 std::span<const std::byte>& salt,
                                 std::uint32_t& rounds) noexcept {
    wire::reader kr{kdfoptions};
    return kr.read_string(salt) && kr.read_uint32(rounds) && kr.empty() && !salt.empty()
        && rounds != 0;
}

std::error_code consume_private_section(std::span<const std::byte> section,
                                        const public_key& pub, bool encrypted,
                                        std::vector<std::byte>& fields,
                                        private_key_layout& layout, std::string& comment);

inline constexpr std::size_t bcrypt_salt_len = 16;
inline constexpr std::uint32_t bcrypt_write_rounds = 16;
inline constexpr std::string_view write_cipher_name = "aes256-ctr";

}  // namespace detail

inline std::span<const std::byte> private_key::field(std::uint32_t off,
                                                     std::uint32_t len) const noexcept {
    if (len == 0) return {};
    if (static_cast<std::size_t>(off) + len > storage_.size()) return {};
    return {storage_.data() + off, len};
}

inline const public_key& private_key::pub() const noexcept { return pub_; }

inline std::string_view private_key::comment() const noexcept { return comment_; }

inline crypto::private_key_material private_key::material() const noexcept {
    crypto::private_key_material m;
    m.algorithm = layout_.algorithm;
    m.seed = field(layout_.seed_off, layout_.seed_len);
    m.public_key = field(layout_.pub_off, layout_.pub_len);
    m.n = field(layout_.n_off, layout_.n_len);
    m.e = field(layout_.e_off, layout_.e_len);
    m.d = field(layout_.d_off, layout_.d_len);
    m.p = field(layout_.p_off, layout_.p_len);
    m.q = field(layout_.q_off, layout_.q_len);
    m.iqmp = field(layout_.iqmp_off, layout_.iqmp_len);
    return m;
}

}  // namespace yanterm::ssh::keys

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/keys/impl/private_key.ipp>
#endif
