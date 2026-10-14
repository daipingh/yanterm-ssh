#pragma once

#include <yanterm-ssh/keys/private_key.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/keys/impl/private_key.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/crypto/detail/bcrypt_pbkdf.hpp>
#include <yanterm-ssh/detail/error.hpp>
#include <yanterm-ssh/keys/detail/base64.hpp>
#include <yanterm-ssh/keys/detail/file_cipher.hpp>
#include <yanterm-ssh/keys/detail/wire_key.hpp>

#include <algorithm>
#include <array>
#include <utility>

namespace yanterm::ssh::keys {

namespace detail {

YANTERM_SSH_INLINE bool unwrap_openssh_armor(std::span<const std::byte> file, std::vector<std::byte>& inner) {
    auto text = std::string_view{reinterpret_cast<const char*>(file.data()), file.size()};
    if (!text.starts_with(openssh_armor_begin)) return false;
    text.remove_prefix(openssh_armor_begin.size());
    const auto end_pos = text.find(openssh_armor_end);
    if (end_pos == std::string_view::npos) return false;
    return base64_decode(text.substr(0, end_pos), inner);
}

YANTERM_SSH_INLINE std::error_code decode_openssh_file(std::span<const std::byte> file,
                                           std::vector<std::byte>& decoded,
                                           std::span<const std::byte>& inner) {
    if (is_traditional_pem(file)) return code::unsupported_key_format;
    if (is_openssh_armor(file)) {
        if (!unwrap_openssh_armor(file, decoded)) {
            return code::unsupported_key_format;
        }
        inner = decoded;
        return {};
    }
    inner = file;
    return {};
}

YANTERM_SSH_INLINE void wrap_openssh_armor(std::span<const std::byte> inner, std::vector<std::byte>& out) {
    const std::string b64 = base64_encode(inner, true);
    std::string text;
    text.reserve(openssh_armor_begin.size() + openssh_armor_end.size() + b64.size()
                 + 4 + b64.size() / openssh_armor_wrap);
    text += openssh_armor_begin;
    text += '\n';
    for (std::size_t i = 0; i < b64.size(); i += openssh_armor_wrap) {
        text.append(b64, i, openssh_armor_wrap);
        text += '\n';
    }
    text += openssh_armor_end;
    text += '\n';
    out.assign(reinterpret_cast<const std::byte*>(text.data()),
               reinterpret_cast<const std::byte*>(text.data() + text.size()));
}

YANTERM_SSH_INLINE void append_field(std::vector<std::byte>& buf, std::span<const std::byte> s,
                         std::uint32_t& off, std::uint32_t& len) {
    off = static_cast<std::uint32_t>(buf.size());
    len = static_cast<std::uint32_t>(s.size());
    buf.insert(buf.end(), s.begin(), s.end());
}

YANTERM_SSH_INLINE std::error_code parse_private_body(wire::reader& r, const public_key& pub,
                                          std::vector<std::byte>& fields,
                                          private_key_layout& layout) {
    std::string_view type;
    if (!r.read_string(type)) return code::invalid_format;
    if (is_cert_or_sk(type)) return code::unsupported_key_format;
    if (type != pub.algorithm_name()) return code::invalid_format;

    const pubkey_type* pt = find_pubkey_type(type);
    if (pt == nullptr) return code::unsupported_algorithm;

    layout.algorithm = pt->id;
    const auto pm = pub.material();

    if (pt->kind == pubkey_kind::ed25519) {
        std::span<const std::byte> pub32;
        std::span<const std::byte> priv64;
        if (!r.read_string(pub32) || !r.read_string(priv64)) {
            return code::invalid_format;
        }
        if (pub32.size() != 32 || priv64.size() != 64) {
            return code::invalid_format;
        }
        if (!std::equal(pub32.begin(), pub32.end(), priv64.begin() + 32)) {
            return code::invalid_format;
        }
        if (pm.a.size() != 32 || !std::equal(pub32.begin(), pub32.end(), pm.a.begin())) {
            return code::invalid_format;
        }
        append_field(fields, priv64.subspan(0, 32), layout.seed_off, layout.seed_len);
        append_field(fields, priv64.subspan(32, 32), layout.pub_off, layout.pub_len);
        return {};
    }

    if (pt->kind == pubkey_kind::ecdsa) {
        std::string_view curve;
        std::span<const std::byte> q;
        std::span<const std::byte> d;
        if (!r.read_string(curve) || !r.read_string(q) || !r.read_mpint(d)) {
            return code::invalid_format;
        }
        if (curve != pt->curve) return code::invalid_format;
        if (!std::equal(q.begin(), q.end(), pm.a.begin(), pm.a.end())) {
            return code::invalid_format;
        }
        append_field(fields, d, layout.seed_off, layout.seed_len);
        append_field(fields, q, layout.pub_off, layout.pub_len);
        return {};
    }

    if (pt->kind == pubkey_kind::rsa) {
        std::span<const std::byte> n;
        std::span<const std::byte> e;
        std::span<const std::byte> d;
        std::span<const std::byte> iqmp;
        std::span<const std::byte> p;
        std::span<const std::byte> q;
        if (!r.read_mpint(n) || !r.read_mpint(e) || !r.read_mpint(d) || !r.read_mpint(iqmp)
            || !r.read_mpint(p) || !r.read_mpint(q)) {
            return code::invalid_format;
        }
        if (!std::equal(n.begin(), n.end(), pm.a.begin(), pm.a.end())
            || !std::equal(e.begin(), e.end(), pm.b.begin(), pm.b.end())) {
            return code::invalid_format;
        }
        append_field(fields, n, layout.n_off, layout.n_len);
        append_field(fields, e, layout.e_off, layout.e_len);
        append_field(fields, d, layout.d_off, layout.d_len);
        append_field(fields, p, layout.p_off, layout.p_len);
        append_field(fields, q, layout.q_off, layout.q_len);
        append_field(fields, iqmp, layout.iqmp_off, layout.iqmp_len);
        return {};
    }

    return code::unsupported_algorithm;
}

YANTERM_SSH_INLINE std::error_code encode_private_body(const public_key& pub,
                                           const crypto::private_key_material& m,
                                           wire::writer& w) {
    const pubkey_type* pt = find_pubkey_type(pub.algorithm());
    if (pt == nullptr) return code::unsupported_algorithm;
    w.write_string(pt->name);

    if (pt->kind == pubkey_kind::ed25519) {
        if (m.seed.size() != 32 || m.public_key.size() != 32) {
            return code::invalid_format;
        }
        w.write_string(m.public_key);
        std::array<std::byte, 64> priv{};
        std::copy(m.seed.begin(), m.seed.end(), priv.begin());
        std::copy(m.public_key.begin(), m.public_key.end(), priv.begin() + 32);
        w.write_string(std::span<const std::byte>{priv});
        return {};
    }

    if (pt->kind == pubkey_kind::ecdsa) {
        if (pt->curve.empty() || m.public_key.empty() || m.seed.empty()) {
            return code::invalid_format;
        }
        w.write_string(pt->curve);
        w.write_string(m.public_key);
        w.write_mpint(m.seed);
        return {};
    }

    if (pt->kind == pubkey_kind::rsa) {
        if (m.n.empty() || m.e.empty() || m.d.empty() || m.p.empty() || m.q.empty()
            || m.iqmp.empty()) {
            return code::invalid_format;
        }
        w.write_mpint(m.n);
        w.write_mpint(m.e);
        w.write_mpint(m.d);
        w.write_mpint(m.iqmp);
        w.write_mpint(m.p);
        w.write_mpint(m.q);
        return {};
    }

    return code::unsupported_algorithm;
}

YANTERM_SSH_INLINE std::error_code consume_private_section(std::span<const std::byte> section,
                                               const public_key& pub, bool encrypted,
                                               std::vector<std::byte>& fields,
                                               private_key_layout& layout, std::string& comment) {
    wire::reader sr{section};
    std::uint32_t check1 = 0;
    std::uint32_t check2 = 0;
    if (!sr.read_uint32(check1) || !sr.read_uint32(check2)) {
        return code::invalid_format;
    }
    if (check1 != check2) {
        return encrypted ? code::incorrect_passphrase : code::invalid_format;
    }
    if (auto ec = parse_private_body(sr, pub, fields, layout)) return ec;
    std::string_view cmt;
    if (!sr.read_string(cmt)) return code::invalid_format;
    if (!valid_openssh_padding(sr.remaining())) {
        return code::invalid_format;
    }
    comment = std::string{cmt};
    return {};
}

}  // namespace detail

YANTERM_SSH_INLINE private_key_info private_key::inspect(std::span<const std::byte> file) {
    private_key_info info;
    std::vector<std::byte> decoded;
    std::span<const std::byte> inner;
    if (detail::decode_openssh_file(file, decoded, inner)) return info;
    if (!detail::has_openssh_magic(inner)) return info;

    wire::reader r{inner.subspan(detail::openssh_key_v1_magic_size)};
    std::string_view cipher;
    std::string_view kdf;
    std::span<const std::byte> kdfoptions;
    if (!detail::read_header_fields(r, cipher, kdf, kdfoptions)) return info;

    info.cipher = std::string{cipher};
    info.kdf = std::string{kdf};
    info.encrypted = info.cipher != "none";
    if (info.kdf == "bcrypt") {
        info.bcrypt_rounds = detail::bcrypt_rounds_from_options(kdfoptions);
    }
    return info;
}

YANTERM_SSH_INLINE std::error_code private_key::parse(std::span<const std::byte> file,
                                          crypto::provider p,
                                          std::span<const std::byte> passphrase,
                                          private_key& out) {
    std::vector<std::byte> decoded;
    std::span<const std::byte> inner;
    if (auto ec = detail::decode_openssh_file(file, decoded, inner)) return ec;
    if (!detail::has_openssh_magic(inner)) return code::unsupported_key_format;

    wire::reader r{inner.subspan(detail::openssh_key_v1_magic_size)};
    std::string_view cipher;
    std::string_view kdf;
    std::span<const std::byte> kdfoptions;
    if (!detail::read_header_fields(r, cipher, kdf, kdfoptions)) {
        return code::invalid_format;
    }

    if (cipher != "none" && passphrase.empty()) {
        return code::passphrase_required;
    }

    const detail::file_cipher* fc = detail::find_file_cipher(cipher);
    if (fc == nullptr) return code::unsupported_algorithm;

    std::span<const std::byte> kdf_salt;
    std::uint32_t kdf_rounds = 0;
    if (fc->k == detail::file_cipher::kind::none) {
        if (kdf != "none" || !kdfoptions.empty()) return code::invalid_format;
    } else {
        if (kdf == "none") return code::invalid_format;
        if (kdf != "bcrypt") return code::unsupported_algorithm;
        if (!detail::parse_bcrypt_options(kdfoptions, kdf_salt, kdf_rounds)) {
            return code::invalid_format;
        }
    }

    std::uint32_t nkeys = 0;
    if (!r.read_uint32(nkeys)) return code::invalid_format;
    if (nkeys != 1) return code::invalid_format;

    std::span<const std::byte> pubblob;
    if (!r.read_string(pubblob)) return code::invalid_format;
    public_key pub;
    if (auto ec = public_key::parse_blob(pubblob, pub)) return ec;

    std::span<const std::byte> section;
    if (!r.read_string(section)) return code::invalid_format;
    if (!r.empty()) return code::invalid_format;

    std::vector<std::byte> decrypted;
    std::span<const std::byte> plain = section;
    const bool encrypted = fc->k != detail::file_cipher::kind::none;
    if (!encrypted) {
        if (fc->block == 0 || section.size() % fc->block != 0) {
            return code::invalid_format;
        }
    } else {
        if (!p) return code::crypto_backend_failure;
        if (section.size() < fc->tag_len) return code::invalid_format;
        const std::size_t body = section.size() - fc->tag_len;
        if (fc->block == 0 || body % fc->block != 0) {
            return code::invalid_format;
        }

        std::array<std::byte, 64> key_iv{};
        auto derived = std::span{key_iv}.first(fc->key_len + fc->iv_len);
        if (!crypto::detail::bcrypt_pbkdf(p, passphrase, kdf_salt, kdf_rounds, derived)) {
            crypto::secure_zero(key_iv);
            return code::hash_failure;
        }
        const auto open_ec = detail::open(p, *fc, derived, section, decrypted);
        crypto::secure_zero(key_iv);
        if (open_ec) {
            if (open_ec == code::decrypt_failure) {
                return code::incorrect_passphrase;
            }
            return open_ec;
        }
        plain = decrypted;
    }

    std::vector<std::byte> fields;
    detail::private_key_layout lay{};
    std::string comment;
    if (auto ec = detail::consume_private_section(plain, pub, encrypted, fields, lay, comment)) {
        return ec;
    }

    private_key tmp;
    tmp.storage_.assign(fields);
    tmp.pub_ = std::move(pub);
    tmp.comment_ = std::move(comment);
    tmp.layout_ = lay;
    out = std::move(tmp);
    return {};
}

YANTERM_SSH_INLINE std::error_code private_key::serialize(crypto::provider p,
                                              std::span<const std::byte> passphrase,
                                              std::string_view cipher_name,
                                              std::vector<std::byte>& out) const {
    const bool encrypting = cipher_name != "none";
    if (!encrypting) {
        if (!passphrase.empty()) return code::invalid_format;
    } else if (cipher_name != detail::write_cipher_name) {
        return code::unsupported_algorithm;
    } else if (passphrase.empty()) {
        return code::invalid_format;
    }

    const detail::file_cipher* fc =
        detail::find_file_cipher(encrypting ? cipher_name : std::string_view{"none"});
    if (fc == nullptr) return code::unsupported_algorithm;
    if (!p) return code::crypto_backend_failure;

    std::array<std::byte, 4> rnd{};
    if (auto ec = p.random_bytes(rnd)) return ec;
    const std::uint32_t check =
        (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(rnd[0])) << 24)
        | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(rnd[1])) << 16)
        | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(rnd[2])) << 8)
        | static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(rnd[3]));

    wire::writer section;
    section.write_uint32(check);
    section.write_uint32(check);
    if (auto ec = detail::encode_private_body(pub_, material(), section)) return ec;
    section.write_string(comment_);
    std::uint8_t pad = 0;
    while (section.size() % fc->block != 0) {
        section.write_byte(++pad);
    }

    std::array<std::byte, detail::bcrypt_salt_len> salt{};
    std::vector<std::byte> sealed;
    std::span<const std::byte> private_blob = section.data();
    if (encrypting) {
        if (auto ec = p.random_bytes(salt)) return ec;
        std::array<std::byte, 64> key_iv{};
        auto derived = std::span{key_iv}.first(fc->key_len + fc->iv_len);
        if (!crypto::detail::bcrypt_pbkdf(p, passphrase, salt, detail::bcrypt_write_rounds,
                                         derived)) {
            crypto::secure_zero(key_iv);
            return code::hash_failure;
        }
        const auto seal_ec = detail::seal(p, *fc, derived, section.data(), sealed);
        crypto::secure_zero(key_iv);
        if (seal_ec) return seal_ec;
        private_blob = sealed;
    }

    wire::writer outer;
    outer.write_bytes({reinterpret_cast<const std::byte*>(detail::openssh_key_v1_magic),
                       detail::openssh_key_v1_magic_size});
    if (encrypting) {
        outer.write_string(detail::write_cipher_name);
        outer.write_string("bcrypt");
        wire::writer kdfopt;
        kdfopt.write_string(std::span<const std::byte>{salt});
        kdfopt.write_uint32(detail::bcrypt_write_rounds);
        outer.write_string(kdfopt.data());
    } else {
        outer.write_string("none");
        outer.write_string("none");
        outer.write_string("");
    }
    outer.write_uint32(1);
    outer.write_string(pub_.blob());
    outer.write_string(private_blob);

    detail::wrap_openssh_armor(outer.data(), out);
    return {};
}

YANTERM_SSH_INLINE std::error_code private_key::generate(crypto::provider p,
                                            crypto::sig_id id,
                                            std::uint32_t bits,
                                            std::string_view comment,
                                            private_key& out) {
    if (!p) return code::crypto_backend_failure;
    if (detail::find_pubkey_type(id) == nullptr || !p.supports(id)) {
        return code::unsupported_algorithm;
    }

    std::array<std::byte, crypto::max_generated_key_storage> storage{};
    crypto::private_key_material priv{};
    if (!p.generate_keypair(id, bits, priv, storage)) {
        crypto::secure_zero(storage);
        return code::keygen_failure;
    }

    private_key tmp;
    tmp.layout_.algorithm = id;
    std::vector<std::byte> fields;
    if (crypto::is_rsa_sig(id)) {
        detail::append_field(fields, priv.n, tmp.layout_.n_off, tmp.layout_.n_len);
        detail::append_field(fields, priv.e, tmp.layout_.e_off, tmp.layout_.e_len);
        detail::append_field(fields, priv.d, tmp.layout_.d_off, tmp.layout_.d_len);
        detail::append_field(fields, priv.p, tmp.layout_.p_off, tmp.layout_.p_len);
        detail::append_field(fields, priv.q, tmp.layout_.q_off, tmp.layout_.q_len);
        detail::append_field(fields, priv.iqmp, tmp.layout_.iqmp_off, tmp.layout_.iqmp_len);
    } else {
        detail::append_field(fields, priv.seed, tmp.layout_.seed_off, tmp.layout_.seed_len);
        detail::append_field(fields, priv.public_key, tmp.layout_.pub_off, tmp.layout_.pub_len);
    }
    tmp.storage_.assign(fields);
    crypto::secure_zero(std::span<std::byte>{fields});
    crypto::secure_zero(storage);

    crypto::public_key_material pub_m;
    pub_m.algorithm = id;
    if (crypto::is_rsa_sig(id)) {
        pub_m.a = tmp.field(tmp.layout_.n_off, tmp.layout_.n_len);
        pub_m.b = tmp.field(tmp.layout_.e_off, tmp.layout_.e_len);
    } else {
        pub_m.a = tmp.field(tmp.layout_.pub_off, tmp.layout_.pub_len);
    }
    if (auto ec = public_key::from_material(pub_m, tmp.pub_)) return ec;
    tmp.comment_ = std::string{comment};
    out = std::move(tmp);
    return {};
}

}  // namespace yanterm::ssh::keys
