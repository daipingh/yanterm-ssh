#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <cstddef>
#include <cstdint>
#include <span>

namespace yanterm::ssh::crypto {

enum class hash_id : std::uint8_t { sha1, sha256, sha384, sha512, sm3 };

// Non-AEAD symmetric algorithms share the cipher_* vtable family (CTR, ChaCha20,
// CBC). aes*-gcm use aead_* instead. chacha20 is a raw cipher because
// chacha20-poly1305@openssh.com is a two-key construction assembled in transport
// (design spec 6.2).
enum class cipher_id : std::uint8_t {
    aes128_ctr, aes192_ctr, aes256_ctr,
    aes128_gcm, aes256_gcm,
    chacha20,
    aes128_cbc, aes192_cbc, aes256_cbc,
    sm4_ctr, sm4_cbc,
};

enum class mac_id : std::uint8_t { hmac_sha1, hmac_sha256, hmac_sha512, poly1305, hmac_sm3 };

enum class kex_id : std::uint8_t {
    curve25519,
    ecdh_nistp256, ecdh_nistp384, ecdh_nistp521,
    dh_group14, dh_group16, dh_group18,
    ecdh_sm2,       // wire: ecgm-sm2-sm3
    sm2_kap,        // wire: sm2-sm3 (initiator / client)
    sm2_kap_server, // sm2-sm3 responder; not advertised
};

enum class sig_id : std::uint8_t {
    ed25519,
    ecdsa_nistp256, ecdsa_nistp384, ecdsa_nistp521,
    rsa_pkcs1_sha1, rsa_pkcs1_sha256, rsa_pkcs1_sha512,
    sm2_za,    // openEuler SM2+ZA+DER; wire "sm2" key type
    sm2_ecdsa, // Kylin ECDSA-on-SM2+mpint
};

[[nodiscard]] constexpr bool is_rsa_sig(sig_id id) noexcept {
    switch (id) {
    case sig_id::rsa_pkcs1_sha1:
    case sig_id::rsa_pkcs1_sha256:
    case sig_id::rsa_pkcs1_sha512: return true;
    default: return false;
    }
}

[[nodiscard]] constexpr bool is_ecdsa_sig(sig_id id) noexcept {
    switch (id) {
    case sig_id::ecdsa_nistp256:
    case sig_id::ecdsa_nistp384:
    case sig_id::ecdsa_nistp521: return true;
    default: return false;
    }
}

[[nodiscard]] constexpr bool is_sm2_sig(sig_id id) noexcept {
    switch (id) {
    case sig_id::sm2_za:
    case sig_id::sm2_ecdsa: return true;
    default: return false;
    }
}

// Selects which capability table `provider_vtable::supports` consults.
enum class primitive_kind : std::uint8_t { hash, cipher, mac, kex, signature };

[[nodiscard]] constexpr std::size_t hash_output_size(hash_id id) noexcept {
    switch (id) {
    case hash_id::sha1:   return 20;
    case hash_id::sha256: return 32;
    case hash_id::sha384: return 48;
    case hash_id::sha512: return 64;
    case hash_id::sm3:    return 32;
    }
    return 0;
}

[[nodiscard]] constexpr std::size_t cipher_key_size(cipher_id id) noexcept {
    switch (id) {
    case cipher_id::aes128_ctr: return 16;
    case cipher_id::aes192_ctr: return 24;
    case cipher_id::aes256_ctr: return 32;
    case cipher_id::aes128_gcm: return 16;
    case cipher_id::aes256_gcm: return 32;
    case cipher_id::chacha20:   return 32;
    case cipher_id::aes128_cbc: return 16;
    case cipher_id::aes192_cbc: return 24;
    case cipher_id::aes256_cbc: return 32;
    case cipher_id::sm4_ctr:    return 16;
    case cipher_id::sm4_cbc:    return 16;
    }
    return 0;
}

// Block size used when computing SSH packet padding (RFC 4253 section 6).
[[nodiscard]] constexpr std::size_t cipher_block_size(cipher_id id) noexcept {
    switch (id) {
    case cipher_id::aes128_ctr:
    case cipher_id::aes192_ctr:
    case cipher_id::aes256_ctr:
    case cipher_id::aes128_gcm:
    case cipher_id::aes256_gcm: return 16;
    case cipher_id::chacha20:   return 8;
    case cipher_id::aes128_cbc:
    case cipher_id::aes192_cbc:
    case cipher_id::aes256_cbc:
    case cipher_id::sm4_ctr:
    case cipher_id::sm4_cbc:    return 16;
    }
    return 0;
}

[[nodiscard]] constexpr std::size_t cipher_iv_size(cipher_id id) noexcept {
    switch (id) {
    case cipher_id::aes128_gcm:
    case cipher_id::aes256_gcm: return 12;
    case cipher_id::aes128_ctr:
    case cipher_id::aes192_ctr:
    case cipher_id::aes256_ctr:
    case cipher_id::aes128_cbc:
    case cipher_id::aes192_cbc:
    case cipher_id::aes256_cbc:
    case cipher_id::sm4_ctr:
    case cipher_id::sm4_cbc:
    case cipher_id::chacha20:   return 16;
    }
    return 0;
}

inline constexpr std::size_t max_generated_key_storage = 8192;

// PKCS#1 RSA signatures are modulus-sized. Provider max RSA is 8192-bit.
inline constexpr std::size_t max_signature_size = 1024;

[[nodiscard]] constexpr std::size_t generated_key_storage_size(
    sig_id id, std::uint32_t bits) noexcept {
    switch (id) {
    case sig_id::ed25519:         return 64;
    case sig_id::ecdsa_nistp256:  return 32 + 65;
    case sig_id::ecdsa_nistp384:  return 48 + 97;
    case sig_id::ecdsa_nistp521:  return 66 + 133;
    case sig_id::sm2_za:
    case sig_id::sm2_ecdsa:       return 32 + 65;
    case sig_id::rsa_pkcs1_sha1:
    case sig_id::rsa_pkcs1_sha256:
    case sig_id::rsa_pkcs1_sha512: {
        const std::uint32_t nbits = (bits == 0) ? 3072u : bits;
        const std::size_t nbytes = (nbits + 7u) / 8u;
        // n, e(~8), d, p, q, iqmp — generous cap, not a packed layout size
        return nbytes * 3u + (nbytes / 2u) * 3u + 32u;
    }
    }
    return 0;
}

// Size of the public value each key agreement puts on the wire, and of the
// shared secret it produces. For finite-field DH both are the modulus size.
[[nodiscard]] constexpr std::size_t kex_public_size(kex_id id) noexcept {
    switch (id) {
    case kex_id::curve25519:    return 32;
    case kex_id::ecdh_nistp256: return 65;    // SEC1 uncompressed: 0x04 || X || Y
    case kex_id::ecdh_nistp384: return 97;
    case kex_id::ecdh_nistp521: return 133;
    case kex_id::ecdh_sm2:
    case kex_id::sm2_kap:
    case kex_id::sm2_kap_server: return 65;
    case kex_id::dh_group14:    return 256;   // 2048-bit modulus
    case kex_id::dh_group16:    return 512;   // 4096-bit
    case kex_id::dh_group18:    return 1024;  // 8192-bit
    }
    return 0;
}

[[nodiscard]] constexpr std::size_t kex_secret_size(kex_id id) noexcept {
    switch (id) {
    case kex_id::curve25519:    return 32;
    case kex_id::ecdh_nistp256: return 32;    // x-coordinate only
    case kex_id::ecdh_nistp384: return 48;
    case kex_id::ecdh_nistp521: return 66;
    case kex_id::ecdh_sm2:
    case kex_id::sm2_kap:
    case kex_id::sm2_kap_server: return 32;
    case kex_id::dh_group14:    return 256;
    case kex_id::dh_group16:    return 512;
    case kex_id::dh_group18:    return 1024;
    }
    return 0;
}

// Raw public key material, in the representation SSH already carries. The
// provider never sees a container format.
struct public_key_material {
    sig_id algorithm = sig_id::ed25519;
    // ed25519: 32-byte public key.  ecdsa: SEC1 uncompressed point.  rsa: modulus n.
    std::span<const std::byte> a;
    // rsa: public exponent e.  Unused by ed25519 and ecdsa.
    std::span<const std::byte> b;
};

struct signature_material {
    // ed25519: 64-byte signature.  ecdsa: r.  rsa: raw signature bytes.
    std::span<const std::byte> a;
    // ecdsa: s.  Unused by ed25519 and rsa.
    std::span<const std::byte> b;
};

struct private_key_material {
    sig_id algorithm = sig_id::ed25519;
    std::span<const std::byte> seed;        // ed25519 seed / ecdsa scalar
    std::span<const std::byte> public_key;  // ed25519 pub / ecdsa SEC1 point
    std::span<const std::byte> n{};         // rsa
    std::span<const std::byte> e{};
    std::span<const std::byte> d{};
    std::span<const std::byte> p{};
    std::span<const std::byte> q{};
    std::span<const std::byte> iqmp{};
};

// Overwrites a buffer in a way the optimizer may not remove.
inline void secure_zero(std::span<std::byte> buf) noexcept {
    volatile std::byte* p = buf.data();
    for (std::size_t i = 0; i < buf.size(); ++i) p[i] = std::byte{0};
}

}  // namespace yanterm::ssh::crypto
