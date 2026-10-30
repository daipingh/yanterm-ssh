#pragma once

#include "../fixed_random_provider.hpp"

#include <yanterm-ssh/core/config.hpp>
#include <yanterm-ssh/core/types.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/crypto/provider.hpp>
#include <yanterm-ssh/keys/private_key.hpp>

#include <cstdint>
#include <string_view>

namespace yanterm::ssh::fuzz {

// connection_prekex input: ctrl byte, chunk byte, then the peer's byte stream.
// ctrl bit 0 picks the role under test (0 client, 1 server), bit 1 strict kex,
// bit 2 ext-info, and (ctrl >> 3) % 3 the chunk mode. Committed seeds and
// fuzz_corpus_gen.cpp depend on this layout.
enum class chunk_mode : unsigned {
    whole = 0,
    fixed = 1,           // chunk byte % 65 bytes per feed
    inline_lengths = 2,  // each chunk is preceded by its own length byte % 65
};

struct prekex_params {
    core::role role = core::role::client;
    core::config cfg{};
    chunk_mode mode = chunk_mode::whole;
};

// Recorded peer streams are bound to the target's identification string and
// KEXINIT through the exchange hash. Pinning them keeps the seeds valid across
// version bumps, default-order changes, and crypto libraries without ML-KEM or
// SM algorithms, so every name here must be available in OpenSSL 1.1.1.
inline constexpr std::string_view pinned_software = "yanterm_fuzz";
inline constexpr std::string_view pinned_kex =
    "curve25519-sha256,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,"
    "diffie-hellman-group16-sha512,diffie-hellman-group14-sha256";
inline constexpr std::string_view pinned_host_key =
    "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,"
    "rsa-sha2-512,rsa-sha2-256";
inline constexpr std::string_view pinned_cipher =
    "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,"
    "aes256-ctr,aes192-ctr,aes128-ctr";
inline constexpr std::string_view pinned_mac =
    "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512";

inline prekex_params decode_ctrl(std::uint8_t ctrl) noexcept {
    prekex_params p;
    p.cfg.software = pinned_software;
    p.cfg.preferred_kex = pinned_kex;
    p.cfg.preferred_host_key = pinned_host_key;
    p.cfg.preferred_cipher = pinned_cipher;
    p.cfg.preferred_mac = pinned_mac;
    p.role = (ctrl & 0x01u) == 0 ? core::role::client : core::role::server;
    p.cfg.advertise_strict_kex = (ctrl & 0x02u) != 0;
    p.cfg.advertise_ext_info = (ctrl & 0x04u) != 0;
    p.mode = static_cast<chunk_mode>((ctrl >> 3u) % 3u);
    return p;
}

// The generator records peer traffic against a target seeded identically, so
// replaying a recorded stream reproduces the same keys past NEWKEYS.
inline constexpr std::uint64_t target_random_seed = 0x5eed1234ULL;
inline constexpr std::uint64_t host_key_random_seed = 0x12345678ULL;

inline crypto::provider base_provider() {
    static crypto::openssl_backend backend;
    return crypto::provider::wrap(backend);
}

inline const keys::private_key& server_host_key() {
    static const keys::private_key key = [] {
        testing::fixed_random_provider rng{base_provider(), host_key_random_seed};
        keys::private_key hk;
        (void)keys::private_key::generate(rng.get(), crypto::sig_id::ed25519, 0, "fuzz-host", hk);
        return hk;
    }();
    return key;
}

}  // namespace yanterm::ssh::fuzz
