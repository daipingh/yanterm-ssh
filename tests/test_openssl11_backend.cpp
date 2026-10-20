#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/core/detail/host_key.hpp>
#include <yanterm-ssh/crypto/openssl11.hpp>
#include <yanterm-ssh/crypto/openssl3.hpp>
#include <yanterm-ssh/keys/public_key.hpp>
#include <yanterm-ssh/wire/types.hpp>

#include <array>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using namespace yanterm::ssh;

// Only built against OpenSSL 3.x, where both backends run in one process.

namespace {

crypto::provider legacy() {
    static crypto::ossl1_1::openssl_backend backend;
    return crypto::provider::wrap(backend);
}

crypto::provider modern() {
    static crypto::ossl3::openssl_backend backend;
    return crypto::provider::wrap(backend);
}

struct backend_pair {
    const char* name;
    crypto::provider from;
    crypto::provider to;
};

std::vector<backend_pair> pairs() {
    return {
        {"1.1 to 1.1", legacy(), legacy()},
        {"1.1 to 3", legacy(), modern()},
        {"3 to 1.1", modern(), legacy()},
    };
}

std::vector<std::byte> unhex(std::string_view s) {
    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return c - 'A' + 10;
    };
    std::vector<std::byte> out;
    for (std::size_t i = 0; i + 1 < s.size(); i += 2) {
        out.push_back(static_cast<std::byte>(nibble(s[i]) * 16 + nibble(s[i + 1])));
    }
    return out;
}

std::string hex(std::span<const std::byte> in) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    for (std::byte b : in) {
        out.push_back(kDigits[std::to_integer<unsigned>(b) >> 4]);
        out.push_back(kDigits[std::to_integer<unsigned>(b) & 0x0Fu]);
    }
    return out;
}

std::vector<std::byte> filled(std::size_t n, unsigned seed) {
    std::vector<std::byte> out(n);
    for (std::size_t i = 0; i < n; ++i) out[i] = static_cast<std::byte>(seed + i * 7u);
    return out;
}

std::span<const std::byte> bytes_of(std::string_view s) {
    return {reinterpret_cast<const std::byte*>(s.data()), s.size()};
}

}  // namespace

TEST_CASE("OpenSSL 1.1 backend offers ecgm-sm2-sm3 and Kylin SM2 under OpenSSL 3",
          "[crypto][openssl11][gm]") {
    crypto::provider p = legacy();
    if (!p.supports(crypto::hash_id::sm3)) SKIP("this OpenSSL has no SM2/SM3");
    REQUIRE(p.supports(crypto::kex_id::ecdh_sm2));
    REQUIRE(p.supports(crypto::sig_id::sm2_ecdsa));
}

// GM/T 0003.3 appendix C.3 keys; the shared secret is the x coordinate of dA*QB.
TEST_CASE("OpenSSL 1.1 backend ecgm-sm2-sm3 ECDH x matches appendix C.3",
          "[crypto][openssl11][gm][ecdh]") {
    crypto::provider p = legacy();
    if (!p.supports(crypto::kex_id::ecdh_sm2)) SKIP("this OpenSSL has no SM2");
    const auto dc = unhex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
    const auto qc = unhex(
        "04"
        "09f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020"
        "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13");
    const auto qs = unhex(
        "04"
        "04ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73"
        "e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df0");

    crypto::private_key_material key;
    key.algorithm = crypto::sig_id::sm2_ecdsa;
    key.seed = dc;
    key.public_key = qc;
    crypto::signing_key client = p.new_signing_key(key);
    REQUIRE(static_cast<bool>(client));
    auto* sk = static_cast<crypto::detail::openssl_signing_key*>(client.get());
    REQUIRE(sk != nullptr);

    // The kex borrows the signing key's EVP_PKEY for a fixed private half.
    crypto::detail::ossl1_1::openssl_kex kex{};
    kex.id = crypto::kex_id::ecdh_sm2;
    kex.pkey = sk->pkey;
    std::array<std::byte, 32> out{};
    std::size_t len = 0;
    const bool ok = crypto::ossl1_1::openssl_backend{}.kex_agree(&kex, qs.data(), qs.size(),
                                                                 out.data(), out.size(), &len);
    kex.pkey = nullptr;
    REQUIRE(ok);
    REQUIRE(len == 32);
    REQUIRE(hex(out) == "335e18d751e51f040e27d468138b7ab1dc86ad7f981d7d416222fd6ab3ed230d");
}

TEST_CASE("both OpenSSL backends produce identical digests, HMACs and Poly1305 tags",
          "[crypto][openssl11]") {
    const crypto::hash_id hashes[] = {
        crypto::hash_id::sha1, crypto::hash_id::sha256, crypto::hash_id::sha384,
        crypto::hash_id::sha512, crypto::hash_id::sm3,
    };
    const auto msg = filled(1000, 3);
    const auto key = filled(64, 11);

    for (crypto::hash_id id : hashes) {
        INFO("hash_id " << static_cast<int>(id));
        if (!legacy().supports(id) || !modern().supports(id)) continue;
        std::vector<std::byte> a(crypto::hash_output_size(id));
        std::vector<std::byte> b(a.size());
        REQUIRE(legacy().hash(id, msg, a));
        REQUIRE(modern().hash(id, msg, b));
        REQUIRE(hex(a) == hex(b));

        crypto::hmac_ctx ma = legacy().new_hmac(id, key);
        crypto::hmac_ctx mb = modern().new_hmac(id, key);
        REQUIRE(static_cast<bool>(ma));
        REQUIRE(static_cast<bool>(mb));
        ma.update(msg);
        mb.update(msg);
        REQUIRE(ma.final_into(a));
        REQUIRE(mb.final_into(b));
        REQUIRE(hex(a) == hex(b));
    }

    std::array<std::byte, 16> ta{};
    std::array<std::byte, 16> tb{};
    const auto pkey = filled(32, 5);
    REQUIRE(legacy().poly1305(pkey, msg, ta));
    REQUIRE(modern().poly1305(pkey, msg, tb));
    REQUIRE(hex(ta) == hex(tb));
}

TEST_CASE("ciphertext from one OpenSSL backend decrypts on the other", "[crypto][openssl11]") {
    const crypto::cipher_id stream_or_cbc[] = {
        crypto::cipher_id::aes128_ctr, crypto::cipher_id::aes192_ctr,
        crypto::cipher_id::aes256_ctr, crypto::cipher_id::chacha20,
        crypto::cipher_id::aes128_cbc, crypto::cipher_id::aes192_cbc,
        crypto::cipher_id::aes256_cbc, crypto::cipher_id::sm4_ctr,
        crypto::cipher_id::sm4_cbc,
    };
    const crypto::cipher_id aeads[] = {crypto::cipher_id::aes128_gcm,
                                       crypto::cipher_id::aes256_gcm};
    const auto plain = filled(64, 1);
    const auto aad = filled(13, 9);

    for (const auto& bp : pairs()) {
        INFO(bp.name);
        for (crypto::cipher_id id : stream_or_cbc) {
            INFO("cipher_id " << static_cast<int>(id));
            if (!bp.from.supports(id) || !bp.to.supports(id)) continue;
            const bool cbc = id == crypto::cipher_id::aes128_cbc
                             || id == crypto::cipher_id::aes192_cbc
                             || id == crypto::cipher_id::aes256_cbc
                             || id == crypto::cipher_id::sm4_cbc;
            const auto key = filled(crypto::cipher_key_size(id), 21);
            const auto iv = filled(16, 31);
            crypto::cipher enc = bp.from.new_cipher(id, key, true);
            crypto::cipher dec = bp.to.new_cipher(id, key, !cbc);
            REQUIRE(static_cast<bool>(enc));
            REQUIRE(static_cast<bool>(dec));
            REQUIRE(enc.set_iv(iv));
            REQUIRE(dec.set_iv(iv));
            std::vector<std::byte> ct(plain.size());
            std::vector<std::byte> back(plain.size());
            REQUIRE(enc.update(plain, ct));
            REQUIRE(hex(ct) != hex(plain));
            REQUIRE(dec.update(ct, back));
            REQUIRE(hex(back) == hex(plain));
        }
        for (crypto::cipher_id id : aeads) {
            INFO("cipher_id " << static_cast<int>(id));
            if (!bp.from.supports(id) || !bp.to.supports(id)) continue;
            const auto key = filled(crypto::cipher_key_size(id), 41);
            const auto iv = filled(12, 51);
            crypto::aead_cipher seal = bp.from.new_aead(id, key, true);
            crypto::aead_cipher open = bp.to.new_aead(id, key, false);
            REQUIRE(static_cast<bool>(seal));
            REQUIRE(static_cast<bool>(open));
            std::vector<std::byte> ct(plain.size());
            std::vector<std::byte> back(plain.size());
            std::array<std::byte, 16> tag{};
            REQUIRE(seal.begin(iv, aad));
            REQUIRE(seal.update(plain, ct));
            REQUIRE(seal.final(tag));
            REQUIRE(open.begin(iv, aad));
            REQUIRE(open.update(ct, back));
            REQUIRE(open.final(tag));
            REQUIRE(hex(back) == hex(plain));
        }
    }
}

TEST_CASE("key agreement succeeds across the two OpenSSL backends", "[crypto][openssl11][kex]") {
    struct kex_case {
        crypto::kex_id from;
        crypto::kex_id to;
    };
    const kex_case cases[] = {
        {crypto::kex_id::curve25519, crypto::kex_id::curve25519},
        {crypto::kex_id::ecdh_nistp256, crypto::kex_id::ecdh_nistp256},
        {crypto::kex_id::ecdh_nistp384, crypto::kex_id::ecdh_nistp384},
        {crypto::kex_id::ecdh_nistp521, crypto::kex_id::ecdh_nistp521},
        {crypto::kex_id::dh_group14, crypto::kex_id::dh_group14},
        {crypto::kex_id::dh_group16, crypto::kex_id::dh_group16},
        {crypto::kex_id::ecdh_sm2, crypto::kex_id::ecdh_sm2},
        {crypto::kex_id::sm2_kap, crypto::kex_id::sm2_kap_server},
    };

    for (const auto& bp : pairs()) {
        INFO(bp.name);
        for (const auto& c : cases) {
            INFO("kex_id " << static_cast<int>(c.from));
            if (!bp.from.supports(c.from) || !bp.to.supports(c.to)) continue;
            crypto::kex_agreement a = bp.from.new_kex(c.from);
            crypto::kex_agreement b = bp.to.new_kex(c.to);
            REQUIRE(static_cast<bool>(a));
            REQUIRE(static_cast<bool>(b));

            std::vector<std::byte> pa(crypto::kex_public_size(c.from));
            std::vector<std::byte> pb(crypto::kex_public_size(c.to));
            std::size_t la = 0;
            std::size_t lb = 0;
            REQUIRE(a.public_value(pa, la));
            REQUIRE(b.public_value(pb, lb));

            std::vector<std::byte> sa(crypto::kex_secret_size(c.from));
            std::vector<std::byte> sb(crypto::kex_secret_size(c.to));
            std::size_t ka = 0;
            std::size_t kb = 0;
            REQUIRE(a.agree(std::span{pb}.first(lb), sa, ka));
            REQUIRE(b.agree(std::span{pa}.first(la), sb, kb));
            REQUIRE(ka == kb);
            REQUIRE(hex(std::span{sa}.first(ka)) == hex(std::span{sb}.first(kb)));
        }
    }
}

TEST_CASE("signatures from one OpenSSL backend verify on the other", "[crypto][openssl11][sig]") {
    struct sig_case {
        crypto::sig_id id;
        std::uint32_t bits;
        std::string_view wire_name;
    };
    const sig_case cases[] = {
        {crypto::sig_id::ed25519, 0, "ssh-ed25519"},
        {crypto::sig_id::ecdsa_nistp256, 0, "ecdsa-sha2-nistp256"},
        {crypto::sig_id::ecdsa_nistp384, 0, "ecdsa-sha2-nistp384"},
        {crypto::sig_id::ecdsa_nistp521, 0, "ecdsa-sha2-nistp521"},
        {crypto::sig_id::rsa_pkcs1_sha256, 2048, "rsa-sha2-256"},
        {crypto::sig_id::rsa_pkcs1_sha512, 2048, "rsa-sha2-512"},
        {crypto::sig_id::sm2_za, 0, "sm2"},
        {crypto::sig_id::sm2_ecdsa, 0, "sm2"},
    };
    const auto msg = bytes_of("yanterm-ssh cross-backend signature");

    for (const auto& bp : pairs()) {
        INFO(bp.name);
        for (const auto& c : cases) {
            INFO(c.wire_name << " sig_id " << static_cast<int>(c.id));
            if (!bp.from.supports(c.id) || !bp.to.supports(c.id)) continue;
            // Both SM2 dialects share the "sm2" key type, generated as sm2_za.
            const crypto::sig_id key_id =
                crypto::is_sm2_sig(c.id) ? crypto::sig_id::sm2_za : c.id;
            std::array<std::byte, crypto::max_generated_key_storage> storage{};
            crypto::private_key_material priv{};
            REQUIRE(bp.from.generate_keypair(key_id, c.bits, priv, storage));
            priv.algorithm = c.id;
            crypto::signing_key signer = bp.from.new_signing_key(priv);
            REQUIRE(static_cast<bool>(signer));
            std::array<std::byte, crypto::max_signature_size> raw{};
            std::size_t len = 0;
            REQUIRE(signer.sign(msg, raw, len));

            wire::writer blob;
            REQUIRE_FALSE(core::detail::encode_signature(
                c.wire_name, std::span<const std::byte>{raw}.first(len), blob));

            crypto::public_key_material pub;
            pub.algorithm = key_id;
            if (crypto::is_rsa_sig(c.id)) {
                pub.a = priv.n;
                pub.b = priv.e;
            } else {
                pub.a = priv.public_key;
            }
            keys::public_key pk;
            REQUIRE_FALSE(keys::public_key::from_material(pub, pk));
            core::detail::host_key_view view;
            REQUIRE_FALSE(core::detail::parse_host_key(pk.blob(), view));
            REQUIRE_FALSE(core::detail::verify_signature(bp.to, view, c.wire_name,
                                                         blob.data(), msg));
        }
    }
}
