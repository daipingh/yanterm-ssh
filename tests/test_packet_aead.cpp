#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/detail/error.hpp>

#include <yanterm-ssh/memory/detail/pages.hpp>
#include <yanterm-ssh/core/detail/packet.hpp>
#include <yanterm-ssh/crypto/openssl.hpp>

#include "fixed_random_provider.hpp"
#include "hex_util.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <span>
#include <string>
#include <vector>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

namespace {

crypto::provider prov() {
    static crypto::openssl_backend backend;
    return crypto::provider::wrap(backend);
}

std::vector<std::byte> make_payload(std::size_t n, std::byte fill = std::byte{0x41}) {
    return std::vector<std::byte>(n, fill);
}

std::uint32_t read_be32(std::span<const std::byte> p) {
    REQUIRE(p.size() >= 4);
    return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(p[0])) << 24)
         | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(p[1])) << 16)
         | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(p[2])) << 8)
         |  static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(p[3]));
}

struct gcm_keys {
    std::array<std::byte, 32> key{};
    std::array<std::byte, 12> iv{};
};

gcm_keys fixed_gcm_keys() {
    gcm_keys k;
    for (std::size_t i = 0; i < k.key.size(); ++i) {
        k.key[i] = static_cast<std::byte>(0x20 + i);
    }
    for (std::size_t i = 0; i < k.iv.size(); ++i) {
        k.iv[i] = static_cast<std::byte>(0xB0 + i);
    }
    return k;
}

core::detail::direction_state make_gcm(crypto::provider p, const gcm_keys& keys,
                                    bool encrypt, std::uint32_t seq = 0) {
    core::detail::direction_state s;
    s.mode = core::detail::packet_mode::gcm;
    s.block_size = 16;
    s.mac_length = 16;
    s.sequence_number = seq;
    s.iv = keys.iv;
    s.aead = p.new_aead(crypto::cipher_id::aes256_gcm, keys.key, encrypt);
    REQUIRE(static_cast<bool>(s.aead));
    return s;
}

struct chacha_keys {
    // K_2 || K_1 (OpenSSH order): payload+poly first, length second.
    std::array<std::byte, 64> key{};
};

chacha_keys fixed_chacha_keys() {
    chacha_keys k;
    for (std::size_t i = 0; i < k.key.size(); ++i) {
        k.key[i] = static_cast<std::byte>(0x30 + i);
    }
    return k;
}

core::detail::direction_state make_chacha(crypto::provider p, const chacha_keys& keys,
                                       std::uint32_t seq = 0) {
    core::detail::direction_state s;
    s.mode = core::detail::packet_mode::chacha20_poly1305;
    s.block_size = 8;
    s.mac_length = 16;
    s.sequence_number = seq;
    const auto k2 = std::span<const std::byte>{keys.key}.first(32);
    const auto k1 = std::span<const std::byte>{keys.key}.subspan(32, 32);
    s.cipher = p.new_cipher(crypto::cipher_id::chacha20, k2, true);
    s.length_cipher = p.new_cipher(crypto::cipher_id::chacha20, k1, true);
    REQUIRE(static_cast<bool>(s.cipher));
    REQUIRE(static_cast<bool>(s.length_cipher));
    return s;
}

struct ctr_keys {
    std::array<std::byte, 32> cipher_key{};
    std::array<std::byte, 16> iv{};
    std::array<std::byte, 32> mac_key{};
};

ctr_keys fixed_ctr_keys() {
    ctr_keys k;
    for (std::size_t i = 0; i < k.cipher_key.size(); ++i) {
        k.cipher_key[i] = static_cast<std::byte>(0x10 + i);
    }
    for (std::size_t i = 0; i < k.iv.size(); ++i) {
        k.iv[i] = static_cast<std::byte>(0xA0 + i);
    }
    for (std::size_t i = 0; i < k.mac_key.size(); ++i) {
        k.mac_key[i] = static_cast<std::byte>(0x50 + i);
    }
    return k;
}

core::detail::direction_state make_ctr(crypto::provider p, core::detail::packet_mode mode,
                                    const ctr_keys& keys) {
    core::detail::direction_state s;
    s.mode = mode;
    s.block_size = 16;
    s.mac_length = 32;
    s.cipher = p.new_cipher(crypto::cipher_id::aes256_ctr, keys.cipher_key, true);
    REQUIRE(static_cast<bool>(s.cipher));
    REQUIRE(s.cipher.set_iv(keys.iv));
    s.mac = p.new_hmac(crypto::hash_id::sha256, keys.mac_key);
    REQUIRE(static_cast<bool>(s.mac));
    return s;
}

core::detail::direction_state make_cbc(crypto::provider p, core::detail::packet_mode mode,
                                    const ctr_keys& keys, bool encrypt) {
    core::detail::direction_state s;
    s.mode = mode;
    s.block_size = 16;
    s.mac_length = 32;
    s.cipher = p.new_cipher(crypto::cipher_id::sm4_cbc, std::span{keys.cipher_key}.first(16),
                            encrypt);
    REQUIRE(static_cast<bool>(s.cipher));
    REQUIRE(s.cipher.set_iv(keys.iv));
    s.mac = p.new_hmac(crypto::hash_id::sha256, keys.mac_key);
    REQUIRE(static_cast<bool>(s.mac));
    return s;
}

std::string as_string(std::span<const std::byte> s) {
    return {reinterpret_cast<const char*>(s.data()), s.size()};
}

core::detail::direction_state make_plaintext() {
    core::detail::direction_state s;
    s.mode = core::detail::packet_mode::plaintext;
    s.block_size = 8;
    s.mac_length = 0;
    return s;
}

core::detail::direction_state make_mode(crypto::provider p, core::detail::packet_mode mode,
                                    bool encrypt = true) {
    switch (mode) {
    case core::detail::packet_mode::plaintext:
        return make_plaintext();
    case core::detail::packet_mode::ctr_encrypt_and_mac:
        return make_ctr(p, mode, fixed_ctr_keys());
    case core::detail::packet_mode::ctr_encrypt_then_mac:
        return make_ctr(p, mode, fixed_ctr_keys());
    case core::detail::packet_mode::cbc_encrypt_and_mac:
    case core::detail::packet_mode::cbc_encrypt_then_mac:
        return make_cbc(p, mode, fixed_ctr_keys(), encrypt);
    case core::detail::packet_mode::gcm:
        return make_gcm(p, fixed_gcm_keys(), encrypt);
    case core::detail::packet_mode::chacha20_poly1305:
        return make_chacha(p, fixed_chacha_keys());
    }
    return {};
}

template <class Append>
void append_split(Append&& append, std::span<const std::byte> payload) {
    if (payload.size() <= 1) {
        append(payload);
        return;
    }
    append(payload.first(1));
    append(payload.subspan(1, payload.size() / 2));
    append(payload.subspan(1 + payload.size() / 2));
}

std::error_code roundtrip(core::detail::packet_writer& w, core::detail::packet_reader& r,
                          std::span<const std::byte> payload,
                          std::vector<std::byte>* wire_out = nullptr) {
    memory::detail::page_pool pool;
    memory::detail::page_slice slice;
    auto ec = w.write(payload, pool, slice);
    if (ec) return ec;
    const auto wire_bytes = slice.bytes();
    if (wire_out) {
        wire_out->assign(wire_bytes.begin(), wire_bytes.end());
    }
    std::size_t consumed = 0;
    memory::detail::page_slice got;
    ec = r.read(wire_bytes, consumed, pool, got);
    if (ec) return ec;
    REQUIRE(consumed == wire_bytes.size());
    REQUIRE(got.size() == payload.size());
    if (!payload.empty()) {
        REQUIRE(std::memcmp(got.bytes().data(), payload.data(), payload.size()) == 0);
    }
    return {};
}

enum class aead_fail_at { begin, update, final_tag };

struct aead_fail_overlay {
    crypto::provider inner_;
    aead_fail_at at;

    [[nodiscard]] crypto::provider inner() const noexcept { return inner_; }

    void* aead_new(crypto::cipher_id id, const std::byte* key, std::size_t keylen,
                   bool enc) noexcept {
        auto h = inner_.new_aead(id, std::span<const std::byte>{key, keylen}, enc);
        if (!h) return nullptr;
        return new (std::nothrow) crypto::aead_cipher(std::move(h));
    }
    void aead_free(void* ctx) noexcept { delete static_cast<crypto::aead_cipher*>(ctx); }
    bool aead_begin(void* ctx, const std::byte* iv, std::size_t ivlen, const std::byte* aad,
                    std::size_t aadlen) noexcept {
        if (at == aead_fail_at::begin) return false;
        if (ctx == nullptr) return false;
        return static_cast<crypto::aead_cipher*>(ctx)->begin(
            std::span<const std::byte>{iv, ivlen}, std::span<const std::byte>{aad, aadlen});
    }
    bool aead_update(void* ctx, const std::byte* in, std::byte* out, std::size_t n) noexcept {
        if (at == aead_fail_at::update) return false;
        if (ctx == nullptr) return false;
        return static_cast<crypto::aead_cipher*>(ctx)->update(std::span<const std::byte>{in, n},
                                                             std::span<std::byte>{out, n});
    }
    bool aead_final(void* ctx, std::byte* tag, std::size_t n) noexcept {
        if (at == aead_fail_at::final_tag) return false;
        if (ctx == nullptr) return false;
        return static_cast<crypto::aead_cipher*>(ctx)->final(std::span<std::byte>{tag, n});
    }
};

}  // namespace

TEST_CASE("gcm round-trips across payload lengths", "[packet][aead][gcm]") {
    crypto::provider p = prov();
    const auto keys = fixed_gcm_keys();
    const std::size_t lengths[] = {0, 1, 15, 16, 17, 100, 32768};
    for (std::size_t n : lengths) {
        INFO("payload_len=" << n);
        core::detail::packet_writer w(p);
        core::detail::packet_reader r(p);
        w.install(make_gcm(p, keys, true));
        r.install(make_gcm(p, keys, false));
        const auto payload = make_payload(n, static_cast<std::byte>(n & 0xff));
        REQUIRE_FALSE(roundtrip(w, r, payload));
    }
}

TEST_CASE("gcm length is cleartext and body is 16-aligned", "[packet][aead][gcm]") {
    crypto::provider p = prov();
    const auto keys = fixed_gcm_keys();
    core::detail::packet_writer w(p);
    w.install(make_gcm(p, keys, true));

    const auto payload = make_payload(17, std::byte{0x11});
    memory::detail::page_pool pool;
    memory::detail::page_slice slice;
    REQUIRE_FALSE(w.write(payload, pool, slice));
    const auto wire_bytes = slice.bytes();

    const auto pkt_len = read_be32(wire_bytes);
    // Length field is plaintext at the head; encrypted body length is 16-aligned.
    REQUIRE(pkt_len % 16u == 0);
    REQUIRE(pkt_len >= 5);
    REQUIRE(wire_bytes.size() == 4u + pkt_len + 16u);

    std::size_t pad = 4;
    const std::size_t rem = (1u + payload.size() + pad) % 16u;
    if (rem != 0) pad += 16u - rem;
    REQUIRE(pkt_len == static_cast<std::uint32_t>(1u + payload.size() + pad));
}

TEST_CASE("gcm IV counter stays in sync and desync fails", "[packet][aead][gcm][iv]") {
    crypto::provider p = prov();
    const auto keys = fixed_gcm_keys();
    core::detail::packet_writer w(p);
    core::detail::packet_reader r(p);
    w.install(make_gcm(p, keys, true));
    r.install(make_gcm(p, keys, false));

    const auto payload = make_payload(8, std::byte{0x22});
    for (int i = 0; i < 4; ++i) {
        REQUIRE_FALSE(roundtrip(w, r, payload));
    }

    // Writer advances IV once without the reader consuming that packet.
    memory::detail::page_pool pool;
    memory::detail::page_slice skipped;
    REQUIRE_FALSE(w.write(payload, pool, skipped));

    memory::detail::page_slice next;
    REQUIRE_FALSE(w.write(payload, pool, next));
    std::size_t consumed = 0;
    memory::detail::page_slice got;
    REQUIRE(r.read(next.bytes(), consumed, pool, got) == code::decrypt_failure);
}

TEST_CASE("gcm rejects corrupted AAD and tag", "[packet][aead][gcm][auth]") {
    crypto::provider p = prov();
    const auto keys = fixed_gcm_keys();
    core::detail::packet_writer w(p);
    w.install(make_gcm(p, keys, true));

    const auto payload = make_payload(20, std::byte{0x33});
    memory::detail::page_pool pool;
    memory::detail::page_slice slice;
    REQUIRE_FALSE(w.write(payload, pool, slice));
    auto bytes = std::vector<std::byte>(slice.bytes().begin(), slice.bytes().end());
    const auto orig_len = read_be32(bytes);
    REQUIRE(orig_len >= 32);
    REQUIRE(orig_len % 16u == 0);

    SECTION("corrupt clear length (AAD) while keeping a valid shorter frame") {
        core::detail::packet_reader r(p);
        r.install(make_gcm(p, keys, false));
        // Shrink length by one AES block so framing still parses; AAD no longer matches.
        const std::uint32_t bad_len = orig_len - 16u;
        bytes[0] = static_cast<std::byte>((bad_len >> 24) & 0xff);
        bytes[1] = static_cast<std::byte>((bad_len >> 16) & 0xff);
        bytes[2] = static_cast<std::byte>((bad_len >> 8) & 0xff);
        bytes[3] = static_cast<std::byte>(bad_len & 0xff);
        // Truncate buffer to the new wire size so the reader authenticates a wrong slice.
        bytes.resize(4u + bad_len + 16u);
        std::size_t consumed = 0;
        memory::detail::page_slice got;
        REQUIRE(r.read(bytes, consumed, pool, got) == code::decrypt_failure);
        REQUIRE(got.empty());
        REQUIRE(consumed == 0);
    }
    SECTION("corrupt tag") {
        core::detail::packet_reader r(p);
        r.install(make_gcm(p, keys, false));
        bytes.back() ^= std::byte{0x01};
        std::size_t consumed = 0;
        memory::detail::page_slice got;
        REQUIRE(r.read(bytes, consumed, pool, got) == code::decrypt_failure);
        REQUIRE(got.empty());
        REQUIRE(consumed == 0);
    }
}

TEST_CASE("gcm reader maps begin/update failure to aead_failure and final to decrypt_failure",
          "[packet][aead][gcm][errc]") {
    crypto::provider p = prov();
    const auto keys = fixed_gcm_keys();
    core::detail::packet_writer w(p);
    w.install(make_gcm(p, keys, true));

    const auto payload = make_payload(20, std::byte{0x33});
    memory::detail::page_pool pool;
    memory::detail::page_slice slice;
    REQUIRE_FALSE(w.write(payload, pool, slice));
    const auto wire = slice.bytes();

    const struct {
        aead_fail_at at;
        code expect;
    } cases[] = {
        {aead_fail_at::begin, code::aead_failure},
        {aead_fail_at::update, code::aead_failure},
        {aead_fail_at::final_tag, code::decrypt_failure},
    };
    for (const auto& c : cases) {
        INFO("fail_at=" << static_cast<int>(c.at));
        aead_fail_overlay ov{p, c.at};
        crypto::provider rp = crypto::provider::decorate(ov);
        core::detail::packet_reader r(rp);
        r.install(make_gcm(rp, keys, false));
        std::size_t consumed = 0;
        memory::detail::page_slice got;
        REQUIRE(r.read(wire, consumed, pool, got) == c.expect);
        REQUIRE(got.empty());
        REQUIRE(consumed == 0);
    }
}

TEST_CASE("chacha20-poly1305 round-trips across payload lengths",
          "[packet][aead][chacha]") {
    crypto::provider p = prov();
    const auto keys = fixed_chacha_keys();
    const std::size_t lengths[] = {0, 1, 7, 8, 9, 100, 32768};
    for (std::size_t n : lengths) {
        INFO("payload_len=" << n);
        core::detail::packet_writer w(p);
        core::detail::packet_reader r(p);
        w.install(make_chacha(p, keys));
        r.install(make_chacha(p, keys));
        const auto payload = make_payload(n, static_cast<std::byte>(n & 0xff));
        REQUIRE_FALSE(roundtrip(w, r, payload));
    }
}

TEST_CASE("chacha20-poly1305 encrypts the length field", "[packet][aead][chacha]") {
    crypto::provider p = prov();
    const auto keys = fixed_chacha_keys();
    core::detail::packet_writer w(p);
    w.install(make_chacha(p, keys));

    const auto payload = make_payload(9, std::byte{0x44});
    memory::detail::page_pool pool;
    memory::detail::page_slice slice;
    REQUIRE_FALSE(w.write(payload, pool, slice));
    const auto wire_bytes = slice.bytes();

    const auto wire_len_field = read_be32(wire_bytes);
    // Encrypted body is 8-aligned: pad chosen so 1+payload+pad % 8 == 0.
    const std::size_t pad = [&] {
        std::size_t p = 4;
        const std::size_t rem = (1u + payload.size() + p) % 8u;
        if (rem != 0) p += 8u - rem;
        return p;
    }();
    const std::uint32_t clear_len = static_cast<std::uint32_t>(1u + payload.size() + pad);
    REQUIRE(wire_len_field != clear_len);
    REQUIRE(wire_bytes.size() == 4u + clear_len + 16u);
}

TEST_CASE("chacha20-poly1305 rejects corrupted ciphertext", "[packet][aead][chacha][mac]") {
    crypto::provider p = prov();
    const auto keys = fixed_chacha_keys();
    core::detail::packet_writer w(p);
    w.install(make_chacha(p, keys));

    const auto payload = make_payload(12, std::byte{0x55});
    memory::detail::page_pool pool;
    memory::detail::page_slice slice;
    REQUIRE_FALSE(w.write(payload, pool, slice));
    auto bytes = std::vector<std::byte>(slice.bytes().begin(), slice.bytes().end());
    REQUIRE(bytes.size() > 8);
    bytes[6] ^= std::byte{0x01};

    core::detail::packet_reader r(p);
    r.install(make_chacha(p, keys));
    std::size_t consumed = 0;
    memory::detail::page_slice got;
    REQUIRE(r.read(bytes, consumed, pool, got) == code::mac_mismatch);
}

TEST_CASE("chacha20-poly1305 handles sequence 0xffffffff", "[packet][aead][chacha][seq]") {
    crypto::provider p = prov();
    const auto keys = fixed_chacha_keys();
    core::detail::packet_writer w(p);
    core::detail::packet_reader r(p);
    w.install(make_chacha(p, keys, 0xffffffffu));
    r.install(make_chacha(p, keys, 0xffffffffu));

    const auto payload = make_payload(3, std::byte{0x66});
    REQUIRE_FALSE(roundtrip(w, r, payload));
    REQUIRE(w.sequence_number() == 0);
    REQUIRE(r.sequence_number() == 0);
}

TEST_CASE("four encryption modes produce distinct wire bytes", "[packet][aead][distinct]") {
    crypto::provider p = prov();
    const auto payload = bytes_of("same-payload");
    const auto ctr = fixed_ctr_keys();
    const auto gcm = fixed_gcm_keys();
    const auto cha = fixed_chacha_keys();

    auto write_one = [&](core::detail::direction_state st) {
        core::detail::packet_writer w(p);
        w.install(std::move(st));
        memory::detail::page_pool pool;
        memory::detail::page_slice slice;
        REQUIRE_FALSE(w.write(payload, pool, slice));
        return std::vector<std::byte>(slice.bytes().begin(), slice.bytes().end());
    };

    const auto eam = write_one(make_ctr(p, core::detail::packet_mode::ctr_encrypt_and_mac, ctr));
    const auto etm = write_one(make_ctr(p, core::detail::packet_mode::ctr_encrypt_then_mac, ctr));
    const auto g = write_one(make_gcm(p, gcm, true));
    const auto c = write_one(make_chacha(p, cha));

    auto differs = [](const std::vector<std::byte>& a, const std::vector<std::byte>& b) {
        if (a.size() != b.size()) return true;
        return std::memcmp(a.data(), b.data(), a.size()) != 0;
    };
    REQUIRE(differs(eam, etm));
    REQUIRE(differs(eam, g));
    REQUIRE(differs(eam, c));
    REQUIRE(differs(etm, g));
    REQUIRE(differs(etm, c));
    REQUIRE(differs(g, c));
}

TEST_CASE("gcm reader consumes nothing until a whole packet is present",
          "[packet][aead][partial]") {
    crypto::provider p = prov();
    const auto keys = fixed_gcm_keys();
    core::detail::packet_writer w(p);
    core::detail::packet_reader r(p);
    w.install(make_gcm(p, keys, true));
    r.install(make_gcm(p, keys, false));

    memory::detail::page_pool pool;
    memory::detail::page_slice packet;
    REQUIRE_FALSE(w.write(bytes_of("hello"), pool, packet));
    const auto wire_bytes = packet.bytes();

    for (std::size_t prefix = 0; prefix < wire_bytes.size(); ++prefix) {
        std::size_t accepted = 0;
        memory::detail::page_slice payload;
        REQUIRE_FALSE(r.read(wire_bytes.first(prefix), accepted, pool, payload));
        REQUIRE(accepted == 0);
        REQUIRE(payload.empty());
    }

    std::size_t accepted = 0;
    memory::detail::page_slice payload;
    REQUIRE_FALSE(r.read(wire_bytes, accepted, pool, payload));
    REQUIRE(accepted == wire_bytes.size());
    REQUIRE(as_string(payload.bytes()) == "hello");
}

TEST_CASE("chacha reader consumes nothing until a whole packet is present",
          "[packet][aead][partial]") {
    crypto::provider p = prov();
    const auto keys = fixed_chacha_keys();
    core::detail::packet_writer w(p);
    core::detail::packet_reader r(p);
    w.install(make_chacha(p, keys));
    r.install(make_chacha(p, keys));

    memory::detail::page_pool pool;
    memory::detail::page_slice packet;
    REQUIRE_FALSE(w.write(bytes_of("hello"), pool, packet));
    const auto wire_bytes = packet.bytes();

    for (std::size_t prefix = 0; prefix < wire_bytes.size(); ++prefix) {
        std::size_t accepted = 0;
        memory::detail::page_slice payload;
        REQUIRE_FALSE(r.read(wire_bytes.first(prefix), accepted, pool, payload));
        REQUIRE(accepted == 0);
        REQUIRE(payload.empty());
    }

    std::size_t accepted = 0;
    memory::detail::page_slice payload;
    REQUIRE_FALSE(r.read(wire_bytes, accepted, pool, payload));
    REQUIRE(accepted == wire_bytes.size());
    REQUIRE(as_string(payload.bytes()) == "hello");
}

TEST_CASE("streamed and contiguous writes match for every packet mode",
          "[packet][aead][stream]") {
    const core::detail::packet_mode modes[] = {
        core::detail::packet_mode::plaintext,
        core::detail::packet_mode::ctr_encrypt_and_mac,
        core::detail::packet_mode::ctr_encrypt_then_mac,
        core::detail::packet_mode::cbc_encrypt_and_mac,
        core::detail::packet_mode::cbc_encrypt_then_mac,
        core::detail::packet_mode::gcm,
        core::detail::packet_mode::chacha20_poly1305,
    };
    const std::size_t lengths[] = {0, 1, 17, 64, 1200};

    for (auto mode : modes) {
        for (std::size_t n : lengths) {
            INFO("mode=" << static_cast<int>(mode) << " payload_len=" << n);
            const auto payload = make_payload(n, static_cast<std::byte>(0xB0 + (n & 0x0f)));

            fixed_random_provider rng_one(prov(), 0xD00DFEEDULL);
            fixed_random_provider rng_split(prov(), 0xD00DFEEDULL);
            crypto::provider p_one = rng_one.get();
            crypto::provider p_split = rng_split.get();

            core::detail::packet_writer w_one(p_one);
            core::detail::packet_writer w_split(p_split);
            w_one.install(make_mode(p_one, mode));
            w_split.install(make_mode(p_split, mode));

            memory::detail::page_pool pool;
            memory::detail::page_slice contiguous;
            memory::detail::page_slice streamed;
            REQUIRE_FALSE(w_one.write(payload, pool, contiguous));
            REQUIRE_FALSE(w_split.write_streamed(
                payload.size(), pool, streamed,
                [&](auto&& append) { append_split(append, payload); }));
            REQUIRE(contiguous.size() == streamed.size());
            REQUIRE(contiguous.size() > 0);
            REQUIRE(std::memcmp(contiguous.bytes().data(), streamed.bytes().data(),
                                contiguous.size()) == 0);

            crypto::provider p_read = prov();
            core::detail::packet_reader r(p_read);
            r.install(make_mode(p_read, mode, false));
            std::size_t accepted = 0;
            memory::detail::page_slice got;
            REQUIRE_FALSE(r.read(streamed.bytes(), accepted, pool, got));
            REQUIRE(accepted == streamed.size());
            REQUIRE(got.size() == payload.size());
            if (!payload.empty()) {
                REQUIRE(std::memcmp(got.bytes().data(), payload.data(), payload.size()) == 0);
            }
        }
    }
}

TEST_CASE("max_payload_size succeeds and max+1 is rejected for AEAD modes",
          "[packet][aead][stream][bound]") {
    const core::detail::packet_mode modes[] = {
        core::detail::packet_mode::gcm,
        core::detail::packet_mode::chacha20_poly1305,
    };
    const std::size_t page_sizes[] = {memory::default_page_size, 256};

    for (auto mode : modes) {
        for (std::size_t page_size : page_sizes) {
            INFO("mode=" << static_cast<int>(mode) << " page_size=" << page_size);
            crypto::provider p = prov();
            core::detail::packet_writer w(p);
            w.install(make_mode(p, mode));
            memory::detail::page_pool pool{page_size};
            const std::size_t max = w.max_payload_size(pool);
            REQUIRE(max > 0);
            REQUIRE(max < page_size);

            memory::detail::page_slice ok;
            REQUIRE_FALSE(w.write(make_payload(max), pool, ok));
            REQUIRE_FALSE(ok.empty());
            const auto seq = w.sequence_number();

            bool fill_called = false;
            memory::detail::page_slice too_big;
            REQUIRE(w.write_streamed(max + 1, pool, too_big, [&](auto&& append) {
                fill_called = true;
                append({});
            }) == code::packet_too_large);
            REQUIRE_FALSE(fill_called);
            REQUIRE(too_big.empty());
            REQUIRE(w.sequence_number() == seq);
        }
    }
}

TEST_CASE("gcm write_streamed accepts arbitrary payload splits", "[packet][aead][gcm][stream]") {
    crypto::provider p = prov();
    const auto keys = fixed_gcm_keys();
    const auto payload = make_payload(33, std::byte{0x7a});
    const std::size_t splits[][6] = {
        {33, 0, 0, 0, 0, 0},
        {0, 33, 0, 0, 0, 0},
        {1, 32, 0, 0, 0, 0},
        {16, 17, 0, 0, 0, 0},
        {1, 1, 1, 1, 29, 0},
        {8, 0, 8, 0, 17, 0},
    };

    for (const auto& split : splits) {
        INFO("split=" << split[0] << "," << split[1] << "," << split[2] << "," << split[3] << ","
                      << split[4] << "," << split[5]);
        fixed_random_provider rng_one(prov(), 0xA11CE5ULL);
        fixed_random_provider rng_split(prov(), 0xA11CE5ULL);

        core::detail::packet_writer w_one(rng_one.get());
        core::detail::packet_writer w_split(rng_split.get());
        w_one.install(make_gcm(rng_one.get(), keys, true));
        w_split.install(make_gcm(rng_split.get(), keys, true));

        memory::detail::page_pool pool;
        memory::detail::page_slice contiguous;
        memory::detail::page_slice streamed;
        REQUIRE_FALSE(w_one.write(payload, pool, contiguous));
        REQUIRE_FALSE(w_split.write_streamed(payload.size(), pool, streamed, [&](auto&& append) {
            std::size_t off = 0;
            const std::span<const std::byte> bytes = payload;
            for (std::size_t n : split) {
                append(bytes.subspan(off, n));
                off += n;
            }
            REQUIRE(off == payload.size());
        }));
        REQUIRE(contiguous.size() == streamed.size());
        REQUIRE(std::memcmp(contiguous.bytes().data(), streamed.bytes().data(),
                            contiguous.size()) == 0);

        core::detail::packet_reader r(p);
        r.install(make_gcm(p, keys, false));
        std::size_t accepted = 0;
        memory::detail::page_slice got;
        REQUIRE_FALSE(r.read(streamed.bytes(), accepted, pool, got));
        REQUIRE(got.size() == payload.size());
        REQUIRE(std::memcmp(got.bytes().data(), payload.data(), payload.size()) == 0);
    }
}
