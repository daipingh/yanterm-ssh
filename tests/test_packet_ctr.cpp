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

void write_be32(std::vector<std::byte>& out, std::uint32_t v) {
    out.push_back(static_cast<std::byte>((v >> 24) & 0xff));
    out.push_back(static_cast<std::byte>((v >> 16) & 0xff));
    out.push_back(static_cast<std::byte>((v >> 8) & 0xff));
    out.push_back(static_cast<std::byte>(v & 0xff));
}

core::detail::direction_state make_plaintext(std::uint32_t seq = 0) {
    core::detail::direction_state s;
    s.mode = core::detail::packet_mode::plaintext;
    s.block_size = 8;
    s.mac_length = 0;
    s.sequence_number = seq;
    return s;
}

struct ctr_keys {
    std::array<std::byte, 32> cipher_key{};
    std::array<std::byte, 16> iv{};
    std::array<std::byte, 32> mac_key{};
};

ctr_keys fixed_keys() {
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
                                    const ctr_keys& keys, std::uint32_t seq = 0) {
    core::detail::direction_state s;
    s.mode = mode;
    s.block_size = 16;
    s.mac_length = 32;
    s.sequence_number = seq;
    s.cipher = p.new_cipher(crypto::cipher_id::aes256_ctr, keys.cipher_key, true);
    REQUIRE(static_cast<bool>(s.cipher));
    REQUIRE(s.cipher.set_iv(keys.iv));
    s.mac = p.new_hmac(crypto::hash_id::sha256, keys.mac_key);
    REQUIRE(static_cast<bool>(s.mac));
    return s;
}

std::string as_string(std::span<const std::byte> s) {
    return {reinterpret_cast<const char*>(s.data()), s.size()};
}

struct ctr_pair {
    core::detail::packet_writer writer;
    core::detail::packet_reader reader;
    std::size_t block_size = 16;
};

ctr_pair make_ctr_pair(core::detail::packet_mode mode) {
    crypto::provider p = prov();
    const auto keys = fixed_keys();
    ctr_pair f{core::detail::packet_writer{p}, core::detail::packet_reader{p}, 16};
    f.writer.install(make_ctr(p, mode, keys));
    f.reader.install(make_ctr(p, mode, keys));
    return f;
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
    REQUIRE(consumed > 0);
    REQUIRE(got.size() == payload.size());
    if (!payload.empty()) {
        REQUIRE(std::memcmp(got.bytes().data(), payload.data(), payload.size()) == 0);
    }
    return {};
}

}  // namespace

TEST_CASE("plaintext round-trips and obeys padding rules", "[packet][ctr][plaintext]") {
    crypto::provider p = prov();
    core::detail::packet_writer w(p);
    core::detail::packet_reader r(p);
    w.install(make_plaintext());
    r.install(make_plaintext());

    const auto payload = make_payload(5, std::byte{0x42});
    memory::detail::page_pool pool;
    memory::detail::page_slice slice;
    REQUIRE_FALSE(w.write(payload, pool, slice));
    const auto wire_bytes = slice.bytes();
    REQUIRE(wire_bytes.size() >= 5u + 4u);

    const auto pkt_len = read_be32(wire_bytes);
    REQUIRE((pkt_len + 4u) % 8u == 0);
    REQUIRE(std::to_integer<std::uint8_t>(wire_bytes[4]) >= 4);

    std::size_t consumed = 0;
    memory::detail::page_slice got;
    REQUIRE_FALSE(r.read(wire_bytes, consumed, pool, got));
    REQUIRE(got.size() == payload.size());
    REQUIRE(std::memcmp(got.bytes().data(), payload.data(), payload.size()) == 0);
}

TEST_CASE("plaintext round-trips across payload lengths", "[packet][ctr][plaintext]") {
    crypto::provider p = prov();
    const std::size_t lengths[] = {0, 1, 7, 8, 9, 100, 32768};
    for (std::size_t n : lengths) {
        INFO("payload_len=" << n);
        core::detail::packet_writer w(p);
        core::detail::packet_reader r(p);
        w.install(make_plaintext());
        r.install(make_plaintext());
        const auto payload = make_payload(n, static_cast<std::byte>(n & 0xff));
        REQUIRE_FALSE(roundtrip(w, r, payload));
    }
}

TEST_CASE("ctr encrypt-and-mac round-trips", "[packet][ctr][eam]") {
    crypto::provider p = prov();
    const auto keys = fixed_keys();
    core::detail::packet_writer w(p);
    core::detail::packet_reader r(p);
    w.install(make_ctr(p, core::detail::packet_mode::ctr_encrypt_and_mac, keys));
    r.install(make_ctr(p, core::detail::packet_mode::ctr_encrypt_and_mac, keys));

    const auto payload = make_payload(37, std::byte{0x7e});
    REQUIRE_FALSE(roundtrip(w, r, payload));
}

TEST_CASE("ctr encrypt-then-mac round-trips with clear length", "[packet][ctr][etm]") {
    crypto::provider p = prov();
    const auto keys = fixed_keys();
    core::detail::packet_writer w(p);
    core::detail::packet_reader r(p);
    w.install(make_ctr(p, core::detail::packet_mode::ctr_encrypt_then_mac, keys));
    r.install(make_ctr(p, core::detail::packet_mode::ctr_encrypt_then_mac, keys));

    const auto payload = make_payload(11, std::byte{0x55});
    std::vector<std::byte> wire_bytes;
    REQUIRE_FALSE(roundtrip(w, r, payload, &wire_bytes));

    const auto pkt_len = read_be32(wire_bytes);
    // EtM: length is plaintext; encrypted body is pkt_len bytes.
    REQUIRE(pkt_len >= 5);
    REQUIRE(pkt_len % 16u == 0);  // encrypted portion multiple of AES block
    REQUIRE(wire_bytes.size() == 4u + pkt_len + 32u);
}

TEST_CASE("sequence numbers increment and wrap", "[packet][ctr][seq]") {
    crypto::provider p = prov();
    core::detail::packet_writer w(p);
    core::detail::packet_reader r(p);
    w.install(make_plaintext());
    r.install(make_plaintext());

    const auto payload = make_payload(1, std::byte{0x01});
    for (std::uint32_t i = 0; i < 3; ++i) {
        REQUIRE(w.sequence_number() == i);
        REQUIRE(r.sequence_number() == i);
        REQUIRE_FALSE(roundtrip(w, r, payload));
    }
    REQUIRE(w.sequence_number() == 3);
    REQUIRE(r.sequence_number() == 3);

    // Manual wrap setup via install (sequence lives in direction_state).
    w.install(make_plaintext(0xfffffffeu));
    r.install(make_plaintext(0xfffffffeu));
    REQUIRE(w.sequence_number() == 0xfffffffeu);
    REQUIRE(r.sequence_number() == 0xfffffffeu);

    for (int i = 0; i < 3; ++i) {
        REQUIRE_FALSE(roundtrip(w, r, payload));
    }
    REQUIRE(w.sequence_number() == 1);  // fe, ff, 00 → next is 1
    REQUIRE(r.sequence_number() == 1);
}

TEST_CASE("reader consumes nothing until a whole packet is present (EtM)",
          "[packet][ctr][partial]") {
    auto fixture = make_ctr_pair(core::detail::packet_mode::ctr_encrypt_then_mac);
    memory::detail::page_pool pool;
    memory::detail::page_slice packet;
    REQUIRE_FALSE(fixture.writer.write(bytes_of("hello"), pool, packet));
    const auto wire_bytes = packet.bytes();

    for (std::size_t prefix = 0; prefix < wire_bytes.size(); ++prefix) {
        std::size_t accepted = 0;
        memory::detail::page_slice payload;
        REQUIRE_FALSE(fixture.reader.read(wire_bytes.first(prefix), accepted, pool, payload));
        REQUIRE(accepted == 0);
        REQUIRE(payload.empty());
    }

    std::size_t accepted = 0;
    memory::detail::page_slice payload;
    REQUIRE_FALSE(fixture.reader.read(wire_bytes, accepted, pool, payload));
    REQUIRE(accepted == wire_bytes.size());
    REQUIRE(as_string(payload.bytes()) == "hello");
}

TEST_CASE("Encrypt-and-MAC consumes the first block as its own unit",
          "[packet][ctr][partial]") {
    auto fixture = make_ctr_pair(core::detail::packet_mode::ctr_encrypt_and_mac);
    memory::detail::page_pool pool;
    memory::detail::page_slice packet;
    REQUIRE_FALSE(fixture.writer.write(bytes_of("hello"), pool, packet));
    const auto wire_bytes = packet.bytes();
    const std::size_t block = fixture.block_size;

    // Feeding exactly one block consumes it (the length is now known) but
    // yields no payload yet.
    std::size_t accepted = 0;
    memory::detail::page_slice payload;
    REQUIRE_FALSE(fixture.reader.read(wire_bytes.first(block), accepted, pool, payload));
    REQUIRE(accepted == block);
    REQUIRE(payload.empty());

    // Feeding a still-incomplete remainder consumes nothing more.
    accepted = 0;
    REQUIRE_FALSE(fixture.reader.read(wire_bytes.subspan(block, 1), accepted, pool, payload));
    REQUIRE(accepted == 0);
    REQUIRE(payload.empty());

    // The rest completes the packet; the first block is not re-decrypted.
    accepted = 0;
    REQUIRE_FALSE(fixture.reader.read(wire_bytes.subspan(block), accepted, pool, payload));
    REQUIRE(accepted == wire_bytes.size() - block);
    REQUIRE(as_string(payload.bytes()) == "hello");
}

TEST_CASE("two packets in one buffer are consumed one unit per call",
          "[packet][ctr][partial]") {
    auto fixture = make_ctr_pair(core::detail::packet_mode::ctr_encrypt_then_mac);
    memory::detail::page_pool pool;
    memory::detail::page_slice first;
    memory::detail::page_slice second;
    REQUIRE_FALSE(fixture.writer.write(bytes_of("one"), pool, first));
    REQUIRE_FALSE(fixture.writer.write(bytes_of("two"), pool, second));

    std::vector<std::byte> buf;
    buf.insert(buf.end(), first.bytes().begin(), first.bytes().end());
    buf.insert(buf.end(), second.bytes().begin(), second.bytes().end());

    std::size_t accepted = 0;
    memory::detail::page_slice payload;
    REQUIRE_FALSE(fixture.reader.read(buf, accepted, pool, payload));
    REQUIRE(accepted == first.size());
    REQUIRE(as_string(payload.bytes()) == "one");

    std::size_t accepted2 = 0;
    REQUIRE_FALSE(fixture.reader.read(std::span{buf}.subspan(accepted), accepted2, pool, payload));
    REQUIRE(accepted2 == second.size());
    REQUIRE(as_string(payload.bytes()) == "two");
}

TEST_CASE("plaintext reader consumes nothing until a whole packet is present",
          "[packet][ctr][partial]") {
    crypto::provider p = prov();
    core::detail::packet_writer w(p);
    core::detail::packet_reader r(p);
    w.install(make_plaintext());
    r.install(make_plaintext());

    const auto payload_bytes = bytes_of("frag");
    memory::detail::page_pool pool;
    memory::detail::page_slice packet;
    REQUIRE_FALSE(w.write(payload_bytes, pool, packet));
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
    REQUIRE(as_string(payload.bytes()) == "frag");
}

TEST_CASE("etm rejects corrupted ciphertext and mac", "[packet][ctr][etm][mac]") {
    crypto::provider p = prov();
    const auto keys = fixed_keys();
    core::detail::packet_writer w(p);
    core::detail::packet_reader r(p);
    w.install(make_ctr(p, core::detail::packet_mode::ctr_encrypt_then_mac, keys));

    const auto payload = make_payload(20, std::byte{0xcd});
    memory::detail::page_pool pool;
    memory::detail::page_slice slice;
    REQUIRE_FALSE(w.write(payload, pool, slice));
    auto bytes = std::vector<std::byte>(slice.bytes().begin(), slice.bytes().end());

    SECTION("corrupt ciphertext body") {
        r.install(make_ctr(p, core::detail::packet_mode::ctr_encrypt_then_mac, keys));
        REQUIRE(bytes.size() > 8);
        bytes[6] ^= std::byte{0x01};
        std::size_t consumed = 0;
        memory::detail::page_slice got;
        REQUIRE(r.read(bytes, consumed, pool, got) == code::mac_mismatch);
    }
    SECTION("corrupt mac tail") {
        r.install(make_ctr(p, core::detail::packet_mode::ctr_encrypt_then_mac, keys));
        bytes.back() ^= std::byte{0x01};
        std::size_t consumed = 0;
        memory::detail::page_slice got;
        REQUIRE(r.read(bytes, consumed, pool, got) == code::mac_mismatch);
    }
}

TEST_CASE("writer rejects a payload that would exceed max_packet_length",
          "[packet][ctr][error]") {
    crypto::provider p = prov();
    core::detail::packet_writer w(p);
    w.install(make_plaintext());

    const auto payload = make_payload(core::detail::max_packet_length);
    memory::detail::page_pool pool;
    memory::detail::page_slice slice;
    REQUIRE(w.write(payload, pool, slice) == code::message_size);
    REQUIRE(slice.empty());
}

TEST_CASE("writer reports message_size when the page cannot hold the wire packet",
          "[packet][ctr][error]") {
    crypto::provider p = prov();
    core::detail::packet_writer w(p);
    w.install(make_plaintext());

    memory::detail::page_pool tiny{memory::detail::page_header_size + 8};
    memory::detail::page_slice slice;
    REQUIRE(w.write(bytes_of("hello"), tiny, slice) == code::message_size);
    REQUIRE(slice.empty());
}

TEST_CASE("Encrypt-and-MAC remainder MAC failure poisons the reader",
          "[packet][ctr][eam][error]") {
    auto fixture = make_ctr_pair(core::detail::packet_mode::ctr_encrypt_and_mac);
    memory::detail::page_pool pool;
    memory::detail::page_slice packet;
    REQUIRE_FALSE(fixture.writer.write(bytes_of("hello"), pool, packet));
    auto wire = std::vector<std::byte>(packet.bytes().begin(), packet.bytes().end());
    const std::size_t block = fixture.block_size;

    std::size_t accepted = 0;
    memory::detail::page_slice payload;
    REQUIRE_FALSE(fixture.reader.read(std::span{wire}.first(block), accepted, pool, payload));
    REQUIRE(accepted == block);
    REQUIRE(payload.empty());

    wire.back() ^= std::byte{0x01};
    accepted = 0;
    REQUIRE(fixture.reader.read(std::span{wire}.subspan(block), accepted, pool, payload)
            == code::mac_mismatch);

    accepted = 0;
    REQUIRE(fixture.reader.read(std::span{wire}.subspan(block), accepted, pool, payload)
            == code::invalid_state);
}

TEST_CASE("EtM padding failure after decrypt poisons the reader",
          "[packet][ctr][etm][error]") {
    crypto::provider p = prov();
    const auto keys = fixed_keys();
    auto enc = make_ctr(p, core::detail::packet_mode::ctr_encrypt_then_mac, keys);

    // packet_length=16 (AES-block aligned). padding_length=0 is illegal after decrypt.
    constexpr std::uint32_t packet_length = 16;
    std::vector<std::byte> body(packet_length, std::byte{0});
    REQUIRE(enc.cipher.update(body, body));

    std::vector<std::byte> wire;
    write_be32(wire, packet_length);
    wire.insert(wire.end(), body.begin(), body.end());

    std::array<std::byte, 4> seq{};
    std::array<std::byte, 32> mac{};
    enc.mac.update(seq);
    enc.mac.update(std::span{wire}.first(4));
    enc.mac.update(body);
    REQUIRE(enc.mac.final_into(mac));
    wire.insert(wire.end(), mac.begin(), mac.end());

    core::detail::packet_reader r(p);
    r.install(make_ctr(p, core::detail::packet_mode::ctr_encrypt_then_mac, keys));
    memory::detail::page_pool pool;
    std::size_t accepted = 0;
    memory::detail::page_slice payload;
    REQUIRE(r.read(wire, accepted, pool, payload) == code::invalid_padding);

    accepted = 0;
    REQUIRE(r.read(wire, accepted, pool, payload) == code::invalid_state);
}

TEST_CASE("Encrypt-and-MAC illegal length consumes first block and poisons reader",
          "[packet][ctr][eam][error]") {
    crypto::provider p = prov();
    const auto keys = fixed_keys();
    constexpr std::size_t block = 16;

    // Ciphertext whose first-block plaintext has packet_length=0 (< 5).
    std::array<std::byte, block> wire{};
    {
        auto enc = make_ctr(p, core::detail::packet_mode::ctr_encrypt_and_mac, keys);
        REQUIRE(enc.cipher.update(wire, wire));
    }

    core::detail::packet_reader r(p);
    r.install(make_ctr(p, core::detail::packet_mode::ctr_encrypt_and_mac, keys));

    memory::detail::page_pool pool;
    std::size_t accepted = 0;
    memory::detail::page_slice payload;
    REQUIRE(r.read(wire, accepted, pool, payload) == code::invalid_packet_length);
    REQUIRE(accepted == block);
    REQUIRE(payload.empty());

    // Same block must not be treated as a fresh E&M prefix (CTR already advanced).
    accepted = 0;
    REQUIRE(r.read(wire, accepted, pool, payload) == code::invalid_state);
    REQUIRE(accepted == 0);
}

TEST_CASE("reader rejects padding_length below minimum", "[packet][ctr][error]") {
    crypto::provider p = prov();
    core::detail::packet_reader r(p);
    r.install(make_plaintext());

    // packet_length=12 → total with length field is 16 (multiple of 8).
    // padding_length=3 → payload would be 8 bytes, but padding is illegal.
    std::vector<std::byte> pkt;
    write_be32(pkt, 12);
    pkt.push_back(std::byte{3});
    pkt.insert(pkt.end(), 8, std::byte{0x11});
    pkt.insert(pkt.end(), 3, std::byte{0x22});

    memory::detail::page_pool pool;
    std::size_t consumed = 0;
    memory::detail::page_slice got;
    REQUIRE(r.read(pkt, consumed, pool, got) == code::invalid_padding);
}

TEST_CASE("reader rejects oversized packet_length", "[packet][ctr][error]") {
    crypto::provider p = prov();
    core::detail::packet_reader r(p);
    r.install(make_plaintext());

    std::vector<std::byte> pkt;
    write_be32(pkt, 40000);
    // Only the length field is required for the early reject.
    memory::detail::page_pool pool;
    std::size_t consumed = 0;
    memory::detail::page_slice got;
    REQUIRE(r.read(pkt, consumed, pool, got) == code::invalid_packet_length);
}

TEST_CASE("padding bytes are random across writes", "[packet][ctr][plaintext]") {
    crypto::provider p = prov();
    core::detail::packet_writer w(p);
    w.install(make_plaintext());

    const auto payload = make_payload(3, std::byte{0x99});
    memory::detail::page_pool pool;
    memory::detail::page_slice a;
    memory::detail::page_slice b;
    REQUIRE_FALSE(w.write(payload, pool, a));
    REQUIRE_FALSE(w.write(payload, pool, b));
    REQUIRE(a.size() == b.size());
    REQUIRE(a.size() > 5);

    const auto pad_a = std::to_integer<std::uint8_t>(a.bytes()[4]);
    const auto pad_b = std::to_integer<std::uint8_t>(b.bytes()[4]);
    REQUIRE(pad_a >= 4);
    REQUIRE(pad_b >= 4);
    REQUIRE(a.size() == 4u + read_be32(a.bytes()));

    const auto body_a = a.bytes().subspan(5);  // skip length + padding_length
    const auto body_b = b.bytes().subspan(5);
    // Payload is identical; padding region must differ (random_bytes).
    const std::size_t payload_len = payload.size();
    REQUIRE(body_a.size() >= payload_len + pad_a);
    REQUIRE(body_b.size() >= payload_len + pad_b);
    const auto pad_bytes_a = body_a.subspan(payload_len, pad_a);
    const auto pad_bytes_b = body_b.subspan(payload_len, pad_b);
    REQUIRE(pad_a == pad_b);  // same payload length → same pad length
    REQUIRE_FALSE(std::memcmp(pad_bytes_a.data(), pad_bytes_b.data(), pad_a) == 0);
}

namespace {

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

}  // namespace

TEST_CASE("streamed and contiguous writes match for plaintext and CTR",
          "[packet][ctr][stream]") {
    const core::detail::packet_mode modes[] = {
        core::detail::packet_mode::plaintext,
        core::detail::packet_mode::ctr_encrypt_and_mac,
        core::detail::packet_mode::ctr_encrypt_then_mac,
    };
    const std::size_t lengths[] = {0, 1, 17, 64, 1200};
    const auto keys = fixed_keys();

    for (auto mode : modes) {
        for (std::size_t n : lengths) {
            INFO("mode=" << static_cast<int>(mode) << " payload_len=" << n);
            const auto payload = make_payload(n, static_cast<std::byte>(0xA0 + (n & 0x0f)));

            fixed_random_provider rng_one(prov(), 0xC0FFEEu);
            fixed_random_provider rng_split(prov(), 0xC0FFEEu);
            crypto::provider p_one = rng_one.get();
            crypto::provider p_split = rng_split.get();

            core::detail::packet_writer w_one(p_one);
            core::detail::packet_writer w_split(p_split);
            if (mode == core::detail::packet_mode::plaintext) {
                w_one.install(make_plaintext());
                w_split.install(make_plaintext());
            } else {
                w_one.install(make_ctr(p_one, mode, keys));
                w_split.install(make_ctr(p_split, mode, keys));
            }

            memory::detail::page_pool pool;
            memory::detail::page_slice contiguous;
            memory::detail::page_slice streamed;
            REQUIRE_FALSE(w_one.write(payload, pool, contiguous));
            REQUIRE_FALSE(w_split.write_streamed(payload.size(), pool, streamed,
                                                 [&](auto&& append) { append_split(append, payload); }));
            REQUIRE(contiguous.size() == streamed.size());
            REQUIRE(contiguous.size() > 0);
            REQUIRE(std::memcmp(contiguous.bytes().data(), streamed.bytes().data(),
                                contiguous.size()) == 0);

            crypto::provider p_read = prov();
            core::detail::packet_reader r(p_read);
            if (mode == core::detail::packet_mode::plaintext) {
                r.install(make_plaintext());
            } else {
                r.install(make_ctr(p_read, mode, keys));
            }
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

TEST_CASE("max_payload_size succeeds and max+1 is rejected for plaintext and CTR",
          "[packet][ctr][stream][bound]") {
    const core::detail::packet_mode modes[] = {
        core::detail::packet_mode::plaintext,
        core::detail::packet_mode::ctr_encrypt_and_mac,
        core::detail::packet_mode::ctr_encrypt_then_mac,
    };
    const std::size_t page_sizes[] = {memory::default_page_size, 256};
    const auto keys = fixed_keys();

    for (auto mode : modes) {
        for (std::size_t page_size : page_sizes) {
            INFO("mode=" << static_cast<int>(mode) << " page_size=" << page_size);
            crypto::provider p = prov();
            core::detail::packet_writer w(p);
            if (mode == core::detail::packet_mode::plaintext) {
                w.install(make_plaintext());
            } else {
                w.install(make_ctr(p, mode, keys));
            }
            memory::detail::page_pool pool{page_size};
            const std::size_t max = w.max_payload_size(pool);
            if (page_size == 256) {
                REQUIRE(max < page_size);
            } else {
                REQUIRE(max > 0);
            }

            memory::detail::page_slice ok;
            REQUIRE_FALSE(w.write(make_payload(max), pool, ok));
            REQUIRE_FALSE(ok.empty());
            const auto seq = w.sequence_number();

            bool fill_called = false;
            memory::detail::page_slice too_big;
            REQUIRE(w.write_streamed(max + 1, pool, too_big, [&](auto&& append) {
                fill_called = true;
                append({});
            }) == code::message_size);
            REQUIRE_FALSE(fill_called);
            REQUIRE(too_big.empty());
            REQUIRE(w.sequence_number() == seq);
        }
    }
}

TEST_CASE("write_streamed rejects a fill that does not sum to payload_size",
          "[packet][ctr][stream][error]") {
    crypto::provider p = prov();
    core::detail::packet_writer w(p);
    w.install(make_plaintext());
    memory::detail::page_pool pool;
    const auto seq = w.sequence_number();

    SECTION("undershoot") {
        memory::detail::page_slice out;
        REQUIRE(w.write_streamed(4, pool, out, [&](auto&& append) { append(bytes_of("ab")); }));
        REQUIRE(out.empty());
        REQUIRE(w.sequence_number() == seq);
    }
    SECTION("overshoot") {
        memory::detail::page_slice out;
        REQUIRE(w.write_streamed(4, pool, out, [&](auto&& append) { append(bytes_of("hello")); }));
        REQUIRE(out.empty());
        REQUIRE(w.sequence_number() == seq);
    }
}
