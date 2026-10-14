#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/memory/detail/pages.hpp>
#include <yanterm-ssh/transport/packet_mode.hpp>
#include <yanterm-ssh/crypto/provider.hpp>
#include <yanterm-ssh/detail/error.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

namespace yanterm::ssh::core::detail {

using ::yanterm::ssh::transport::packet_mode;

inline constexpr std::size_t max_packet_length = 35000;
static_assert(::yanterm::ssh::memory::default_page_size - memory::detail::page_header_size >= 4 + max_packet_length + 64,
              "one whole SSH binary packet (length + body + longest MAC) must fit a page");
inline constexpr std::size_t min_padding = 4;

// Everything needed to protect one direction. Move-only; owns its crypto handles.
// The GCM iv is derived key material. std::array's move copies, so the source
// is wiped after the bytes have been taken.
struct direction_state {
    packet_mode mode = packet_mode::plaintext;
    std::size_t block_size = 8;  // padding multiple; 8 when plaintext
    std::size_t mac_length = 0;
    crypto::cipher cipher;         // CTR modes, and the chacha payload key
    crypto::cipher length_cipher;  // chacha length key only      (Task 10)
    crypto::aead_cipher aead;             // GCM only                    (Task 10)
    crypto::hmac_ctx mac;
    std::array<std::byte, 12> iv{};       // GCM only                    (Task 10)
    std::uint32_t sequence_number = 0;

    direction_state() = default;
    ~direction_state() { crypto::secure_zero(std::span<std::byte>{iv}); }

    direction_state(const direction_state&) = delete;
    direction_state& operator=(const direction_state&) = delete;

    direction_state(direction_state&& other) noexcept;
    direction_state& operator=(direction_state&& other) noexcept;
};

inline direction_state::direction_state(direction_state&& other) noexcept
    : mode(other.mode)
    , block_size(other.block_size)
    , mac_length(other.mac_length)
    , cipher(std::move(other.cipher))
    , length_cipher(std::move(other.length_cipher))
    , aead(std::move(other.aead))
    , mac(std::move(other.mac))
    , iv(other.iv)
    , sequence_number(other.sequence_number) {
    crypto::secure_zero(std::span<std::byte>{other.iv});
}

inline direction_state& direction_state::operator=(direction_state&& other) noexcept {
    if (this != &other) {
        crypto::secure_zero(std::span<std::byte>{iv});
        mode = other.mode;
        block_size = other.block_size;
        mac_length = other.mac_length;
        cipher = std::move(other.cipher);
        length_cipher = std::move(other.length_cipher);
        aead = std::move(other.aead);
        mac = std::move(other.mac);
        iv = other.iv;
        sequence_number = other.sequence_number;
        crypto::secure_zero(std::span<std::byte>{other.iv});
    }
    return *this;
}

[[nodiscard]] inline std::size_t align_block(std::size_t block_size) noexcept {
    return (std::max)(std::size_t{8}, block_size == 0 ? std::size_t{8} : block_size);
}

// Smallest padding_len >= min_padding such that (base + padding_len) % block == 0.
[[nodiscard]] inline std::size_t choose_padding(std::size_t base, std::size_t block) noexcept {
    std::size_t pad = min_padding;
    const std::size_t rem = (base + pad) % block;
    if (rem != 0) pad += block - rem;
    return pad;
}

inline void store_be32(std::span<std::byte> out, std::uint32_t v) noexcept {
    out[0] = static_cast<std::byte>((v >> 24) & 0xffu);
    out[1] = static_cast<std::byte>((v >> 16) & 0xffu);
    out[2] = static_cast<std::byte>((v >> 8) & 0xffu);
    out[3] = static_cast<std::byte>(v & 0xffu);
}

[[nodiscard]] inline std::uint32_t load_be32(std::span<const std::byte> in) noexcept {
    return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[0])) << 24)
         | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[1])) << 16)
         | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[2])) << 8)
         |  static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(in[3]));
}

[[nodiscard]] inline std::error_code check_packet_length(std::uint32_t packet_length) noexcept {
    if (packet_length > max_packet_length) return code::packet_too_large;
    if (packet_length < 5) return code::invalid_packet_length;
    return {};
}

[[nodiscard]] inline std::error_code check_padding(std::uint8_t padding_length,
                                                   std::uint32_t packet_length) noexcept {
    if (padding_length < min_padding) return code::invalid_padding;
    if (padding_length > packet_length - 1u) return code::invalid_padding;
    return {};
}

// AES-GCM OpenSSH IV: fixed 4 bytes || big-endian invocation counter (8 bytes).
inline void bump_gcm_iv(std::array<std::byte, 12>& iv) noexcept {
    std::uint64_t ctr = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        ctr = (ctr << 8) | std::to_integer<std::uint8_t>(iv[4 + i]);
    }
    ++ctr;
    for (std::size_t i = 0; i < 8; ++i) {
        iv[11 - i] = static_cast<std::byte>(ctr & 0xffu);
        ctr >>= 8;
    }
}

// ChaCha20 IV for EVP_chacha20 / OpenSSH: counter(4,LE) || 00 00 00 00 || seq(8,BE).
inline void make_chacha_iv(std::array<std::byte, 16>& iv, std::uint32_t counter,
                           std::uint32_t seq) noexcept {
    iv[0] = static_cast<std::byte>(counter & 0xffu);
    iv[1] = static_cast<std::byte>((counter >> 8) & 0xffu);
    iv[2] = static_cast<std::byte>((counter >> 16) & 0xffu);
    iv[3] = static_cast<std::byte>((counter >> 24) & 0xffu);
    iv[4] = std::byte{0};
    iv[5] = std::byte{0};
    iv[6] = std::byte{0};
    iv[7] = std::byte{0};
    iv[8] = std::byte{0};
    iv[9] = std::byte{0};
    iv[10] = std::byte{0};
    iv[11] = std::byte{0};
    iv[12] = static_cast<std::byte>((seq >> 24) & 0xffu);
    iv[13] = static_cast<std::byte>((seq >> 16) & 0xffu);
    iv[14] = static_cast<std::byte>((seq >> 8) & 0xffu);
    iv[15] = static_cast<std::byte>(seq & 0xffu);
}

class packet_writer {
public:
    explicit packet_writer(crypto::provider p) : p_{p} {}

    void install(direction_state st) { st_ = std::move(st); }

    void reset_sequence() noexcept { st_.sequence_number = 0; }

    [[nodiscard]] std::uint32_t sequence_number() const noexcept { return st_.sequence_number; }

    // Writes one complete wire packet (length + body + MAC/tag) into a page
    // slice taken from `pool`. The page invariant (page_size >= one whole
    // packet) guarantees the packet never straddles pages. Delegates to
    // `write_streamed`; there is no intermediate full plaintext packet and no
    // session-sized GCM/ChaCha scratch.
    std::error_code write(std::span<const std::byte> payload, memory::detail::page_pool& pool, memory::detail::page_slice& out);

    // `fill` is invoked synchronously with an `append(span<const byte>)`
    // callable. Header, CBC leftovers, and small fragments sit in a bounded
    // stack staging buffer; cipher/aead updates always use disjoint in/out
    // (the wire page is never encrypted in place). The fragments must sum to
    // `payload_size` exactly or the write fails without committing `out` /
    // sequence / IV.
    template <class Fill>
    std::error_code write_streamed(std::size_t payload_size, memory::detail::page_pool& pool, memory::detail::page_slice& out,
                                   Fill&& fill) {
        stream_job job;
        if (auto ec = begin_packet(payload_size, pool, job); ec) return ec;
        std::forward<Fill>(fill)(
            [&](std::span<const std::byte> frag) { append_payload(job, frag); });
        if (job.ec) return job.ec;
        if (job.filled != payload_size) return code::invalid_state;
        return finish_packet(job, out);
    }

    [[nodiscard]] std::size_t max_payload_size(const memory::detail::page_pool& pool) const noexcept;

private:
    struct stream_job {
        static constexpr std::size_t staging_size = 512;

        memory::detail::page_slice slice;
        std::span<std::byte> wire;
        std::size_t payload_size = 0;
        std::size_t filled = 0;
        std::size_t pad = 0;
        std::size_t staged = 0;
        std::size_t cipher_out = 0;
        std::uint32_t packet_length = 0;
        std::error_code ec{};
        std::array<std::byte, 32> poly_key{};
        std::array<std::byte, staging_size> staging{};

        stream_job() = default;
        stream_job(const stream_job&) = delete;
        stream_job& operator=(const stream_job&) = delete;
        ~stream_job() {
            crypto::secure_zero(std::span<std::byte>{staging});
            crypto::secure_zero(std::span<std::byte>{poly_key});
        }
    };

    static void copy_in(std::span<std::byte> dst, std::span<const std::byte> src) noexcept;

    // Rejects a packet that would exceed the protocol max or the page. Does not
    // assert: a too-small pool or an oversized payload is a recoverable failure.
    [[nodiscard]] static std::error_code prepare_wire(std::size_t payload_size, std::size_t pad,
                                                      std::size_t tail, const memory::detail::page_pool& pool,
                                                      std::uint32_t& packet_length,
                                                      std::size_t& wire_size) noexcept;

    [[nodiscard]] std::size_t mode_tail() const noexcept;

    [[nodiscard]] std::size_t mode_block() const noexcept;

    [[nodiscard]] std::size_t mode_align_base() const noexcept;

    [[nodiscard]] std::error_code layout_for(std::size_t payload_size, const memory::detail::page_pool& pool,
                                             std::size_t& pad, std::uint32_t& packet_length,
                                             std::size_t& wire_size) const noexcept;

    std::error_code begin_packet(std::size_t payload_size, memory::detail::page_pool& pool, stream_job& job);

    void append_payload(stream_job& job, std::span<const std::byte> frag);

    [[nodiscard]] bool is_cbc() const noexcept;

    [[nodiscard]] bool encrypts_length() const noexcept;

    void stage_bytes(stream_job& job, std::span<const std::byte> src) noexcept;

    std::error_code emit_cipher(stream_job& job, std::span<const std::byte> plain);

    std::error_code crypt_chunk(std::span<const std::byte> in, std::span<std::byte> out);

    std::error_code flush_staging(stream_job& job);

    std::error_code flush_complete_blocks(stream_job& job);

    std::error_code spill_for_frag(stream_job& job, std::span<const std::byte>& frag);

    std::error_code finish_packet(stream_job& job, memory::detail::page_slice& out);

    crypto::provider p_;
    direction_state st_{};
};

class packet_reader {
public:
    explicit packet_reader(crypto::provider p) : p_{p} {}

    // Swaps in new keys. There is no buffered wire data to carry over: any
    // leftover bytes are still owned by the caller and will be presented again,
    // so they naturally decrypt under the keys installed here.
    void install(direction_state st);

    void reset_sequence() noexcept { st_.sequence_number = 0; }

    [[nodiscard]] std::uint32_t sequence_number() const noexcept { return st_.sequence_number; }

    // Consumes whole units only. When `in` does not hold a complete unit,
    // `accepted` stays 0, `payload` stays empty and no error is returned: the
    // caller keeps the bytes and presents them again later.
    //
    // The single exception is Encrypt-and-MAC, where reading the length
    // requires decrypting the first block and the cipher cannot be rewound.
    // That block is consumed as its own unit and its plaintext is retained here
    // (at most one cipher block). If length/alignment checks fail after that
    // decrypt, `accepted` still includes the block (caller must discard it) and
    // the reader is unusable until the next `install` — retrying the same
    // ciphertext would double-decrypt. Encrypt-then-MAC body decrypt followed
    // by illegal padding is poisoned the same way.
    std::error_code read(std::span<const std::byte> in, std::size_t& accepted, memory::detail::page_pool& pool,
                         memory::detail::page_slice& payload);

private:
    static void copy_out(std::span<std::byte> dst, std::span<const std::byte> src) noexcept;

    static std::error_code make_payload(memory::detail::page_slice& plain, std::size_t body_offset,
                                        std::uint32_t packet_length, memory::detail::page_slice& payload);

    std::error_code complete_clear_length(std::span<const std::byte> in, std::size_t& accepted,
                                          memory::detail::page_pool& pool, memory::detail::page_slice& payload,
                                          bool encrypted_body);

    std::error_code complete_eam(std::span<const std::byte> in, std::size_t& accepted,
                                 memory::detail::page_pool& pool, memory::detail::page_slice& payload);

    std::error_code complete_gcm(std::span<const std::byte> in, std::size_t& accepted,
                                 memory::detail::page_pool& pool, memory::detail::page_slice& payload);

    std::error_code complete_chacha(std::span<const std::byte> in, std::size_t& accepted,
                                    memory::detail::page_pool& pool, memory::detail::page_slice& payload);

    crypto::provider p_;
    direction_state st_{};
    std::vector<std::byte> eam_plain_;  // <= one cipher block of retained plaintext
    bool eam_prefix_ready_ = false;
    // Set once a streaming cipher has advanced without completing a packet
    // (E&M first-block / remainder, or EtM body decrypt). Cleared only by
    // install(); further read() calls return invalid_state so the caller cannot
    // double-decrypt.
    bool unusable_ = false;
};

}  // namespace yanterm::ssh::core::detail

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/core/detail/impl/packet.ipp>
#endif
