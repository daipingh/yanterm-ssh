#pragma once

#include <yanterm-ssh/core/detail/packet.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/core/detail/impl/packet.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/crypto/algorithms.hpp>

#include <cstring>
#include <string>
#include <system_error>

namespace yanterm::ssh::core::detail {

YANTERM_SSH_INLINE std::error_code packet_read_need_more() noexcept {
    class category final : public std::error_category {
    public:
        [[nodiscard]] const char* name() const noexcept override { return "yanterm-ssh.need-more"; }
        [[nodiscard]] std::string message(int) const override { return "need more"; }
    };
    static const category instance;
    return {1, instance};
}

YANTERM_SSH_INLINE std::error_code packet_writer::write(std::span<const std::byte> payload, memory::detail::page_pool& pool, memory::detail::page_slice& out) {
    return write_streamed(payload.size(), pool, out,
                          [payload](auto&& append) { append(payload); });
}

YANTERM_SSH_INLINE std::size_t packet_writer::max_payload_size(const memory::detail::page_pool& pool) const noexcept {
    const std::size_t block = mode_block();
    const std::size_t tail = mode_tail();
    const std::size_t align_base = mode_align_base();
    if (block == 0) return 0;
    if (pool.page_capacity() < 4u + tail) return 0;
    const std::size_t max_pl = (std::min)(max_packet_length, pool.page_capacity() - 4u - tail);
    if (max_pl < 1u + min_padding) return 0;
    const std::size_t limit = max_pl - 1u;
    const std::size_t cap = limit + align_base;
    const std::size_t aligned = (cap / block) * block;
    if (aligned < align_base + min_padding) return 0;
    std::size_t payload = aligned - align_base - min_padding;
    if (payload > max_packet_length) payload = max_packet_length;
    std::size_t pad = 0;
    std::uint32_t packet_length = 0;
    std::size_t wire_size = 0;
    while (layout_for(payload, pool, pad, packet_length, wire_size)) {
        if (payload == 0) return 0;
        --payload;
    }
    return payload;
}

YANTERM_SSH_INLINE void packet_writer::copy_in(std::span<std::byte> dst, std::span<const std::byte> src) noexcept {
    if (!src.empty()) std::memcpy(dst.data(), src.data(), src.size());
}

YANTERM_SSH_INLINE std::error_code packet_writer::prepare_wire(std::size_t payload_size, std::size_t pad,
                                                      std::size_t tail, const memory::detail::page_pool& pool,
                                                      std::uint32_t& packet_length,
                                                      std::size_t& wire_size) noexcept {
    if (payload_size > max_packet_length) {
        return code::message_size;
    }
    const std::size_t pl = 1u + payload_size + pad;
    if (pl > max_packet_length) return code::message_size;
    const std::size_t ws = 4u + pl + tail;
    if (ws < 4u + pl || ws > pool.page_capacity()) {
        return code::message_size;
    }
    packet_length = static_cast<std::uint32_t>(pl);
    wire_size = ws;
    return {};
}

YANTERM_SSH_INLINE std::size_t packet_writer::mode_tail() const noexcept {
    switch (st_.mode) {
    case packet_mode::plaintext:
        return 0;
    case packet_mode::ctr_encrypt_and_mac:
    case packet_mode::ctr_encrypt_then_mac:
    case packet_mode::cbc_encrypt_and_mac:
    case packet_mode::cbc_encrypt_then_mac:
        return st_.mac_length;
    case packet_mode::gcm:
    case packet_mode::chacha20_poly1305:
        return 16;
    }
    return 0;
}

YANTERM_SSH_INLINE std::size_t packet_writer::mode_block() const noexcept {
    switch (st_.mode) {
    case packet_mode::gcm:
        return 16;
    case packet_mode::chacha20_poly1305:
        return 8;
    default:
        return align_block(st_.block_size);
    }
}

YANTERM_SSH_INLINE std::size_t packet_writer::mode_align_base() const noexcept {
    switch (st_.mode) {
    case packet_mode::plaintext:
    case packet_mode::ctr_encrypt_and_mac:
    case packet_mode::cbc_encrypt_and_mac:
        return 5;
    default:
        return 1;
    }
}

YANTERM_SSH_INLINE std::error_code packet_writer::layout_for(std::size_t payload_size, const memory::detail::page_pool& pool,
                                             std::size_t& pad, std::uint32_t& packet_length,
                                             std::size_t& wire_size) const noexcept {
    pad = choose_padding(mode_align_base() + payload_size, mode_block());
    return prepare_wire(payload_size, pad, mode_tail(), pool, packet_length, wire_size);
}

YANTERM_SSH_INLINE std::error_code packet_writer::begin_packet(std::size_t payload_size, memory::detail::page_pool& pool, stream_job& job) {
    switch (st_.mode) {
    case packet_mode::plaintext:
        break;
    case packet_mode::ctr_encrypt_and_mac:
    case packet_mode::ctr_encrypt_then_mac:
    case packet_mode::cbc_encrypt_and_mac:
    case packet_mode::cbc_encrypt_then_mac:
        if (!st_.cipher || !st_.mac || st_.mac_length == 0) {
            return code::invalid_state;
        }
        break;
    case packet_mode::gcm:
        if (!st_.aead) return code::invalid_state;
        break;
    case packet_mode::chacha20_poly1305:
        if (!st_.cipher || !st_.length_cipher) return code::invalid_state;
        break;
    default:
        return code::invalid_state;
    }

    std::size_t pad = 0;
    std::uint32_t packet_length = 0;
    std::size_t wire_size = 0;
    if (auto ec = layout_for(payload_size, pool, pad, packet_length, wire_size); ec) return ec;

    memory::detail::page_slice slice = pool.allocate(wire_size);
    if (slice.size() != wire_size) return code::message_size;
    auto w = slice.mutable_bytes();

    job.slice = std::move(slice);
    job.wire = w;
    job.payload_size = payload_size;
    job.pad = pad;
    job.packet_length = packet_length;
    job.staged = 0;
    job.cipher_out = 0;

    switch (st_.mode) {
    case packet_mode::plaintext:
        store_be32(w.first(4), packet_length);
        w[4] = static_cast<std::byte>(pad);
        return p_.random_bytes(w.subspan(5 + payload_size, pad));
    case packet_mode::cbc_encrypt_and_mac:
    case packet_mode::ctr_encrypt_and_mac: {
        std::array<std::byte, 4> seq{};
        store_be32(seq, st_.sequence_number);
        st_.mac.update(seq);
        store_be32(std::span<std::byte>{job.staging}.first(4), packet_length);
        job.staging[4] = static_cast<std::byte>(pad);
        job.staged = 5;
        return {};
    }
    case packet_mode::cbc_encrypt_then_mac:
    case packet_mode::ctr_encrypt_then_mac: {
        store_be32(w.first(4), packet_length);
        std::array<std::byte, 4> seq{};
        store_be32(seq, st_.sequence_number);
        st_.mac.update(seq);
        st_.mac.update(w.first(4));
        job.staging[0] = static_cast<std::byte>(pad);
        job.staged = 1;
        return {};
    }
    case packet_mode::gcm:
        store_be32(w.first(4), packet_length);
        if (!st_.aead.begin(st_.iv, w.first(4))) return code::aead_failure;
        job.staging[0] = static_cast<std::byte>(pad);
        job.staged = 1;
        return {};
    case packet_mode::chacha20_poly1305: {
        const std::uint32_t seqn = st_.sequence_number;
        std::array<std::byte, 4> len_plain{};
        store_be32(len_plain, packet_length);
        std::array<std::byte, 16> iv{};
        make_chacha_iv(iv, /*counter=*/0, seqn);
        if (!st_.length_cipher.set_iv(iv)) return code::cipher_failure;
        if (!st_.length_cipher.update(len_plain, w.first(4))) {
            return code::cipher_failure;
        }
        make_chacha_iv(iv, /*counter=*/0, seqn);
        if (!st_.cipher.set_iv(iv)) return code::cipher_failure;
        std::array<std::byte, 64> zero_block{};
        std::array<std::byte, 64> poly_block{};
        if (!st_.cipher.update(zero_block, poly_block)) {
            return code::cipher_failure;
        }
        std::memcpy(job.poly_key.data(), poly_block.data(), job.poly_key.size());
        crypto::secure_zero(std::span<std::byte>{poly_block});
        make_chacha_iv(iv, /*counter=*/1, seqn);
        if (!st_.cipher.set_iv(iv)) return code::cipher_failure;
        job.staging[0] = static_cast<std::byte>(pad);
        job.staged = 1;
        return {};
    }
    }
    return code::invalid_state;
}

YANTERM_SSH_INLINE bool packet_writer::is_cbc() const noexcept {
    return st_.mode == packet_mode::cbc_encrypt_and_mac
        || st_.mode == packet_mode::cbc_encrypt_then_mac;
}

YANTERM_SSH_INLINE bool packet_writer::encrypts_length() const noexcept {
    return st_.mode == packet_mode::ctr_encrypt_and_mac
        || st_.mode == packet_mode::cbc_encrypt_and_mac;
}

YANTERM_SSH_INLINE void packet_writer::stage_bytes(stream_job& job, std::span<const std::byte> src) noexcept {
    copy_in(std::span<std::byte>{job.staging}.subspan(job.staged, src.size()), src);
    job.staged += src.size();
}

YANTERM_SSH_INLINE std::error_code packet_writer::crypt_chunk(std::span<const std::byte> in,
                                                             std::span<std::byte> out) {
    if (out.size() < in.size()) return code::cipher_failure;
    out = out.first(in.size());
    switch (st_.mode) {
    case packet_mode::plaintext:
        copy_in(out, in);
        return {};
    case packet_mode::cbc_encrypt_and_mac:
    case packet_mode::ctr_encrypt_and_mac:
        st_.mac.update(in);
        if (!st_.cipher.update(in, out)) return code::cipher_failure;
        return {};
    case packet_mode::cbc_encrypt_then_mac:
    case packet_mode::ctr_encrypt_then_mac:
        if (!st_.cipher.update(in, out)) return code::cipher_failure;
        st_.mac.update(out);
        return {};
    case packet_mode::gcm:
        if (!st_.aead.update(in, out)) return code::aead_failure;
        return {};
    case packet_mode::chacha20_poly1305:
        if (!st_.cipher.update(in, out)) return code::cipher_failure;
        return {};
    }
    return code::invalid_state;
}

YANTERM_SSH_INLINE std::error_code packet_writer::emit_cipher(stream_job& job,
                                                             std::span<const std::byte> plain) {
    if (plain.empty()) return {};
    const std::size_t start = encrypts_length() ? 0u : 4u;
    const std::size_t enc_end = 4u + static_cast<std::size_t>(job.packet_length);
    const std::size_t off = start + job.cipher_out;
    if (off + plain.size() > enc_end) return code::cipher_failure;
    if (auto ec = crypt_chunk(plain, job.wire.subspan(off, plain.size())); ec) return ec;
    job.cipher_out += plain.size();
    return {};
}

YANTERM_SSH_INLINE std::error_code packet_writer::flush_staging(stream_job& job) {
    if (job.staged == 0) return {};
    if (is_cbc()) {
        const std::size_t block = st_.block_size;
        if (block == 0 || job.staged % block != 0) return code::cipher_failure;
    }
    const std::size_t n = job.staged;
    if (auto ec = emit_cipher(job, std::span<const std::byte>{job.staging.data(), n}); ec) {
        return ec;
    }
    crypto::secure_zero(std::span<std::byte>{job.staging}.first(n));
    job.staged = 0;
    return {};
}

YANTERM_SSH_INLINE std::error_code packet_writer::flush_complete_blocks(stream_job& job) {
    if (!is_cbc()) return flush_staging(job);
    const std::size_t block = st_.block_size;
    if (block == 0) return code::cipher_failure;
    const std::size_t aligned = job.staged - (job.staged % block);
    if (aligned == 0) return {};
    if (auto ec = emit_cipher(job, std::span<const std::byte>{job.staging.data(), aligned}); ec) {
        return ec;
    }
    const std::size_t tail = job.staged - aligned;
    if (tail != 0) {
        std::memmove(job.staging.data(), job.staging.data() + aligned, tail);
    }
    crypto::secure_zero(std::span<std::byte>{job.staging}.subspan(tail, aligned));
    job.staged = tail;
    return {};
}

YANTERM_SSH_INLINE std::error_code packet_writer::spill_for_frag(stream_job& job,
                                                                std::span<const std::byte>& frag) {
    const std::size_t cap = job.staging.size();
    const bool cbc = is_cbc();
    const std::size_t block = st_.block_size;
    if (cbc && (block == 0 || cap % block != 0)) return code::cipher_failure;

    if (cbc) {
        const std::size_t rem = job.staged % block;
        if (rem != 0) {
            const std::size_t need = block - rem;
            const std::size_t n = (std::min)(need, frag.size());
            stage_bytes(job, frag.first(n));
            job.filled += n;
            frag = frag.subspan(n);
            if (n < need) return {};
        }
    }

    std::size_t take = (std::min)(cap - job.staged, frag.size());
    if (cbc) take = (take / block) * block;
    if (take != 0) {
        stage_bytes(job, frag.first(take));
        job.filled += take;
        frag = frag.subspan(take);
    }

    if (auto ec = flush_staging(job); ec) return ec;

    if (frag.size() >= cap) {
        std::size_t n = frag.size();
        if (cbc) n = (n / block) * block;
        if (n != 0) {
            if (auto ec = emit_cipher(job, frag.first(n)); ec) return ec;
            job.filled += n;
            frag = frag.subspan(n);
        }
    }
    return {};
}

YANTERM_SSH_INLINE void packet_writer::append_payload(stream_job& job, std::span<const std::byte> frag) {
    if (job.ec) return;
    if (frag.size() > job.payload_size - job.filled) {
        job.ec = code::invalid_state;
        return;
    }
    if (frag.empty()) return;
    if (st_.mode == packet_mode::plaintext) {
        copy_in(job.wire.subspan(5 + job.filled, frag.size()), frag);
        job.filled += frag.size();
        return;
    }
    while (!frag.empty()) {
        if (job.staged + frag.size() <= job.staging.size()) {
            stage_bytes(job, frag);
            job.filled += frag.size();
            return;
        }
        if (auto ec = spill_for_frag(job, frag); ec) {
            job.ec = ec;
            return;
        }
    }
}

YANTERM_SSH_INLINE std::error_code packet_writer::finish_packet(stream_job& job, memory::detail::page_slice& out) {
    auto w = job.wire;
    auto tail = w.subspan(4 + static_cast<std::size_t>(job.packet_length), mode_tail());

    if (st_.mode != packet_mode::plaintext) {
        if (auto ec = flush_complete_blocks(job); ec) return ec;
        if (job.pad != 0) {
            if (job.staged + job.pad > job.staging.size()) return code::cipher_failure;
            if (auto ec = p_.random_bytes(std::span<std::byte>{job.staging}.subspan(job.staged, job.pad));
                ec) {
                return ec;
            }
            job.staged += job.pad;
        }
        if (auto ec = flush_staging(job); ec) return ec;
        const std::size_t want = encrypts_length() ? 4u + static_cast<std::size_t>(job.packet_length)
                                                   : static_cast<std::size_t>(job.packet_length);
        if (job.cipher_out != want) return code::cipher_failure;
    }

    switch (st_.mode) {
    case packet_mode::plaintext:
        break;
    case packet_mode::cbc_encrypt_and_mac:
    case packet_mode::ctr_encrypt_and_mac:
    case packet_mode::cbc_encrypt_then_mac:
    case packet_mode::ctr_encrypt_then_mac:
        if (!st_.mac.final_into(tail)) return code::hash_failure;
        break;
    case packet_mode::gcm:
        if (!st_.aead.final(tail)) return code::crypto_backend_failure;
        bump_gcm_iv(st_.iv);
        break;
    case packet_mode::chacha20_poly1305:
        if (!p_.poly1305(job.poly_key, w.first(4 + static_cast<std::size_t>(job.packet_length)),
                         tail)) {
            return code::mac_failure;
        }
        break;
    default:
        return code::invalid_state;
    }

    ++st_.sequence_number;
    out = std::move(job.slice);
    return {};
}

YANTERM_SSH_INLINE void packet_reader::install(direction_state st) {
    st_ = std::move(st);
    eam_prefix_ready_ = false;
    unusable_ = false;
    eam_plain_.clear();
}

YANTERM_SSH_INLINE std::error_code packet_reader::read(std::span<const std::byte> in, std::size_t& accepted, memory::detail::page_pool& pool,
                         memory::detail::page_slice& payload) {
    accepted = 0;
    payload.reset();
    if (unusable_) return code::invalid_state;

    std::error_code result{};
    switch (st_.mode) {
    case packet_mode::plaintext:
        result = complete_clear_length(in, accepted, pool, payload, /*encrypted_body=*/false);
        break;
    case packet_mode::cbc_encrypt_then_mac:
    case packet_mode::ctr_encrypt_then_mac:
        result = complete_clear_length(in, accepted, pool, payload, /*encrypted_body=*/true);
        break;
    case packet_mode::cbc_encrypt_and_mac:
    case packet_mode::ctr_encrypt_and_mac:
        result = complete_eam(in, accepted, pool, payload);
        break;
    case packet_mode::gcm:
        result = complete_gcm(in, accepted, pool, payload);
        break;
    case packet_mode::chacha20_poly1305:
        result = complete_chacha(in, accepted, pool, payload);
        break;
    default:
        result = code::invalid_state;
        break;
    }

    if (result == packet_read_need_more()) {
        payload.reset();
        return {};
    }
    if (result) {
        payload.reset();
        return result;
    }
    return {};
}

YANTERM_SSH_INLINE void packet_reader::copy_out(std::span<std::byte> dst, std::span<const std::byte> src) noexcept {
    if (!src.empty()) std::memcpy(dst.data(), src.data(), src.size());
}

YANTERM_SSH_INLINE std::error_code packet_reader::make_payload(memory::detail::page_slice& plain, std::size_t body_offset,
                             std::uint32_t packet_length, memory::detail::page_slice& payload) {
    const auto bytes = plain.bytes();
    const auto padding_length = std::to_integer<std::uint8_t>(bytes[body_offset]);
    if (const auto e = check_padding(padding_length, packet_length); e) {
        return e;
    }
    const std::size_t payload_len =
        static_cast<std::size_t>(packet_length) - 1u - padding_length;
    payload = plain.subslice(body_offset + 1u, payload_len);
    return {};
}

YANTERM_SSH_INLINE std::error_code packet_reader::complete_clear_length(std::span<const std::byte> in, std::size_t& accepted,
                               memory::detail::page_pool& pool, memory::detail::page_slice& payload, bool encrypted_body) {
    if (in.size() < 4) return packet_read_need_more();
    const std::uint32_t packet_length = load_be32(in);
    if (const auto e = check_packet_length(packet_length); e) return e;

    const std::size_t block = align_block(st_.block_size);
    if (encrypted_body) {
        if (packet_length % block != 0) return code::invalid_packet_length;
    } else {
        if ((packet_length + 4u) % block != 0) return code::invalid_packet_length;
    }

    const std::size_t wire_size = 4u + packet_length + st_.mac_length;
    if (in.size() < wire_size) return packet_read_need_more();

    const auto len_bytes = in.first(4);
    const auto body = in.subspan(4, packet_length);
    const auto mac_wire = in.subspan(4 + packet_length, st_.mac_length);

    if (encrypted_body) {
        if (!st_.mac || st_.mac_length == 0 || !st_.cipher) return code::invalid_state;
        // EtM: verify the MAC over the ciphertext before decrypting.
        std::array<std::byte, 4> seq{};
        store_be32(seq, st_.sequence_number);
        std::array<std::byte, 64> expect{};
        st_.mac.update(seq);
        st_.mac.update(len_bytes);
        st_.mac.update(body);
        if (!st_.mac.final_into(std::span{expect}.first(st_.mac_length))) {
            return code::hash_failure;
        }
        if (!p_.constant_time_eq(std::span<const std::byte>{expect}.first(st_.mac_length),
                                 mac_wire)) {
            return code::mac_mismatch;
        }
    }

    memory::detail::page_slice plain = pool.allocate(packet_length);
    if (plain.size() != packet_length) return code::invalid_state;
    auto w = plain.mutable_bytes();
    if (encrypted_body) {
        if (!st_.cipher.update(body, w)) {
            unusable_ = true;
            return code::cipher_failure;
        }
    } else {
        copy_out(w, body);
    }

    if (const auto e = make_payload(plain, 0, packet_length, payload); e) {
        if (encrypted_body) unusable_ = true;
        return e;
    }
    accepted += wire_size;
    ++st_.sequence_number;
    return {};
}

YANTERM_SSH_INLINE std::error_code packet_reader::complete_eam(std::span<const std::byte> in, std::size_t& accepted, memory::detail::page_pool& pool,
                      memory::detail::page_slice& payload) {
    if (!st_.cipher || !st_.mac || st_.mac_length == 0) return code::invalid_state;
    const std::size_t block = align_block(st_.block_size);

    if (!eam_prefix_ready_) {
        if (in.size() < block) return packet_read_need_more();
        eam_plain_.assign(block, std::byte{0});
        if (!st_.cipher.update(in.first(block), eam_plain_)) {
            unusable_ = true;
            return code::cipher_failure;
        }
        // Cipher has advanced: this block is consumed whether or not the length
        // is legal. On failure mark the reader unusable until install().
        accepted += block;
        const std::uint32_t candidate = load_be32(eam_plain_);
        if (const auto e = check_packet_length(candidate); e) {
            eam_plain_.clear();
            unusable_ = true;
            return e;
        }
        if ((candidate + 4u) % block != 0) {
            eam_plain_.clear();
            unusable_ = true;
            return code::invalid_packet_length;
        }
        eam_prefix_ready_ = true;
        in = in.subspan(block);
    }

    const std::uint32_t packet_length = load_be32(eam_plain_);
    const std::size_t plain_size = 4u + packet_length;
    const std::size_t rest_cipher = plain_size - block;
    if (in.size() < rest_cipher + st_.mac_length) return packet_read_need_more();

    memory::detail::page_slice plain = pool.allocate(plain_size);
    if (plain.size() != plain_size) return code::invalid_state;
    auto w = plain.mutable_bytes();
    copy_out(w.first(block), eam_plain_);
    if (rest_cipher > 0) {
        if (!st_.cipher.update(in.first(rest_cipher), w.subspan(block))) {
            unusable_ = true;
            return code::cipher_failure;
        }
    }

    std::array<std::byte, 4> seq{};
    store_be32(seq, st_.sequence_number);
    std::array<std::byte, 64> expect{};
    st_.mac.update(seq);
    st_.mac.update(w);
    if (!st_.mac.final_into(std::span{expect}.first(st_.mac_length))) {
        unusable_ = true;
        return code::hash_failure;
    }
    if (!p_.constant_time_eq(std::span<const std::byte>{expect}.first(st_.mac_length),
                             in.subspan(rest_cipher, st_.mac_length))) {
        unusable_ = true;
        return code::mac_mismatch;
    }

    if (const auto e = make_payload(plain, 4, packet_length, payload); e) {
        unusable_ = true;
        return e;
    }
    accepted += rest_cipher + st_.mac_length;
    eam_prefix_ready_ = false;
    eam_plain_.clear();
    ++st_.sequence_number;
    return {};
}

YANTERM_SSH_INLINE std::error_code packet_reader::complete_gcm(std::span<const std::byte> in, std::size_t& accepted, memory::detail::page_pool& pool,
                      memory::detail::page_slice& payload) {
    if (!st_.aead) return code::invalid_state;
    if (in.size() < 4) return packet_read_need_more();

    const std::uint32_t packet_length = load_be32(in);
    if (const auto e = check_packet_length(packet_length); e) return e;
    if (packet_length % 16u != 0) return code::invalid_packet_length;

    constexpr std::size_t tag_len = 16;
    const std::size_t wire_size = 4u + packet_length + tag_len;
    if (in.size() < wire_size) return packet_read_need_more();

    memory::detail::page_slice plain = pool.allocate(packet_length);
    if (plain.size() != packet_length) return code::invalid_state;
    auto pt = plain.mutable_bytes();
    std::array<std::byte, 16> tag{};
    const auto tag_wire = in.subspan(4 + packet_length, tag_len);
    std::memcpy(tag.data(), tag_wire.data(), tag.size());
    if (!st_.aead.begin(st_.iv, in.first(4))) {
        crypto::secure_zero(pt);
        return code::aead_failure;
    }
    if (!st_.aead.update(in.subspan(4, packet_length), pt)) {
        crypto::secure_zero(pt);
        return code::aead_failure;
    }
    if (!st_.aead.final(tag)) {
        crypto::secure_zero(pt);
        return code::decrypt_failure;
    }

    if (const auto e = make_payload(plain, 0, packet_length, payload); e) return e;
    accepted += wire_size;
    bump_gcm_iv(st_.iv);
    ++st_.sequence_number;
    return {};
}

YANTERM_SSH_INLINE std::error_code packet_reader::complete_chacha(std::span<const std::byte> in, std::size_t& accepted, memory::detail::page_pool& pool,
                         memory::detail::page_slice& payload) {
    if (!st_.cipher || !st_.length_cipher) return code::invalid_state;
    if (in.size() < 4) return packet_read_need_more();

    const std::uint32_t seq = st_.sequence_number;
    std::array<std::byte, 16> iv{};
    // Deterministic in the sequence number, so decrypting the length twice
    // (across two feed calls) yields the same result.
    make_chacha_iv(iv, /*counter=*/0, seq);
    if (!st_.length_cipher.set_iv(iv)) return code::cipher_failure;
    std::array<std::byte, 4> len_plain{};
    if (!st_.length_cipher.update(in.first(4), len_plain)) {
        return code::cipher_failure;
    }

    const std::uint32_t packet_length = load_be32(len_plain);
    if (const auto e = check_packet_length(packet_length); e) return e;
    if (packet_length % 8u != 0) return code::invalid_packet_length;

    constexpr std::size_t tag_len = 16;
    const std::size_t wire_size = 4u + packet_length + tag_len;
    if (in.size() < wire_size) return packet_read_need_more();

    make_chacha_iv(iv, /*counter=*/0, seq);
    if (!st_.cipher.set_iv(iv)) return code::cipher_failure;
    std::array<std::byte, 64> zero_block{};
    std::array<std::byte, 64> poly_block{};
    if (!st_.cipher.update(zero_block, poly_block)) {
        return code::cipher_failure;
    }
    const auto poly_key = std::span<const std::byte>{poly_block}.first(32);

    std::array<std::byte, 16> expect{};
    if (!p_.poly1305(poly_key, in.first(4u + packet_length), expect)) {
        return code::mac_failure;
    }
    if (!p_.constant_time_eq(expect, in.subspan(4u + packet_length, tag_len))) {
        return code::mac_mismatch;
    }

    make_chacha_iv(iv, /*counter=*/1, seq);
    if (!st_.cipher.set_iv(iv)) return code::cipher_failure;
    memory::detail::page_slice plain = pool.allocate(packet_length);
    if (plain.size() != packet_length) return code::invalid_state;
    if (!st_.cipher.update(in.subspan(4, packet_length), plain.mutable_bytes())) {
        return code::cipher_failure;
    }

    if (const auto e = make_payload(plain, 0, packet_length, payload); e) return e;
    accepted += wire_size;
    ++st_.sequence_number;
    return {};
}

}  // namespace yanterm::ssh::core::detail
