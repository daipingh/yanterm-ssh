#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/detail/error.hpp>
#include <yanterm-ssh/detail/intrusive_list.hpp>
#include <yanterm-ssh/channel.hpp>
#include <yanterm-ssh/session.hpp>
#include <yanterm-ssh/sftp/packets.hpp>

#include <corral/Event.h>
#include <corral/Nursery.h>
#include <corral/ParkingLot.h>
#include <corral/Semaphore.h>
#include <corral/utility.h>
#include <corral/wait.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

namespace yanterm::ssh {

struct sftp_options {
    std::uint32_t max_packet_length = sftp::default_max_packet_length;
    std::uint32_t max_inflight = 64;
    bool query_limits = true;
};

// Handle bytes only. Destruction does not send SSH_FXP_CLOSE.
class sftp_handle {
public:
    sftp_handle() = default;

    [[nodiscard]] bool empty() const noexcept { return bytes_.empty(); }
    void clear() noexcept { bytes_.clear(); }

private:
    template <class Stream>
    friend class basic_sftp_client;

    explicit sftp_handle(std::span<const std::byte> bytes)
        : bytes_(bytes.begin(), bytes.end()) {}

    [[nodiscard]] std::span<const std::byte> bytes() const noexcept { return bytes_; }

    std::vector<std::byte> bytes_;
};

namespace sftp {

struct id_name_lists {
    std::vector<std::string> users;
    std::vector<std::string> groups;
};

}  // namespace sftp

template <class Stream>
class basic_sftp_client {
    static_assert(auv::detail::stream_like<Stream>);

public:
    explicit basic_sftp_client(Stream stream, sftp_options opts = {})
        : stream_(std::move(stream)), opts_(opts) {
        limits_.max_packet_length = opts_.max_packet_length;
        limits_.max_read_length = sftp::fallback_io_length;
        limits_.max_write_length = sftp::fallback_io_length;
    }

    basic_sftp_client(const basic_sftp_client&) = delete;
    basic_sftp_client& operator=(const basic_sftp_client&) = delete;
    basic_sftp_client(basic_sftp_client&&) = delete;
    basic_sftp_client& operator=(basic_sftp_client&&) = delete;

    corral::Task<std::error_code> start();

    [[nodiscard]] bool supports(sftp::extension ext) const noexcept { return extensions_.contains(ext); }
    [[nodiscard]] const sftp::limits_info& limits() const noexcept { return limits_; }

    corral::Task<sftp::result<sftp_handle>> open(std::string_view path, std::uint32_t flags,
                                                 const sftp::attrs& attributes = {});
    corral::Task<sftp::result<std::size_t>> read(const sftp_handle& handle, std::uint64_t offset,
                                                 std::span<std::byte> dst);
    corral::Task<sftp::result<>> write(const sftp_handle& handle, std::uint64_t offset,
                                       std::span<const std::byte> src);
    corral::Task<sftp::result<>> close(sftp_handle& handle);

    corral::Task<sftp::result<sftp::attrs>> stat(std::string_view path);
    corral::Task<sftp::result<sftp::attrs>> lstat(std::string_view path);
    corral::Task<sftp::result<sftp::attrs>> fstat(const sftp_handle& handle);
    corral::Task<sftp::result<>> setstat(std::string_view path, const sftp::attrs& attributes);
    corral::Task<sftp::result<>> fsetstat(const sftp_handle& handle, const sftp::attrs& attributes);

    corral::Task<sftp::result<sftp_handle>> opendir(std::string_view path);
    corral::Task<sftp::result<std::vector<sftp::name_entry>>> readdir(const sftp_handle& handle);
    corral::Task<sftp::result<std::vector<sftp::name_entry>>> read_dir(std::string_view path);

    corral::Task<sftp::result<>> remove(std::string_view path);
    corral::Task<sftp::result<>> mkdir(std::string_view path, const sftp::attrs& attributes = {});
    corral::Task<sftp::result<>> rmdir(std::string_view path);
    corral::Task<sftp::result<std::vector<sftp::name_entry>>> realpath(std::string_view path);
    corral::Task<sftp::result<>> rename(std::string_view oldpath, std::string_view newpath);
    corral::Task<sftp::result<std::vector<sftp::name_entry>>> readlink(std::string_view path);
    corral::Task<sftp::result<>> symlink(std::string_view target, std::string_view linkpath);

    corral::Task<sftp::result<std::size_t>> read_all(const sftp_handle& handle, std::uint64_t offset,
                                                     std::span<std::byte> dst);
    corral::Task<sftp::result<>> write_all(const sftp_handle& handle, std::uint64_t offset,
                                           std::span<const std::byte> src);

    corral::Task<sftp::result<>> posix_rename(std::string_view oldpath, std::string_view newpath);
    corral::Task<sftp::result<sftp::statvfs_info>> statvfs(std::string_view path);
    corral::Task<sftp::result<sftp::statvfs_info>> fstatvfs(const sftp_handle& handle);
    corral::Task<sftp::result<>> hardlink(std::string_view oldpath, std::string_view newpath);
    corral::Task<sftp::result<>> fsync(const sftp_handle& handle);
    corral::Task<sftp::result<>> lsetstat(std::string_view path, const sftp::attrs& attributes);
    corral::Task<sftp::result<sftp::limits_info>> query_limits();
    corral::Task<sftp::result<std::vector<sftp::name_entry>>> expand_path(std::string_view path);
    corral::Task<sftp::result<>> copy_data(const sftp_handle& src, std::uint64_t src_offset,
                                           std::uint64_t length, const sftp_handle& dst,
                                           std::uint64_t dst_offset);
    corral::Task<sftp::result<std::string>> home_directory(std::string_view user = {});
    corral::Task<sftp::result<sftp::id_name_lists>>
    users_groups_by_id(std::span<const std::uint32_t> uids, std::span<const std::uint32_t> gids);

private:
    static constexpr bool drains_stderr = std::is_same_v<Stream, channel>;
    // DATA reply: type, id, data length.
    static constexpr std::uint32_t data_reply_overhead = 9;
    // WRITE request: type, id, handle length, offset, data length.
    static constexpr std::uint32_t write_request_overhead = 21;

    struct waiter : detail::intrusive_list_item<waiter> {
        std::uint32_t id = 0;
        bool done = false;
        std::error_code ec;
        sftp::msg type{};
        std::vector<std::byte> payload;
        corral::ParkingLot lot;
    };

    // Chunks past `stop` are not issued; the lowest stop offset wins.
    struct pipeline_outcome {
        std::size_t stop = 0;
        std::error_code ec;
        std::string message;

        void halt(std::size_t at, std::error_code e, std::string m) {
            if (at >= stop) return;
            stop = at;
            ec = e;
            message = std::move(m);
        }
    };

    struct raw_reply {
        std::error_code ec;
        sftp::msg type{};
        std::vector<std::byte> payload;
    };

    struct chunk_read {
        std::error_code ec;
        std::size_t n = 0;
    };

    [[nodiscard]] std::error_code gate() const {
        if (failed_) return failed_;
        if (!started_) return make_error_code(code::invalid_state);
        return {};
    }

    [[nodiscard]] std::error_code gate(sftp::extension ext) const {
        if (auto ec = gate()) return ec;
        if (!supports(ext)) return sftp::make_error_code(sftp::status_code::op_unsupported);
        return {};
    }

    template <class T>
    sftp::result<T> failed_result(std::error_code ec) const {
        return {ec, {}, {}};
    }

    [[nodiscard]] std::uint32_t alloc_id() {
        for (;;) {
            const auto id = next_id_++;
            bool used = false;
            for (const auto& w : waiters_) {
                if (w.id == id) used = true;
            }
            if (!used) return id;
        }
    }

    [[nodiscard]] std::uint32_t read_limit() const {
        const std::uint64_t max_read = limits_.max_read_length == 0
            ? sftp::fallback_io_length
            : limits_.max_read_length;
        const std::uint64_t cap = opts_.max_packet_length > data_reply_overhead
            ? static_cast<std::uint64_t>(opts_.max_packet_length) - data_reply_overhead
            : 1;
        std::uint64_t n = std::min(max_read, cap);
        if (n == 0) n = 1;
        if (n > 0xffffffffu) n = 0xffffffffu;
        return static_cast<std::uint32_t>(n);
    }

    // Outbound frame bound: ours, narrowed by the peer's limits@openssh.com
    // max-packet-length when it reported one.
    [[nodiscard]] std::uint32_t frame_limit() const {
        std::uint64_t cap = opts_.max_packet_length;
        if (limits_.max_packet_length != 0) cap = std::min(cap, limits_.max_packet_length);
        return static_cast<std::uint32_t>(cap);
    }

    [[nodiscard]] std::uint32_t write_limit(const sftp_handle& handle) const {
        const std::uint64_t overhead = write_request_overhead + handle.bytes().size();
        const std::uint64_t cap = frame_limit();
        if (cap <= overhead) return 0;
        const std::uint64_t max_write = limits_.max_write_length == 0 ? sftp::fallback_io_length
                                                                      : limits_.max_write_length;
        return static_cast<std::uint32_t>(std::min(max_write, cap - overhead));
    }

    [[nodiscard]] std::uint32_t inflight_limit() const {
        return opts_.max_inflight == 0 ? 1u : opts_.max_inflight;
    }

    // Every pending linked waiter other than reader_ is parked in drive(), so
    // the first one found can always take over.
    void release_reader(const waiter& w) {
        if (reader_ != &w) return;
        reader_ = nullptr;
        if (failed_) return;
        for (auto& next : waiters_) {
            if (&next != &w && !next.done) {
                next.lot.unparkOne();
                return;
            }
        }
    }

    void fail(std::error_code ec) {
        if (!ec) return;
        if (!failed_) failed_ = ec;
        for (auto& w : waiters_) {
            if (!w.done) {
                w.ec = failed_;
                w.done = true;
                w.lot.unparkOne();
            }
        }
        failed_ev_.trigger();
        write_lot_.unparkAll();
    }

    void reset_frame() noexcept {
        frame_ready_ = false;
        length_known_ = false;
        hdr_got_ = 0;
        body_got_ = 0;
    }

    std::error_code accept_read(std::error_code ec, std::size_t n) {
        if (!ec && n > 0) return {};
        if (!ec) ec = auv::make_error_code(auv::errc::eof);
        if (ec == auv::make_error_code(auv::errc::eof)) ec = make_error_code(code::session_closed);
        fail(ec);
        return failed_;
    }

    corral::Task<chunk_read> read_some(std::span<std::byte> dst);
    corral::Task<std::error_code> read_piece();
    corral::Task<std::error_code> lock_write();
    void unlock_write() {
        write_busy_ = false;
        write_lot_.unparkOne();
    }
    corral::Task<std::error_code> write_bytes(std::span<const std::byte> payload,
                                              std::span<const std::byte> extra);
    corral::Task<void> send(std::span<const std::byte> payload, std::span<const std::byte> extra);
    corral::Task<void> drive(waiter& w);
    void dispatch_frame();
    corral::Task<raw_reply> exchange(std::uint32_t id, std::span<const std::byte> payload,
                                     std::span<const std::byte> extra = {});

    template <class Fn>
    corral::Task<void> pipeline(std::size_t total, std::size_t chunk, pipeline_outcome& out, Fn fn) {
        corral::Semaphore slots(inflight_limit());
        CORRAL_WITH_NURSERY(n) {
            for (std::size_t off = 0; off < total && off < out.stop; off += chunk) {
                auto slot = co_await slots.lock();
                if (off >= out.stop) break;
                const auto len = std::min(chunk, total - off);
                n.start([&fn, off, len, slot = std::move(slot)]() -> corral::Task<void> {
                    co_await fn(off, len);
                });
            }
            co_return corral::join;
        };
    }

    sftp::result<> finish_status(const raw_reply& raw, bool eof_is_error = true) const;
    sftp::result<sftp_handle> finish_handle(const raw_reply& raw) const;
    sftp::result<sftp::attrs> finish_attrs(const raw_reply& raw) const;
    sftp::result<std::vector<sftp::name_entry>> finish_names(const raw_reply& raw,
                                                             bool eof_is_empty) const;
    sftp::result<sftp::statvfs_info> finish_statvfs(const raw_reply& raw) const;

    corral::Task<sftp::result<>> status_path(sftp::msg type, std::string_view path);
    corral::Task<sftp::result<sftp::attrs>> attrs_path(sftp::msg type, std::string_view path);

    Stream stream_;
    sftp_options opts_{};
    sftp::limits_info limits_{};
    sftp::extension_set extensions_{};
    bool started_ = false;
    bool stderr_open_ = drains_stderr;
    std::error_code failed_{};
    corral::Event failed_ev_;
    std::uint32_t next_id_ = 1;
    bool write_busy_ = false;
    corral::ParkingLot write_lot_;
    detail::intrusive_list<waiter> waiters_;
    waiter* reader_ = nullptr;
    std::byte hdr_[4]{};
    std::size_t hdr_got_ = 0;
    bool length_known_ = false;
    std::uint32_t body_need_ = 0;
    std::vector<std::byte> body_;
    std::size_t body_got_ = 0;
    bool frame_ready_ = false;
};

template <class Stream>
corral::Task<typename basic_sftp_client<Stream>::chunk_read>
basic_sftp_client<Stream>::read_some(std::span<std::byte> dst) {
    chunk_read out;
    if (dst.empty()) co_return out;
    if constexpr (drains_stderr) {
        if (stderr_open_) {
            std::byte junk[256];
            auv::buffer stdout_buf{reinterpret_cast<char*>(dst.data()), dst.size()};
            auv::buffer stderr_buf{reinterpret_cast<char*>(junk), sizeof junk};
            // Cancellable: a read that already copied bytes still completes,
            // so the caller can commit hdr_/body_ before the next cancel point.
            auto [stdout_read, stderr_read, failed] = co_await corral::anyOf(
                stream_.read([](void* p) { return *static_cast<auv::buffer*>(p); }, &stdout_buf),
                stream_.read_stderr([](void* p) { return *static_cast<auv::buffer*>(p); },
                                    &stderr_buf),
                failed_ev_);
            if (stdout_read) {
                auto [ec, n] = *stdout_read;
                out.n = n;
                out.ec = accept_read(ec, n);
                co_return out;
            }
            if (stderr_read) {
                auto [ec, n] = *stderr_read;
                (void)n;
                if (ec == auv::make_error_code(auv::errc::eof)) stderr_open_ = false;
                else if (ec) out.ec = accept_read(ec, 0);
            }
            if (failed) out.ec = failed_;
            co_return out;
        }
    }
    auv::buffer buf{reinterpret_cast<char*>(dst.data()), dst.size()};
    auto [got, failed] = co_await corral::anyOf(
        stream_.read([](void* p) { return *static_cast<auv::buffer*>(p); }, &buf), failed_ev_);
    if (!got) {
        out.ec = failed_;
        co_return out;
    }
    auto [ec, n] = *got;
    out.n = n;
    out.ec = accept_read(ec, n);
    co_return out;
}

template <class Stream>
corral::Task<std::error_code> basic_sftp_client<Stream>::read_piece() {
    if (failed_) co_return failed_;
    if (!length_known_) {
        const auto got = co_await read_some(std::span<std::byte>(hdr_ + hdr_got_, 4 - hdr_got_));
        if (got.ec) co_return got.ec;
        hdr_got_ += got.n;
        if (hdr_got_ < 4) co_return {};
        const auto len = sftp::decode_frame_header(std::span<const std::byte>(hdr_, 4));
        if (len < 1 || len > opts_.max_packet_length) {
            const auto ec = make_error_code(code::invalid_packet_length);
            fail(ec);
            co_return failed_;
        }
        body_.resize(len);
        body_need_ = len;
        body_got_ = 0;
        length_known_ = true;
        co_return {};
    }
    const auto got = co_await read_some(
        std::span<std::byte>(body_.data() + body_got_, body_need_ - body_got_));
    if (got.ec) co_return got.ec;
    body_got_ += got.n;
    if (body_got_ == body_need_) frame_ready_ = true;
    co_return {};
}

template <class Stream>
corral::Task<std::error_code> basic_sftp_client<Stream>::lock_write() {
    while (write_busy_ && !failed_) co_await write_lot_.park();
    if (failed_) co_return failed_;
    write_busy_ = true;
    co_return {};
}

template <class Stream>
corral::Task<std::error_code> basic_sftp_client<Stream>::write_bytes(
    std::span<const std::byte> payload, std::span<const std::byte> extra) {
    const auto len = static_cast<std::uint32_t>(payload.size() + extra.size());
    std::byte hdr[4] = {
        static_cast<std::byte>(len >> 24),
        static_cast<std::byte>(len >> 16),
        static_cast<std::byte>(len >> 8),
        static_cast<std::byte>(len),
    };
    auv::buffer bufs[3] = {
        {reinterpret_cast<char*>(hdr), 4},
        {reinterpret_cast<const char*>(payload.data()), payload.size()},
        {reinterpret_cast<const char*>(extra.data()), extra.size()},
    };
    const std::size_t nbufs = extra.empty() ? 2 : 3;
    // A frame is never abandoned half-written while the client is healthy;
    // once it has failed the stream is dead and a blocked write may be dropped.
    auto [wrote, failed] = co_await corral::noncancellable(
        corral::anyOf(stream_.write(bufs, nbufs), failed_ev_));
    (void)failed;
    if (wrote && *wrote) fail(*wrote);
    co_return failed_;
}

template <class Stream>
corral::Task<void> basic_sftp_client<Stream>::send(std::span<const std::byte> payload,
                                                   std::span<const std::byte> extra) {
    (void)co_await write_bytes(payload, extra);
    unlock_write();
}

template <class Stream>
void basic_sftp_client<Stream>::dispatch_frame() {
    const auto payload = std::span<const std::byte>(body_.data(), body_need_);
    const auto type = sftp::packet_type(payload);
    if (type == sftp::msg::version || type == sftp::msg::init ||
        (static_cast<std::uint8_t>(type) >= 1 && static_cast<std::uint8_t>(type) <= 20) ||
        type == sftp::msg::extended) {
        fail(make_error_code(code::unexpected_message));
        return;
    }
    std::uint32_t id = 0;
    if (!sftp::packet_request_id(payload, id)) {
        fail(make_error_code(code::invalid_format));
        return;
    }
    switch (type) {
    case sftp::msg::status:
    case sftp::msg::handle:
    case sftp::msg::data:
    case sftp::msg::name:
    case sftp::msg::attrs:
    case sftp::msg::extended_reply:
        break;
    default:
        fail(make_error_code(code::unexpected_message));
        return;
    }
    for (auto& w : waiters_) {
        if (w.id != id || w.done) continue;
        w.type = type;
        w.payload.swap(body_);
        w.done = true;
        w.lot.unparkOne();
        return;
    }
}

template <class Stream>
corral::Task<void> basic_sftp_client<Stream>::drive(waiter& w) {
    struct reader_guard {
        basic_sftp_client& self;
        const waiter& w;
        ~reader_guard() { self.release_reader(w); }
    } guard{*this, w};
    while (!w.done) {
        if (failed_) {
            w.ec = failed_;
            w.done = true;
            break;
        }
        if (reader_ == nullptr) reader_ = &w;
        if (reader_ != &w) {
            co_await w.lot.park();
            continue;
        }
        if (!frame_ready_) {
            auto ec = co_await read_piece();
            if (ec && !w.done) {
                w.ec = failed_ ? failed_ : ec;
                w.done = true;
            }
            continue;
        }
        dispatch_frame();
        reset_frame();
    }
}

template <class Stream>
corral::Task<typename basic_sftp_client<Stream>::raw_reply>
basic_sftp_client<Stream>::exchange(std::uint32_t id, std::span<const std::byte> payload,
                                    std::span<const std::byte> extra) {
    raw_reply raw;
    if (auto ec = gate()) {
        raw.ec = ec;
        co_return raw;
    }
    const auto cap = frame_limit();
    if (payload.size() > cap || extra.size() > cap - payload.size()) {
        raw.ec = make_error_code(code::invalid_argument);
        co_return raw;
    }
    if (auto ec = co_await lock_write()) {
        raw.ec = ec;
        co_return raw;
    }
    // The waiter reads while its own frame is still being written: with no
    // other request in flight nobody else drains replies, and a peer stalled
    // on our receive window would never open its own.
    waiter w;
    w.id = id;
    waiters_.push_back(w);
    co_await corral::allOf(drive(w), send(payload, extra));
    raw.ec = w.ec;
    raw.type = w.type;
    raw.payload = std::move(w.payload);
    co_return raw;
}

template <class Stream>
sftp::result<> basic_sftp_client<Stream>::finish_status(const raw_reply& raw,
                                                        bool eof_is_error) const {
    sftp::result<> out;
    if (raw.ec) {
        out.ec = raw.ec;
        return out;
    }
    if (raw.type != sftp::msg::status) {
        out.ec = make_error_code(code::unexpected_message);
        return out;
    }
    sftp::status_reply st;
    if (!sftp::decode_status(raw.payload, st)) {
        out.ec = make_error_code(code::invalid_format);
        return out;
    }
    if (st.code == sftp::status_code::ok) return out;
    if (!eof_is_error && st.code == sftp::status_code::eof) return out;
    out.ec = sftp::make_error_code(st.code);
    out.message.assign(st.message.begin(), st.message.end());
    return out;
}

template <class Stream>
sftp::result<sftp_handle> basic_sftp_client<Stream>::finish_handle(const raw_reply& raw) const {
    if (raw.ec || raw.type == sftp::msg::status) {
        auto st = finish_status(raw);
        if (!st.ec) return failed_result<sftp_handle>(make_error_code(code::unexpected_message));
        return {st.ec, std::move(st.message), {}};
    }
    if (raw.type != sftp::msg::handle) {
        return failed_result<sftp_handle>(make_error_code(code::unexpected_message));
    }
    sftp::handle_reply h;
    if (!sftp::decode_handle(raw.payload, h)) {
        return failed_result<sftp_handle>(make_error_code(code::invalid_format));
    }
    return {{}, {}, sftp_handle{h.handle}};
}

template <class Stream>
sftp::result<sftp::attrs> basic_sftp_client<Stream>::finish_attrs(const raw_reply& raw) const {
    if (raw.ec || raw.type == sftp::msg::status) {
        auto st = finish_status(raw);
        if (!st.ec) return failed_result<sftp::attrs>(make_error_code(code::unexpected_message));
        return {st.ec, std::move(st.message), {}};
    }
    if (raw.type != sftp::msg::attrs) {
        return failed_result<sftp::attrs>(make_error_code(code::unexpected_message));
    }
    sftp::attrs_reply a;
    if (!sftp::decode_attrs_reply(raw.payload, a)) {
        return failed_result<sftp::attrs>(make_error_code(code::invalid_format));
    }
    return {{}, {}, a.attributes};
}

template <class Stream>
sftp::result<std::vector<sftp::name_entry>>
basic_sftp_client<Stream>::finish_names(const raw_reply& raw, bool eof_is_empty) const {
    if (raw.ec) return {raw.ec, {}, {}};
    if (raw.type == sftp::msg::status) {
        sftp::status_reply st;
        if (!sftp::decode_status(raw.payload, st)) {
            return failed_result<std::vector<sftp::name_entry>>(make_error_code(code::invalid_format));
        }
        if (eof_is_empty && st.code == sftp::status_code::eof) return {{}, {}, {}};
        if (st.code == sftp::status_code::ok) {
            return failed_result<std::vector<sftp::name_entry>>(make_error_code(code::unexpected_message));
        }
        return {sftp::make_error_code(st.code), std::string(st.message), {}};
    }
    if (raw.type != sftp::msg::name) {
        return failed_result<std::vector<sftp::name_entry>>(make_error_code(code::unexpected_message));
    }
    sftp::name_reply_view view;
    if (!sftp::decode_name(raw.payload, view)) {
        return failed_result<std::vector<sftp::name_entry>>(make_error_code(code::invalid_format));
    }
    std::vector<sftp::name_entry> names;
    names.reserve(view.entries.size());
    for (const auto& e : view.entries) {
        names.push_back(sftp::name_entry{
            std::string(e.filename), std::string(e.longname), e.attributes});
    }
    return {{}, {}, std::move(names)};
}

template <class Stream>
sftp::result<sftp::statvfs_info> basic_sftp_client<Stream>::finish_statvfs(const raw_reply& raw) const {
    if (raw.ec || raw.type == sftp::msg::status) {
        auto st = finish_status(raw);
        if (!st.ec) return failed_result<sftp::statvfs_info>(make_error_code(code::unexpected_message));
        return {st.ec, std::move(st.message), {}};
    }
    if (raw.type != sftp::msg::extended_reply) {
        return failed_result<sftp::statvfs_info>(make_error_code(code::unexpected_message));
    }
    sftp::statvfs_info info;
    std::uint32_t id = 0;
    if (!sftp::decode_statvfs_reply(raw.payload, id, info)) {
        return failed_result<sftp::statvfs_info>(make_error_code(code::invalid_format));
    }
    (void)id;
    return {{}, {}, info};
}

template <class Stream>
corral::Task<std::error_code> basic_sftp_client<Stream>::start() {
    if (started_ || failed_) co_return make_error_code(code::invalid_state);
    struct guard {
        basic_sftp_client& self;
        ~guard() {
            if (!self.started_ && !self.failed_) self.fail(make_error_code(code::invalid_state));
        }
    } cancel_guard{*this};
    wire::writer hello;
    sftp::encode_init(hello);
    if (auto ec = co_await lock_write()) co_return ec;
    auto wec = co_await write_bytes(hello.data(), {});
    unlock_write();
    if (wec) co_return failed_ ? failed_ : wec;

    while (!frame_ready_) {
        if (auto ec = co_await read_piece()) co_return ec;
    }
    const auto payload = std::span<const std::byte>(body_.data(), body_need_);
    sftp::version_reply version;
    if (sftp::packet_type(payload) != sftp::msg::version || !sftp::decode_version(payload, version)) {
        reset_frame();
        fail(make_error_code(code::unexpected_message));
        co_return failed_;
    }
    reset_frame();
    if (version.version < sftp::protocol_version) {
        fail(make_error_code(code::negotiation_failed));
        co_return failed_;
    }
    extensions_ = sftp::advertised_extensions(version.extensions);
    started_ = true;
    if (opts_.query_limits && supports(sftp::extension::limits)) {
        auto lim = co_await query_limits();
        if (failed_) co_return failed_;
        if (!lim.ec) limits_ = lim.value;
    }
    co_return std::error_code{};
}

template <class Stream>
corral::Task<sftp::result<sftp_handle>>
basic_sftp_client<Stream>::open(std::string_view path, std::uint32_t flags, const sftp::attrs& attributes) {
    if (auto ec = gate()) co_return failed_result<sftp_handle>(ec);
    const auto id = alloc_id();
    wire::writer w;
    sftp::encode_open(w, id, path, flags, attributes);
    co_return finish_handle(co_await exchange(id, w.data()));
}

template <class Stream>
corral::Task<sftp::result<std::size_t>>
basic_sftp_client<Stream>::read(const sftp_handle& handle, std::uint64_t offset, std::span<std::byte> dst) {
    if (auto ec = gate()) co_return failed_result<std::size_t>(ec);
    if (dst.empty()) co_return sftp::result<std::size_t>{{}, {}, 0};
    const auto want = static_cast<std::uint32_t>(std::min<std::size_t>(dst.size(), read_limit()));
    const auto id = alloc_id();
    wire::writer w;
    sftp::encode_read(w, id, handle.bytes(), offset, want);
    auto raw = co_await exchange(id, w.data());
    if (raw.ec) co_return failed_result<std::size_t>(raw.ec);
    if (raw.type == sftp::msg::status) {
        auto st = finish_status(raw);
        if (st.ec == sftp::status_code::eof) co_return sftp::result<std::size_t>{{}, {}, 0};
        if (!st.ec) co_return failed_result<std::size_t>(make_error_code(code::unexpected_message));
        co_return sftp::result<std::size_t>{st.ec, std::move(st.message), {}};
    }
    if (raw.type != sftp::msg::data) {
        co_return failed_result<std::size_t>(make_error_code(code::unexpected_message));
    }
    sftp::data_reply data;
    if (!sftp::decode_data(raw.payload, data)) {
        co_return failed_result<std::size_t>(make_error_code(code::invalid_format));
    }
    if (data.data.size() > want || data.data.size() > dst.size()) {
        co_return failed_result<std::size_t>(make_error_code(code::unexpected_message));
    }
    if (!data.data.empty()) std::memcpy(dst.data(), data.data.data(), data.data.size());
    co_return sftp::result<std::size_t>{{}, {}, data.data.size()};
}

template <class Stream>
corral::Task<sftp::result<>>
basic_sftp_client<Stream>::write(const sftp_handle& handle, std::uint64_t offset,
                                 std::span<const std::byte> src) {
    if (auto ec = gate()) co_return sftp::result<>{ec, {}};
    if (src.size() > write_limit(handle)) {
        co_return sftp::result<>{make_error_code(code::invalid_argument), {}};
    }
    const auto id = alloc_id();
    wire::writer w;
    sftp::encode_write_header(w, id, handle.bytes(), offset,
                              static_cast<std::uint32_t>(src.size()));
    co_return finish_status(co_await exchange(id, w.data(), src));
}

template <class Stream>
corral::Task<sftp::result<>> basic_sftp_client<Stream>::close(sftp_handle& handle) {
    if (auto ec = gate()) co_return sftp::result<>{ec, {}};
    const auto id = alloc_id();
    wire::writer w;
    sftp::encode_close(w, id, handle.bytes());
    auto out = finish_status(co_await exchange(id, w.data()));
    if (!out.ec) handle.clear();
    co_return out;
}

template <class Stream>
corral::Task<sftp::result<sftp::attrs>> basic_sftp_client<Stream>::attrs_path(sftp::msg type,
                                                                             std::string_view path) {
    if (auto ec = gate()) co_return failed_result<sftp::attrs>(ec);
    const auto id = alloc_id();
    wire::writer w;
    sftp::encode_path_request(w, type, id, path);
    co_return finish_attrs(co_await exchange(id, w.data()));
}

template <class Stream>
corral::Task<sftp::result<sftp::attrs>> basic_sftp_client<Stream>::stat(std::string_view path) {
    co_return co_await attrs_path(sftp::msg::stat, path);
}
template <class Stream>
corral::Task<sftp::result<sftp::attrs>> basic_sftp_client<Stream>::lstat(std::string_view path) {
    co_return co_await attrs_path(sftp::msg::lstat, path);
}

template <class Stream>
corral::Task<sftp::result<sftp::attrs>> basic_sftp_client<Stream>::fstat(const sftp_handle& handle) {
    if (auto ec = gate()) co_return failed_result<sftp::attrs>(ec);
    const auto id = alloc_id();
    wire::writer w;
    w.write_byte(static_cast<std::uint8_t>(sftp::msg::fstat));
    w.write_uint32(id);
    w.write_string(handle.bytes());
    co_return finish_attrs(co_await exchange(id, w.data()));
}

template <class Stream>
corral::Task<sftp::result<>> basic_sftp_client<Stream>::setstat(std::string_view path,
                                                               const sftp::attrs& attributes) {
    if (auto ec = gate()) co_return sftp::result<>{ec, {}};
    const auto id = alloc_id();
    wire::writer w;
    sftp::encode_setstat(w, sftp::msg::setstat, id, path, attributes);
    co_return finish_status(co_await exchange(id, w.data()));
}

template <class Stream>
corral::Task<sftp::result<>> basic_sftp_client<Stream>::fsetstat(const sftp_handle& handle,
                                                                const sftp::attrs& attributes) {
    if (auto ec = gate()) co_return sftp::result<>{ec, {}};
    const auto id = alloc_id();
    wire::writer w;
    sftp::encode_fsetstat(w, id, handle.bytes(), attributes);
    co_return finish_status(co_await exchange(id, w.data()));
}

template <class Stream>
corral::Task<sftp::result<sftp_handle>> basic_sftp_client<Stream>::opendir(std::string_view path) {
    if (auto ec = gate()) co_return failed_result<sftp_handle>(ec);
    const auto id = alloc_id();
    wire::writer w;
    sftp::encode_path_request(w, sftp::msg::opendir, id, path);
    co_return finish_handle(co_await exchange(id, w.data()));
}

template <class Stream>
corral::Task<sftp::result<std::vector<sftp::name_entry>>>
basic_sftp_client<Stream>::readdir(const sftp_handle& handle) {
    if (auto ec = gate()) co_return failed_result<std::vector<sftp::name_entry>>(ec);
    const auto id = alloc_id();
    wire::writer w;
    w.write_byte(static_cast<std::uint8_t>(sftp::msg::readdir));
    w.write_uint32(id);
    w.write_string(handle.bytes());
    co_return finish_names(co_await exchange(id, w.data()), true);
}

template <class Stream>
corral::Task<sftp::result<std::vector<sftp::name_entry>>>
basic_sftp_client<Stream>::read_dir(std::string_view path) {
    auto opened = co_await opendir(path);
    if (opened.ec) co_return sftp::result<std::vector<sftp::name_entry>>{
        opened.ec, std::move(opened.message), {}};
    std::vector<sftp::name_entry> all;
    std::error_code ec;
    std::string message;
    for (;;) {
        auto page = co_await readdir(opened.value);
        if (page.ec) {
            ec = page.ec;
            message = std::move(page.message);
            break;
        }
        if (page.value.empty()) break;
        all.insert(all.end(), page.value.begin(), page.value.end());
    }
    if (!failed_) {
        auto closed = co_await close(opened.value);
        if (!ec && closed.ec) {
            ec = closed.ec;
            message = std::move(closed.message);
        }
    }
    co_return sftp::result<std::vector<sftp::name_entry>>{ec, std::move(message), std::move(all)};
}

template <class Stream>
corral::Task<sftp::result<>> basic_sftp_client<Stream>::status_path(sftp::msg type,
                                                                   std::string_view path) {
    if (auto ec = gate()) co_return sftp::result<>{ec, {}};
    const auto id = alloc_id();
    wire::writer w;
    sftp::encode_path_request(w, type, id, path);
    co_return finish_status(co_await exchange(id, w.data()));
}

template <class Stream>
corral::Task<sftp::result<>> basic_sftp_client<Stream>::remove(std::string_view path) {
    co_return co_await status_path(sftp::msg::remove, path);
}
template <class Stream>
corral::Task<sftp::result<>> basic_sftp_client<Stream>::rmdir(std::string_view path) {
    co_return co_await status_path(sftp::msg::rmdir, path);
}
template <class Stream>
corral::Task<sftp::result<>> basic_sftp_client<Stream>::mkdir(std::string_view path,
                                                             const sftp::attrs& attributes) {
    if (auto ec = gate()) co_return sftp::result<>{ec, {}};
    const auto id = alloc_id();
    wire::writer w;
    sftp::encode_setstat(w, sftp::msg::mkdir, id, path, attributes);
    co_return finish_status(co_await exchange(id, w.data()));
}

template <class Stream>
corral::Task<sftp::result<std::vector<sftp::name_entry>>>
basic_sftp_client<Stream>::realpath(std::string_view path) {
    if (auto ec = gate()) co_return failed_result<std::vector<sftp::name_entry>>(ec);
    const auto id = alloc_id();
    wire::writer w;
    sftp::encode_path_request(w, sftp::msg::realpath, id, path);
    co_return finish_names(co_await exchange(id, w.data()), false);
}

template <class Stream>
corral::Task<sftp::result<>> basic_sftp_client<Stream>::rename(std::string_view oldpath,
                                                              std::string_view newpath) {
    if (auto ec = gate()) co_return sftp::result<>{ec, {}};
    const auto id = alloc_id();
    wire::writer w;
    sftp::encode_rename(w, id, oldpath, newpath);
    co_return finish_status(co_await exchange(id, w.data()));
}

template <class Stream>
corral::Task<sftp::result<std::vector<sftp::name_entry>>>
basic_sftp_client<Stream>::readlink(std::string_view path) {
    if (auto ec = gate()) co_return failed_result<std::vector<sftp::name_entry>>(ec);
    const auto id = alloc_id();
    wire::writer w;
    sftp::encode_path_request(w, sftp::msg::readlink, id, path);
    co_return finish_names(co_await exchange(id, w.data()), false);
}

template <class Stream>
corral::Task<sftp::result<>> basic_sftp_client<Stream>::symlink(std::string_view target,
                                                               std::string_view linkpath) {
    if (auto ec = gate()) co_return sftp::result<>{ec, {}};
    const auto id = alloc_id();
    wire::writer w;
    sftp::encode_symlink(w, id, target, linkpath);
    co_return finish_status(co_await exchange(id, w.data()));
}

template <class Stream>
corral::Task<sftp::result<std::size_t>>
basic_sftp_client<Stream>::read_all(const sftp_handle& handle, std::uint64_t offset,
                                    std::span<std::byte> dst) {
    if (auto ec = gate()) co_return failed_result<std::size_t>(ec);
    pipeline_outcome out{dst.size(), {}, {}};
    co_await pipeline(dst.size(), read_limit(), out,
                      [&](std::size_t off, std::size_t len) -> corral::Task<void> {
        std::size_t done = 0;
        while (done < len && off + done < out.stop) {
            auto r = co_await read(handle, offset + off + done, dst.subspan(off + done, len - done));
            if (r.ec || r.value == 0) {
                out.halt(off + done, r.ec, std::move(r.message));
                co_return;
            }
            done += r.value;
        }
    });
    co_return sftp::result<std::size_t>{out.ec, std::move(out.message), out.stop};
}

template <class Stream>
corral::Task<sftp::result<>>
basic_sftp_client<Stream>::write_all(const sftp_handle& handle, std::uint64_t offset,
                                     std::span<const std::byte> src) {
    if (auto ec = gate()) co_return sftp::result<>{ec, {}};
    if (src.empty()) co_return {};
    const auto chunk = write_limit(handle);
    if (chunk == 0) co_return sftp::result<>{make_error_code(code::invalid_argument), {}};
    pipeline_outcome out{src.size(), {}, {}};
    co_await pipeline(src.size(), chunk, out,
                      [&](std::size_t off, std::size_t len) -> corral::Task<void> {
        auto r = co_await write(handle, offset + off, src.subspan(off, len));
        if (r.ec) out.halt(off, r.ec, std::move(r.message));
    });
    co_return sftp::result<>{out.ec, std::move(out.message)};
}

template <class Stream>
corral::Task<sftp::result<>> basic_sftp_client<Stream>::posix_rename(std::string_view oldpath,
                                                                    std::string_view newpath) {
    if (auto ec = gate(sftp::extension::posix_rename)) co_return sftp::result<>{ec, {}};
    const auto id = alloc_id();
    wire::writer w;
    sftp::encode_posix_rename(w, id, oldpath, newpath);
    co_return finish_status(co_await exchange(id, w.data()));
}

template <class Stream>
corral::Task<sftp::result<sftp::statvfs_info>>
basic_sftp_client<Stream>::statvfs(std::string_view path) {
    if (auto ec = gate(sftp::extension::statvfs)) co_return failed_result<sftp::statvfs_info>(ec);
    const auto id = alloc_id();
    wire::writer w;
    sftp::encode_statvfs(w, id, path);
    co_return finish_statvfs(co_await exchange(id, w.data()));
}

template <class Stream>
corral::Task<sftp::result<sftp::statvfs_info>>
basic_sftp_client<Stream>::fstatvfs(const sftp_handle& handle) {
    if (auto ec = gate(sftp::extension::fstatvfs)) co_return failed_result<sftp::statvfs_info>(ec);
    const auto id = alloc_id();
    wire::writer w;
    sftp::encode_fstatvfs(w, id, handle.bytes());
    co_return finish_statvfs(co_await exchange(id, w.data()));
}

template <class Stream>
corral::Task<sftp::result<>> basic_sftp_client<Stream>::hardlink(std::string_view oldpath,
                                                                std::string_view newpath) {
    if (auto ec = gate(sftp::extension::hardlink)) co_return sftp::result<>{ec, {}};
    const auto id = alloc_id();
    wire::writer w;
    sftp::encode_hardlink(w, id, oldpath, newpath);
    co_return finish_status(co_await exchange(id, w.data()));
}

template <class Stream>
corral::Task<sftp::result<>> basic_sftp_client<Stream>::fsync(const sftp_handle& handle) {
    if (auto ec = gate(sftp::extension::fsync)) co_return sftp::result<>{ec, {}};
    const auto id = alloc_id();
    wire::writer w;
    sftp::encode_fsync(w, id, handle.bytes());
    co_return finish_status(co_await exchange(id, w.data()));
}

template <class Stream>
corral::Task<sftp::result<>> basic_sftp_client<Stream>::lsetstat(std::string_view path,
                                                                const sftp::attrs& attributes) {
    if (auto ec = gate(sftp::extension::lsetstat)) co_return sftp::result<>{ec, {}};
    const auto id = alloc_id();
    wire::writer w;
    sftp::encode_lsetstat(w, id, path, attributes);
    co_return finish_status(co_await exchange(id, w.data()));
}

template <class Stream>
corral::Task<sftp::result<sftp::limits_info>> basic_sftp_client<Stream>::query_limits() {
    if (auto ec = gate(sftp::extension::limits)) co_return failed_result<sftp::limits_info>(ec);
    const auto id = alloc_id();
    wire::writer w;
    sftp::encode_limits(w, id);
    auto raw = co_await exchange(id, w.data());
    if (raw.ec) {
        co_return sftp::result<sftp::limits_info>{raw.ec, {}, {}};
    }
    if (raw.type == sftp::msg::status) {
        auto st = finish_status(raw);
        if (!st.ec) {
            co_return failed_result<sftp::limits_info>(make_error_code(code::unexpected_message));
        }
        co_return sftp::result<sftp::limits_info>{st.ec, std::move(st.message), {}};
    }
    if (raw.type != sftp::msg::extended_reply) {
        co_return failed_result<sftp::limits_info>(make_error_code(code::unexpected_message));
    }
    sftp::limits_info info;
    std::uint32_t got_id = 0;
    if (!sftp::decode_limits_reply(raw.payload, got_id, info)) {
        co_return failed_result<sftp::limits_info>(make_error_code(code::invalid_format));
    }
    co_return sftp::result<sftp::limits_info>{{}, {}, info};
}

template <class Stream>
corral::Task<sftp::result<std::vector<sftp::name_entry>>>
basic_sftp_client<Stream>::expand_path(std::string_view path) {
    if (auto ec = gate(sftp::extension::expand_path)) {
        co_return failed_result<std::vector<sftp::name_entry>>(ec);
    }
    const auto id = alloc_id();
    wire::writer w;
    sftp::encode_expand_path(w, id, path);
    co_return finish_names(co_await exchange(id, w.data()), false);
}

template <class Stream>
corral::Task<sftp::result<>>
basic_sftp_client<Stream>::copy_data(const sftp_handle& src, std::uint64_t src_offset,
                                     std::uint64_t length, const sftp_handle& dst,
                                     std::uint64_t dst_offset) {
    if (auto ec = gate(sftp::extension::copy_data)) co_return sftp::result<>{ec, {}};
    const auto id = alloc_id();
    wire::writer w;
    sftp::encode_copy_data(w, id, src.bytes(), src_offset, length, dst.bytes(), dst_offset);
    co_return finish_status(co_await exchange(id, w.data()));
}

template <class Stream>
corral::Task<sftp::result<std::string>>
basic_sftp_client<Stream>::home_directory(std::string_view user) {
    if (auto ec = gate(sftp::extension::home_directory)) co_return failed_result<std::string>(ec);
    const auto id = alloc_id();
    wire::writer w;
    sftp::encode_home_directory(w, id, user);
    auto names = finish_names(co_await exchange(id, w.data()), false);
    if (names.ec) co_return sftp::result<std::string>{names.ec, std::move(names.message), {}};
    if (names.value.size() != 1) {
        co_return failed_result<std::string>(make_error_code(code::unexpected_message));
    }
    co_return sftp::result<std::string>{{}, {}, std::move(names.value.front().filename)};
}

template <class Stream>
corral::Task<sftp::result<sftp::id_name_lists>>
basic_sftp_client<Stream>::users_groups_by_id(std::span<const std::uint32_t> uids,
                                              std::span<const std::uint32_t> gids) {
    if (auto ec = gate(sftp::extension::users_groups_by_id)) {
        co_return failed_result<sftp::id_name_lists>(ec);
    }
    // Keeps the uint32 blob lengths exact; exchange() enforces the frame bound.
    const std::size_t max_ids = frame_limit() / 4u;
    if (uids.size() > max_ids || gids.size() > max_ids - uids.size()) {
        co_return failed_result<sftp::id_name_lists>(make_error_code(code::invalid_argument));
    }
    const auto id = alloc_id();
    wire::writer w;
    sftp::encode_users_groups_by_id(w, id, uids, gids);
    auto raw = co_await exchange(id, w.data());
    if (raw.ec) {
        co_return sftp::result<sftp::id_name_lists>{raw.ec, {}, {}};
    }
    if (raw.type == sftp::msg::status) {
        auto st = finish_status(raw);
        if (!st.ec) {
            co_return failed_result<sftp::id_name_lists>(make_error_code(code::unexpected_message));
        }
        co_return sftp::result<sftp::id_name_lists>{st.ec, std::move(st.message), {}};
    }
    if (raw.type != sftp::msg::extended_reply) {
        co_return failed_result<sftp::id_name_lists>(make_error_code(code::unexpected_message));
    }
    sftp::users_groups_reply_view view;
    if (!sftp::decode_users_groups_by_id_reply(
            raw.payload, static_cast<std::uint32_t>(uids.size()),
            static_cast<std::uint32_t>(gids.size()), view)) {
        co_return failed_result<sftp::id_name_lists>(make_error_code(code::unexpected_message));
    }
    sftp::id_name_lists names;
    names.users.reserve(view.users.size());
    names.groups.reserve(view.groups.size());
    for (auto u : view.users) names.users.emplace_back(u);
    for (auto g : view.groups) names.groups.emplace_back(g);
    co_return sftp::result<sftp::id_name_lists>{{}, {}, std::move(names)};
}

using sftp_client = basic_sftp_client<channel>;

inline corral::Task<std::tuple<std::error_code, std::unique_ptr<sftp_client>>>
open_sftp(session& sess, sftp_options opts = {}) {
    auto opened = co_await sess.open_session_channel();
    if (opened.ec) co_return {opened.ec, nullptr};
    if (auto ec = co_await opened.ch.request_subsystem("sftp")) {
        co_await opened.ch.close();
        co_return {ec, nullptr};
    }
    auto client = std::make_unique<sftp_client>(std::move(opened.ch), opts);
    if (auto ec = co_await client->start()) co_return {ec, nullptr};
    co_return {std::error_code{}, std::move(client)};
}

}  // namespace yanterm::ssh
