#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/sftp.hpp>
#include <yanterm-ssh/sftp/packets.hpp>

#include "facade_fixture.hpp"
#include "memory_pipe.hpp"
#include "test_loop.hpp"

#include <corral/corral.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

using namespace yanterm::ssh;
using namespace yanterm::ssh::testing;

namespace {

struct reader_gate {
    corral::Handle handle{};

    bool await_ready() const noexcept { return false; }
    void await_suspend(corral::Handle h) { handle = h; }
    void await_resume() {}
    bool await_early_cancel() noexcept { return true; }
    bool await_cancel(corral::Handle) noexcept {
        handle = nullptr;
        return true;
    }
    auto await_must_resume() const noexcept { return std::false_type{}; }

    void wake() {
        if (handle) std::exchange(handle, nullptr).resume();
    }
};

struct script_state {
    TestLoop* loop = nullptr;
    std::vector<std::byte> inbox;
    std::vector<std::byte> outbox;
    bool closed = false;
    std::size_t delivered = 0;
    bool read_waiting = false;
    std::size_t write_budget = static_cast<std::size_t>(-1);
    // Models a peer that stops reading requests until its replies are consumed.
    bool writes_wait_for_reads = false;
    bool write_parked = false;
    reader_gate reader;
    corral::ParkingLot data;
    corral::ParkingLot progress;

    void wake() {
        loop->post([self = this] {
            self->progress.unparkAll();
            if (!self->inbox.empty() || self->closed) self->reader.wake();
            if (self->write_budget > 0 || self->closed) self->data.unparkAll();
        });
    }
};

class script_end {
public:
    explicit script_end(std::shared_ptr<script_state> st) : st_(std::move(st)) {}

    script_end(const script_end&) = delete;
    script_end& operator=(const script_end&) = delete;
    script_end(script_end&&) noexcept = default;
    script_end& operator=(script_end&&) noexcept = default;

    corral::Task<auv::read_result> read(auv::read_allocator alloc, void* arg) {
        if (!st_ || st_->closed) co_return {auv::make_error_code(auv::errc::eof), 0};
        while (st_->inbox.empty() && !st_->closed) {
            st_->read_waiting = true;
            st_->wake();
            co_await st_->reader;
            st_->read_waiting = false;
        }
        if (st_->inbox.empty()) co_return {auv::make_error_code(auv::errc::eof), 0};
        auv::buffer buf = alloc(arg);
        const auto n = std::min(buf.size(), st_->inbox.size());
        std::memcpy(buf.data(), st_->inbox.data(), n);
        st_->inbox.erase(st_->inbox.begin(), st_->inbox.begin() + static_cast<std::ptrdiff_t>(n));
        st_->delivered += n;
        st_->wake();
        co_return {std::error_code{}, n};
    }

    corral::Task<std::error_code> write(const auv::buffer* bufs, std::size_t nbufs) {
        if (!st_ || st_->closed) co_return std::make_error_code(std::errc::not_connected);
        std::size_t bi = 0;
        std::size_t bo = 0;
        auto remaining = [&] {
            if (bi >= nbufs) return std::size_t{0};
            std::size_t n = bufs[bi].size() - bo;
            for (std::size_t i = bi + 1; i < nbufs; ++i) n += bufs[i].size();
            return n;
        };
        while (remaining() > 0) {
            if (st_->closed) co_return std::make_error_code(std::errc::not_connected);
            if (st_->write_budget == 0 || (st_->writes_wait_for_reads && !st_->inbox.empty())) {
                st_->write_parked = true;
                st_->wake();
                co_await st_->data.park();
                st_->write_parked = false;
                continue;
            }
            const auto room = st_->write_budget;
            std::size_t left = room;
            while (left > 0 && bi < nbufs) {
                const auto* p = reinterpret_cast<const std::byte*>(bufs[bi].data());
                const auto avail = bufs[bi].size() - bo;
                const auto n = std::min(left, avail);
                st_->outbox.insert(st_->outbox.end(), p + bo, p + bo + n);
                left -= n;
                bo += n;
                if (bo == bufs[bi].size()) {
                    ++bi;
                    bo = 0;
                }
            }
            st_->write_budget -= room - left;
            st_->wake();
        }
        co_return std::error_code{};
    }

    corral::Task<std::error_code> shutdown() { co_return std::error_code{}; }
    corral::Task<void> close() {
        if (st_) {
            st_->closed = true;
            st_->wake();
        }
        co_return;
    }

private:
    std::shared_ptr<script_state> st_;
};

std::vector<std::byte> frame(std::span<const std::byte> payload) {
    std::vector<std::byte> out;
    const auto n = static_cast<std::uint32_t>(payload.size());
    out.push_back(static_cast<std::byte>(n >> 24));
    out.push_back(static_cast<std::byte>(n >> 16));
    out.push_back(static_cast<std::byte>(n >> 8));
    out.push_back(static_cast<std::byte>(n));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

std::vector<std::byte> encoded(const std::function<void(wire::writer&)>& fn) {
    wire::writer w;
    fn(w);
    return w.take();
}

void feed(script_state& st, std::span<const std::byte> bytes) {
    st.inbox.insert(st.inbox.end(), bytes.begin(), bytes.end());
    st.wake();
}

corral::Task<std::vector<std::byte>> next_payload(script_state& st) {
    auto have = [&] { return st.outbox.size(); };
    while (have() < 4) co_await st.progress.park();
    const auto len = sftp::decode_frame_header(std::span<const std::byte>(st.outbox.data(), 4));
    while (have() < 4u + len) co_await st.progress.park();
    std::vector<std::byte> payload(st.outbox.begin() + 4, st.outbox.begin() + 4 + static_cast<std::ptrdiff_t>(len));
    st.outbox.erase(st.outbox.begin(), st.outbox.begin() + 4 + static_cast<std::ptrdiff_t>(len));
    co_return payload;
}

void send_status(script_state& st, std::uint32_t id, sftp::status_code code, std::string_view message) {
    auto payload = encoded([&](wire::writer& w) {
        sftp::encode_status(w, id, code, message, "en");
    });
    feed(st, frame(payload));
}

void send_version(script_state& st, std::uint32_t version, std::span<const sftp::extension_pair> exts = {}) {
    auto payload = encoded([&](wire::writer& w) { sftp::encode_version(w, version, exts); });
    feed(st, frame(payload));
}

corral::Task<void> expect_init(script_state& st) {
    auto payload = co_await next_payload(st);
    std::uint32_t version = 0;
    REQUIRE(sftp::decode_init(payload, version));
    REQUIRE(version == 3);
}

struct harness {
    TestLoop loop;
    std::shared_ptr<script_state> st = std::make_shared<script_state>();
    sftp_options opts{};
    sftp::limits_info peer_limits{};
    basic_sftp_client<script_end> client;

    harness() : harness(sftp_options{}) {}
    explicit harness(sftp_options o) : opts(std::move(o)), client(script_end{st}, opts) {
        st->loop = &loop;
    }
};

bool advertised(std::span<const sftp::extension_pair> exts, std::string_view name,
                std::string_view version) {
    return std::any_of(exts.begin(), exts.end(), [&](const sftp::extension_pair& e) {
        return e.name == name && e.version == version;
    });
}

corral::Task<void> handshake(harness& h, std::uint32_t version = 3,
                             std::span<const sftp::extension_pair> exts = {}) {
    const bool want_limits = h.opts.query_limits && version >= 3
        && advertised(exts, "limits@openssh.com", "1");
    CORRAL_WITH_NURSERY(n) {
        n.start([&]() -> corral::Task<void> {
            co_await expect_init(*h.st);
            send_version(*h.st, version, exts);
            if (!want_limits) co_return;
            auto payload = co_await next_payload(*h.st);
            wire::reader r{payload};
            std::uint8_t type = 0;
            std::uint32_t id = 0;
            std::string_view req;
            REQUIRE(r.read_byte(type));
            REQUIRE(type == static_cast<std::uint8_t>(sftp::msg::extended));
            REQUIRE(r.read_uint32(id));
            REQUIRE(r.read_string(req));
            REQUIRE(req == "limits@openssh.com");
            auto body = encoded([&](wire::writer& w) {
                sftp::encode_limits_reply(w, id, h.peer_limits);
            });
            feed(*h.st, frame(body));
        });
        auto ec = co_await h.client.start();
        if (version < 3) REQUIRE(ec == errc::negotiation_failed);
        else REQUIRE_FALSE(ec);
        co_return corral::join;
    };
}

void send_payload(script_state& st, std::vector<std::byte> payload) {
    feed(st, frame(payload));
}

corral::Task<std::uint32_t> expect_request(script_state& st, sftp::msg type) {
    auto payload = co_await next_payload(st);
    std::uint32_t id = 0;
    REQUIRE(sftp::packet_type(payload) == type);
    REQUIRE(sftp::packet_request_id(payload, id));
    co_return id;
}

}  // namespace

TEST_CASE("sftp handshake accepts version 3 and latches an older peer", "[sftp][client]") {
    harness ok;
    corral::run(ok.loop, handshake(ok, 3));
    harness old;
    corral::run(old.loop, [&]() -> corral::Task<void> {
        co_await handshake(old, 2);
        auto st = co_await old.client.stat("/tmp");
        REQUIRE(st.ec == errc::negotiation_failed);
        REQUIRE(st.message.empty());
        const auto sent = old.st->outbox.size();
        auto restarted = co_await old.client.start();
        REQUIRE(restarted == errc::invalid_state);
        REQUIRE(old.st->outbox.size() == sent);
    }());
}

TEST_CASE("sftp handshake rejects a non-version greeting and latches", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                co_await expect_init(*h.st);
                send_status(*h.st, 1, sftp::status_code::ok, "nope");
            });
            auto ec = co_await h.client.start();
            REQUIRE(ec == errc::protocol_violation);
            auto again = co_await h.client.stat("/tmp");
            REQUIRE(again.ec == ec);
            co_return corral::join;
        };
    }());
}

TEST_CASE("sftp works at protocol 3 when the peer answers a higher version", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        co_await handshake(h, 6);
        REQUIRE(h.client.supports(sftp::extension::posix_rename) == false);
    }());
}

TEST_CASE("sftp status failure keeps the server text and maps to errc", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        co_await handshake(h);
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto payload = co_await next_payload(*h.st);
                std::uint32_t id = 0;
                std::string_view path;
                REQUIRE(sftp::decode_path_request(payload, sftp::msg::remove, id, path));
                REQUIRE(path == "/missing");
                send_status(*h.st, id, sftp::status_code::no_such_file, "gone");
            });
            auto removed = co_await h.client.remove("/missing");
            REQUIRE(removed.ec == std::errc::no_such_file_or_directory);
            REQUIRE(removed.message == "gone");
            co_return corral::join;
        };
    }());
}

TEST_CASE("sftp rejects operations before the handshake", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        auto st = co_await h.client.stat("/tmp");
        REQUIRE(st.ec == errc::invalid_state);
        REQUIRE(st.message.empty());
        auto renamed = co_await h.client.posix_rename("/a", "/b");
        REQUIRE(renamed.ec == errc::invalid_state);
        REQUIRE(h.st->outbox.empty());
    }());
}

TEST_CASE("sftp reassembles a version frame fed one byte at a time", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                co_await expect_init(*h.st);
                auto ver = frame(encoded([&](wire::writer& w) { sftp::encode_version(w, 3); }));
                for (const auto byte : ver) {
                    const auto before = h.st->delivered;
                    feed(*h.st, std::span<const std::byte>(&byte, 1));
                    while (h.st->delivered == before) co_await h.st->progress.park();
                }
            });
            auto started = co_await h.client.start();
            REQUIRE_FALSE(started);
            co_return corral::join;
        };
    }());
}

TEST_CASE("sftp latches an oversize or empty frame length", "[sftp][client]") {
    const auto drive = [](std::vector<std::byte> hdr) {
        harness h;
        corral::run(h.loop, [&]() -> corral::Task<void> {
            CORRAL_WITH_NURSERY(n) {
                n.start([&]() -> corral::Task<void> {
                    co_await expect_init(*h.st);
                    feed(*h.st, hdr);
                });
                auto ec = co_await h.client.start();
                REQUIRE(ec == errc::malformed_input);
                auto again = co_await h.client.stat("/tmp");
                REQUIRE(again.ec == ec);
                REQUIRE(again.message.empty());
                co_return corral::join;
            };
        }());
    };
    drive(std::vector<std::byte>{std::byte{0}, std::byte{4}, std::byte{0}, std::byte{1}});
    drive(std::vector<std::byte>{std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}});
}

TEST_CASE("sftp maps a truncated header followed by EOF to session_closed", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                co_await expect_init(*h.st);
                const auto before = h.st->delivered;
                const std::byte prefix[] = {std::byte{0}, std::byte{0}};
                feed(*h.st, std::span<const std::byte>(prefix, 2));
                while (h.st->delivered < before + 2) co_await h.st->progress.park();
                while (!h.st->read_waiting) co_await h.st->progress.park();
                h.st->closed = true;
                h.st->wake();
            });
            auto started = co_await h.client.start();
            REQUIRE(started == errc::session_closed);
            auto again = co_await h.client.stat("/tmp");
            REQUIRE(again.ec == errc::session_closed);
            co_return corral::join;
        };
    }());
}

TEST_CASE("sftp maps a closed stream to session_closed", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                co_await expect_init(*h.st);
                h.st->closed = true;
                h.st->wake();
            });
            auto started = co_await h.client.start();
            REQUIRE(started == errc::session_closed);
            co_return corral::join;
        };
    }());
}

TEST_CASE("sftp matches concurrent replies out of order", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        co_await handshake(h);
        sftp::result<> first;
        sftp::result<> second;
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto a = co_await next_payload(*h.st);
                auto b = co_await next_payload(*h.st);
                std::uint32_t id_a = 0;
                std::uint32_t id_b = 0;
                std::string_view path_a;
                std::string_view path_b;
                REQUIRE(sftp::decode_path_request(a, sftp::msg::remove, id_a, path_a));
                REQUIRE(sftp::decode_path_request(b, sftp::msg::remove, id_b, path_b));
                REQUIRE(path_a == "/a");
                REQUIRE(path_b == "/b");
                send_status(*h.st, id_b, sftp::status_code::ok, {});
                send_status(*h.st, id_a, sftp::status_code::permission_denied, "no");
            });
            n.start([&]() -> corral::Task<void> { first = co_await h.client.remove("/a"); });
            n.start([&]() -> corral::Task<void> { second = co_await h.client.remove("/b"); });
            co_return corral::join;
        };
        REQUIRE(first.ec == std::errc::permission_denied);
        REQUIRE(first.message == "no");
        REQUIRE_FALSE(second.ec);
        REQUIRE(second.message.empty());
    }());
}

TEST_CASE("sftp drops a late reply to a cancelled request", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        co_await handshake(h);
        std::uint32_t late_id = 0;
        corral::Event got;
        corral::Event send_late;
        CORRAL_WITH_NURSERY(outer) {
            outer.start([&]() -> corral::Task<void> {
                auto payload = co_await next_payload(*h.st);
                std::string_view path;
                REQUIRE(sftp::decode_path_request(payload, sftp::msg::remove, late_id, path));
                REQUIRE(path == "/x");
                got.trigger();
                co_await send_late;
                send_status(*h.st, late_id, sftp::status_code::no_such_file, "late");
            });
            CORRAL_WITH_NURSERY(op) {
                op.start([&]() -> corral::Task<void> {
                    auto removed = co_await h.client.remove("/x");
                    (void)removed;
                });
                co_await got;
                co_return corral::cancel;
            };
            send_late.trigger();
            while (h.st->inbox.empty()) co_await h.st->progress.park();
            CORRAL_WITH_NURSERY(next) {
                next.start([&]() -> corral::Task<void> {
                    auto payload = co_await next_payload(*h.st);
                    std::uint32_t id = 0;
                    std::string_view path;
                    REQUIRE(sftp::decode_path_request(payload, sftp::msg::remove, id, path));
                    REQUIRE(id != late_id);
                    REQUIRE(path == "/y");
                    send_status(*h.st, id, sftp::status_code::ok, "should-not-stick");
                });
                auto removed = co_await h.client.remove("/y");
                REQUIRE_FALSE(removed.ec);
                REQUIRE(removed.message.empty());
                co_return corral::join;
            };
            co_return corral::join;
        };
    }());
}

TEST_CASE("sftp finishes a frame after cancel lands mid-write", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        co_await handshake(h);
        h.st->write_budget = 1;
        corral::Event partial;
        CORRAL_WITH_NURSERY(outer) {
            outer.start([&]() -> corral::Task<void> {
                while (h.st->outbox.size() < 1) co_await h.st->progress.park();
                partial.trigger();
                h.st->write_budget = static_cast<std::size_t>(-1);
                h.st->wake();
            });
            CORRAL_WITH_NURSERY(op) {
                op.start([&]() -> corral::Task<void> {
                    auto removed = co_await h.client.remove("/x");
                    (void)removed;
                });
                co_await partial;
                co_return corral::cancel;
            };
            co_return corral::join;
        };
        REQUIRE(h.st->outbox.size() >= 4);
        const auto len = sftp::decode_frame_header(std::span<const std::byte>(h.st->outbox.data(), 4));
        REQUIRE(h.st->outbox.size() == 4u + len);
        std::span<const std::byte> payload(h.st->outbox.data() + 4, len);
        std::uint32_t id = 0;
        std::string_view path;
        REQUIRE(sftp::decode_path_request(payload, sftp::msg::remove, id, path));
        REQUIRE(path == "/x");
        h.st->outbox.clear();
        h.st->write_budget = static_cast<std::size_t>(-1);
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto id2 = co_await expect_request(*h.st, sftp::msg::remove);
                send_status(*h.st, id2, sftp::status_code::ok, {});
            });
            auto removed = co_await h.client.remove("/y");
            REQUIRE_FALSE(removed.ec);
            co_return corral::join;
        };
    }());
}


TEST_CASE("sftp reassembles a frame after cancel lands mid-read", "[sftp][client]") {
    const auto drive = [](std::size_t prefix_n) {
        harness h;
        corral::run(h.loop, [&]() -> corral::Task<void> {
            co_await handshake(h);
            std::uint32_t cancelled_id = 0;
            std::vector<std::byte> remainder;
            corral::Event mid_frame;
            CORRAL_WITH_NURSERY(outer) {
                outer.start([&]() -> corral::Task<void> {
                    auto payload = co_await next_payload(*h.st);
                    std::string_view path;
                    REQUIRE(sftp::decode_path_request(payload, sftp::msg::remove, cancelled_id, path));
                    REQUIRE(path == "/x");
                    auto status = encoded([&](wire::writer& w) {
                        sftp::encode_status(w, cancelled_id, sftp::status_code::ok, {});
                    });
                    auto full = frame(status);
                    REQUIRE(full.size() > prefix_n);
                    remainder.assign(full.begin() + static_cast<std::ptrdiff_t>(prefix_n), full.end());
                    const auto before = h.st->delivered;
                    feed(*h.st, std::span<const std::byte>(full.data(), prefix_n));
                    while (h.st->delivered < before + prefix_n) co_await h.st->progress.park();
                    while (!h.st->read_waiting) co_await h.st->progress.park();
                    mid_frame.trigger();
                });
                CORRAL_WITH_NURSERY(op) {
                    op.start([&]() -> corral::Task<void> {
                        auto removed = co_await h.client.remove("/x");
                        (void)removed;
                    });
                    co_await mid_frame;
                    co_return corral::cancel;
                };
                feed(*h.st, remainder);
                CORRAL_WITH_NURSERY(next) {
                    next.start([&]() -> corral::Task<void> {
                        auto payload = co_await next_payload(*h.st);
                        std::uint32_t id = 0;
                        std::string_view path;
                        REQUIRE(sftp::decode_path_request(payload, sftp::msg::remove, id, path));
                        REQUIRE(id != cancelled_id);
                        REQUIRE(path == "/y");
                        send_status(*h.st, id, sftp::status_code::ok, {});
                    });
                    auto removed = co_await h.client.remove("/y");
                    REQUIRE_FALSE(removed.ec);
                    REQUIRE(removed.message.empty());
                    co_return corral::join;
                };
                co_return corral::join;
            };
        }());
    };
    drive(2);      // partial header
    drive(4 + 5);  // full header + partial body
}

TEST_CASE("sftp drops a cancelled request before it reaches the wire", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        co_await handshake(h);
        h.st->write_budget = 0;
        corral::Event first_parked;
        corral::Event hold_done;
        CORRAL_WITH_NURSERY(outer) {
            outer.start([&]() -> corral::Task<void> {
                while (!h.st->write_parked) co_await h.st->progress.park();
                first_parked.trigger();
            });
            outer.start([&]() -> corral::Task<void> {
                auto held = co_await h.client.remove("/hold");
                REQUIRE_FALSE(held.ec);
                hold_done.trigger();
            });
            co_await first_parked;
            CORRAL_WITH_NURSERY(blocked) {
                blocked.start([&]() -> corral::Task<void> {
                    auto removed = co_await h.client.remove("/never");
                    (void)removed;
                });
                co_await corral::yield;
                co_await corral::yield;
                co_return corral::cancel;
            };
            h.st->write_budget = static_cast<std::size_t>(-1);
            h.st->wake();
            auto held_payload = co_await next_payload(*h.st);
            std::uint32_t id = 0;
            std::string_view path;
            REQUIRE(sftp::decode_path_request(held_payload, sftp::msg::remove, id, path));
            REQUIRE(path == "/hold");
            send_status(*h.st, id, sftp::status_code::ok, {});
            co_await hold_done;
            CORRAL_WITH_NURSERY(next) {
                next.start([&]() -> corral::Task<void> {
                    auto payload = co_await next_payload(*h.st);
                    std::uint32_t id2 = 0;
                    std::string_view path2;
                    REQUIRE(sftp::decode_path_request(payload, sftp::msg::remove, id2, path2));
                    REQUIRE(path2 == "/after");
                    REQUIRE(id2 != id);
                    send_status(*h.st, id2, sftp::status_code::ok, {});
                });
                auto after = co_await h.client.remove("/after");
                REQUIRE_FALSE(after.ec);
                co_return corral::join;
            };
            co_return corral::join;
        };
    }());
}

TEST_CASE("sftp rejects an outbound frame longer than max_packet_length without failing", "[sftp][client]") {
    sftp_options opts;
    opts.max_packet_length = 64;
    opts.query_limits = false;
    harness h(opts);
    corral::run(h.loop, [&]() -> corral::Task<void> {
        co_await handshake(h);
        const std::string long_path(128, 'x');
        auto removed = co_await h.client.remove(long_path);
        REQUIRE(removed.ec == errc::invalid_argument);
        REQUIRE(h.st->outbox.empty());
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto id = co_await expect_request(*h.st, sftp::msg::remove);
                send_status(*h.st, id, sftp::status_code::ok, {});
            });
            auto again = co_await h.client.remove("/y");
            REQUIRE_FALSE(again.ec);
            co_return corral::join;
        };
    }());
}

corral::Task<sftp_handle> open_ok(harness& h) {
    sftp_handle handle;
    CORRAL_WITH_NURSERY(n) {
        n.start([&]() -> corral::Task<void> {
            auto id = co_await expect_request(*h.st, sftp::msg::open);
            const auto body = encoded([&](wire::writer& w) {
                const std::byte raw[] = {std::byte{'H'}};
                sftp::encode_handle(w, id, raw);
            });
            send_payload(*h.st, body);
        });
        auto opened = co_await h.client.open("/f", sftp::open_flags::read);
        REQUIRE_FALSE(opened.ec);
        handle = std::move(opened.value);
        co_return corral::join;
    };
    co_return handle;
}

const sftp::extension_pair k_limits[] = {{"limits@openssh.com", "1"}};
const sftp::extension_pair k_statvfs[] = {{"statvfs@openssh.com", "2"}};
const sftp::extension_pair k_home[] = {{"home-directory", "1"}};
const sftp::extension_pair k_users[] = {{"users-groups-by-id@openssh.com", "1"}};
const sftp::extension_pair k_expand[] = {{"expand-path@openssh.com", "1"}};

TEST_CASE("sftp read treats EOF as an empty success and rejects a long DATA", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        co_await handshake(h);
        auto handle = co_await open_ok(h);
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto id = co_await expect_request(*h.st, sftp::msg::read);
                send_status(*h.st, id, sftp::status_code::eof, "end");
            });
            std::byte dst[4];
            auto got = co_await h.client.read(handle, 0, dst);
            REQUIRE_FALSE(got.ec);
            REQUIRE(got.value == 0);
            REQUIRE(got.message.empty());
            co_return corral::join;
        };
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto id = co_await expect_request(*h.st, sftp::msg::read);
                const auto body = encoded([&](wire::writer& w) {
                    const std::byte raw[] = {std::byte{'a'}, std::byte{'b'}};
                    sftp::encode_data(w, id, raw);
                });
                send_payload(*h.st, body);
            });
            std::byte one{};
            auto got = co_await h.client.read(handle, 0, std::span<std::byte>(&one, 1));
            REQUIRE(got.ec == errc::protocol_violation);
            REQUIRE(got.message.empty());
            co_return corral::join;
        };
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto id = co_await expect_request(*h.st, sftp::msg::remove);
                send_status(*h.st, id, sftp::status_code::ok, {});
            });
            auto removed = co_await h.client.remove("/still");
            REQUIRE_FALSE(removed.ec);
            co_return corral::join;
        };
    }());
}

TEST_CASE("sftp read_all retries a short read and stops at EOF", "[sftp][client]") {
    sftp_options opts;
    opts.max_inflight = 1;
    harness h(opts);
    h.peer_limits.max_read_length = 4;
    h.peer_limits.max_write_length = 4;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        co_await handshake(h, 3, k_limits);
        REQUIRE(h.client.limits().max_read_length == 4);
        auto handle = co_await open_ok(h);
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                const std::string chunks[] = {"abcd", "ef"};
                for (const auto& chunk : chunks) {
                    auto payload = co_await next_payload(*h.st);
                    std::uint32_t id = 0;
                    std::span<const std::byte> hb;
                    std::uint64_t offset = 0;
                    std::uint32_t length = 0;
                    REQUIRE(sftp::decode_read(payload, id, hb, offset, length));
                    REQUIRE((length == 4 || offset == 6));
                    const auto body = encoded([&](wire::writer& w) {
                        std::vector<std::byte> raw(chunk.size());
                        std::memcpy(raw.data(), chunk.data(), chunk.size());
                        sftp::encode_data(w, id, raw);
                    });
                    send_payload(*h.st, body);
                }
                auto id = co_await expect_request(*h.st, sftp::msg::read);
                send_status(*h.st, id, sftp::status_code::eof, "end");
            });
            std::vector<std::byte> dst(10);
            auto got = co_await h.client.read_all(handle, 0, dst);
            REQUIRE_FALSE(got.ec);
            REQUIRE(got.value == 6);
            REQUIRE(std::memcmp(dst.data(), "abcdef", 6) == 0);
            co_return corral::join;
        };
    }());
}

TEST_CASE("sftp read_all reports the filled prefix when a later chunk fails", "[sftp][client]") {
    sftp_options opts;
    opts.max_inflight = 1;
    harness h(opts);
    h.peer_limits.max_read_length = 4;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        co_await handshake(h, 3, k_limits);
        auto handle = co_await open_ok(h);
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto id = co_await expect_request(*h.st, sftp::msg::read);
                send_payload(*h.st, encoded([&](wire::writer& w) {
                    const std::byte raw[] = {std::byte{'a'}, std::byte{'b'}, std::byte{'c'}, std::byte{'d'}};
                    sftp::encode_data(w, id, raw);
                }));
                id = co_await expect_request(*h.st, sftp::msg::read);
                send_status(*h.st, id, sftp::status_code::failure, "io");
            });
            std::vector<std::byte> dst(10);
            auto got = co_await h.client.read_all(handle, 0, dst);
            REQUIRE(got.ec == sftp::status_code::failure);
            REQUIRE(got.message == "io");
            REQUIRE(got.value == 4);
            REQUIRE(std::memcmp(dst.data(), "abcd", 4) == 0);
            co_return corral::join;
        };
    }());
}

TEST_CASE("sftp read of an empty buffer returns zero without a request", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        co_await handshake(h);
        auto handle = co_await open_ok(h);
        const auto before = h.st->outbox.size();
        auto got = co_await h.client.read(handle, 0, {});
        REQUIRE_FALSE(got.ec);
        REQUIRE(got.value == 0);
        REQUIRE(h.st->outbox.size() == before);
    }());
}

TEST_CASE("sftp keeps reading replies while its own request is blocked on write", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        co_await handshake(h);
        h.st->writes_wait_for_reads = true;
        send_status(*h.st, 999, sftp::status_code::ok, "stray");
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto id = co_await expect_request(*h.st, sftp::msg::remove);
                send_status(*h.st, id, sftp::status_code::ok, {});
            });
            auto removed = co_await h.client.remove("/x");
            REQUIRE_FALSE(removed.ec);
            REQUIRE(removed.message.empty());
            co_return corral::join;
        };
    }());
}

TEST_CASE("sftp write_all stops issuing after the first failing chunk", "[sftp][client]") {
    sftp_options opts;
    opts.max_inflight = 1;
    harness h(opts);
    h.peer_limits.max_write_length = 4;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        co_await handshake(h, 3, k_limits);
        auto handle = co_await open_ok(h);
        int writes = 0;
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto first = co_await next_payload(*h.st);
                ++writes;
                std::uint32_t id = 0;
                std::span<const std::byte> hb;
                std::uint64_t offset = 0;
                std::span<const std::byte> data;
                REQUIRE(sftp::decode_write(first, id, hb, offset, data));
                REQUIRE(offset == 0);
                REQUIRE(data.size() == 4);
                send_status(*h.st, id, sftp::status_code::ok, {});
                auto second = co_await next_payload(*h.st);
                ++writes;
                REQUIRE(sftp::decode_write(second, id, hb, offset, data));
                REQUIRE(offset == 4);
                send_status(*h.st, id, sftp::status_code::failure, "disk");
            });
            const std::byte src[] = {std::byte{1}, std::byte{2}, std::byte{3}, std::byte{4},
                                     std::byte{5}, std::byte{6}, std::byte{7}, std::byte{8},
                                     std::byte{9}, std::byte{10}, std::byte{11}, std::byte{12}};
            auto wrote = co_await h.client.write_all(handle, 0, src);
            REQUIRE(wrote.ec == sftp::status_code::failure);
            REQUIRE(wrote.message == "disk");
            co_return corral::join;
        };
        REQUIRE(writes == 2);
        REQUIRE(h.st->outbox.empty());
    }());
}

TEST_CASE("sftp write refuses a buffer larger than the negotiated limit", "[sftp][client]") {
    harness h;
    h.peer_limits.max_write_length = 4;
    h.peer_limits.max_read_length = 0;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        co_await handshake(h, 3, k_limits);
        auto handle = co_await open_ok(h);
        const std::byte big[5] = {};
        const auto before = h.st->outbox.size();
        auto wrote = co_await h.client.write(handle, 0, big);
        REQUIRE(wrote.ec == errc::invalid_argument);
        REQUIRE(wrote.message.empty());
        REQUIRE(h.st->outbox.size() == before);

        std::vector<std::byte> wide(40000);
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto payload = co_await next_payload(*h.st);
                std::uint32_t id = 0;
                std::span<const std::byte> hb;
                std::uint64_t offset = 0;
                std::uint32_t length = 0;
                REQUIRE(sftp::decode_read(payload, id, hb, offset, length));
                REQUIRE(length == sftp::fallback_io_length);
                send_status(*h.st, id, sftp::status_code::eof, {});
            });
            auto got = co_await h.client.read(handle, 0, wide);
            REQUIRE_FALSE(got.ec);
            co_return corral::join;
        };
        const auto mark = h.st->outbox.size();
        std::vector<std::byte> too_wide(40000);
        auto rejected = co_await h.client.write(handle, 0, too_wide);
        REQUIRE(rejected.ec == errc::invalid_argument);
        REQUIRE(h.st->outbox.size() == mark);
    }());
}

TEST_CASE("sftp write_all keeps every WRITE frame within the packet limit", "[sftp][client]") {
    struct scenario {
        const char* name;
        std::uint32_t local_max;
        std::uint64_t peer_max_packet;
        std::uint64_t peer_max_write;
        std::size_t total;
    };
    const scenario cases[] = {
        {"local limit below the fallback write length", 1024, 0, 0, 3000},
        {"peer advertises an unbounded write length", 1024, 0, 0xffffffffu, 3000},
        {"peer packet limit below ours", sftp::default_max_packet_length, 600, 0xffffffffu, 2000},
    };
    for (const auto& c : cases) {
        SECTION(c.name) {
            sftp_options opts;
            opts.max_packet_length = c.local_max;
            harness h(opts);
            h.peer_limits.max_packet_length = c.peer_max_packet;
            h.peer_limits.max_write_length = c.peer_max_write;
            const auto frame_cap = c.peer_max_packet == 0
                ? std::uint64_t{c.local_max}
                : std::min<std::uint64_t>(c.local_max, c.peer_max_packet);
            corral::run(h.loop, [&]() -> corral::Task<void> {
                co_await handshake(h, 3, k_limits);
                auto handle = co_await open_ok(h);
                std::vector<std::byte> src(c.total);
                for (std::size_t i = 0; i < src.size(); ++i) src[i] = static_cast<std::byte>(i);
                std::vector<std::byte> seen(c.total);
                std::size_t covered = 0;
                CORRAL_WITH_NURSERY(n) {
                    n.start([&]() -> corral::Task<void> {
                        while (covered < c.total) {
                            while (h.st->outbox.size() < 4) co_await h.st->progress.park();
                            const auto len = sftp::decode_frame_header(
                                std::span<const std::byte>(h.st->outbox.data(), 4));
                            REQUIRE(len <= frame_cap);
                            auto payload = co_await next_payload(*h.st);
                            std::uint32_t id = 0;
                            std::span<const std::byte> hb;
                            std::uint64_t offset = 0;
                            std::span<const std::byte> data;
                            REQUIRE(sftp::decode_write(payload, id, hb, offset, data));
                            REQUIRE(offset + data.size() <= c.total);
                            std::memcpy(seen.data() + offset, data.data(), data.size());
                            covered += data.size();
                            send_status(*h.st, id, sftp::status_code::ok, {});
                        }
                    });
                    auto wrote = co_await h.client.write_all(handle, 0, src);
                    REQUIRE_FALSE(wrote.ec);
                    co_return corral::join;
                };
                REQUIRE(seen == src);
            }());
        }
    }
}

TEST_CASE("sftp does not send an extension the peer did not advertise", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        co_await handshake(h);
        const auto before = h.st->outbox.size();
        auto renamed = co_await h.client.posix_rename("/a", "/b");
        REQUIRE(renamed.ec == std::errc::operation_not_supported);
        REQUIRE(renamed.message.empty());
        REQUIRE(h.st->outbox.size() == before);
        REQUIRE_FALSE(h.client.supports(sftp::extension::posix_rename));
    }());
}

TEST_CASE("sftp keeps the client usable when one response has the wrong type", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        co_await handshake(h);
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto id = co_await expect_request(*h.st, sftp::msg::stat);
                const auto body = encoded([&](wire::writer& w) {
                    const std::byte raw[] = {std::byte{'H'}};
                    sftp::encode_handle(w, id, raw);
                });
                send_payload(*h.st, body);
            });
            auto st = co_await h.client.stat("/tmp");
            REQUIRE(st.ec == errc::protocol_violation);
            REQUIRE(st.message.empty());
            co_return corral::join;
        };
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto id = co_await expect_request(*h.st, sftp::msg::remove);
                send_status(*h.st, id, sftp::status_code::ok, {});
            });
            auto removed = co_await h.client.remove("/ok");
            REQUIRE_FALSE(removed.ec);
            co_return corral::join;
        };
    }());
}

TEST_CASE("sftp decodes an EXTENDED_REPLY statvfs body", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        co_await handshake(h, 3, k_statvfs);
        REQUIRE(h.client.supports(sftp::extension::statvfs));
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto payload = co_await next_payload(*h.st);
                wire::reader r{payload};
                std::uint8_t type = 0;
                std::uint32_t id = 0;
                std::string_view name;
                std::string_view path;
                REQUIRE(r.read_byte(type));
                REQUIRE(type == static_cast<std::uint8_t>(sftp::msg::extended));
                REQUIRE(r.read_uint32(id));
                REQUIRE(r.read_string(name));
                REQUIRE(name == "statvfs@openssh.com");
                REQUIRE(r.read_string(path));
                REQUIRE(path == "/mnt");
                sftp::statvfs_info info;
                info.bsize = 4096;
                info.namemax = 255;
                const auto body = encoded([&](wire::writer& w) {
                    sftp::encode_statvfs_reply(w, id, info);
                    w.write_uint32(0);
                });
                send_payload(*h.st, body);
            });
            auto got = co_await h.client.statvfs("/mnt");
            REQUIRE_FALSE(got.ec);
            REQUIRE(got.value.bsize == 4096);
            REQUIRE(got.value.namemax == 255);
            REQUIRE(got.message.empty());
            co_return corral::join;
        };
    }());
}

TEST_CASE("sftp home_directory requires exactly one name", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        co_await handshake(h, 3, k_home);
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto id = co_await expect_request(*h.st, sftp::msg::extended);
                const sftp::name_entry entries[] = {{"/home/alice", "", {}}};
                const auto body = encoded([&](wire::writer& w) { sftp::encode_name(w, id, entries); });
                send_payload(*h.st, body);
            });
            auto home = co_await h.client.home_directory("alice");
            REQUIRE_FALSE(home.ec);
            REQUIRE(home.value == "/home/alice");
            co_return corral::join;
        };
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto id = co_await expect_request(*h.st, sftp::msg::extended);
                const sftp::name_entry entries[] = {{"/a", "", {}}, {"/b", "", {}}};
                const auto body = encoded([&](wire::writer& w) { sftp::encode_name(w, id, entries); });
                send_payload(*h.st, body);
            });
            auto home = co_await h.client.home_directory();
            REQUIRE(home.ec == errc::protocol_violation);
            REQUIRE(home.message.empty());
            co_return corral::join;
        };
        const auto before = h.st->outbox.size();
        auto expanded = co_await h.client.expand_path("/tmp");
        REQUIRE(expanded.ec == std::errc::operation_not_supported);
        REQUIRE(h.st->outbox.size() == before);
    }());
}

TEST_CASE("sftp expand_path returns NAME entries", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        co_await handshake(h, 3, k_expand);
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto id = co_await expect_request(*h.st, sftp::msg::extended);
                const sftp::name_entry entries[] = {{"/tmp", "", {}}};
                const auto body = encoded([&](wire::writer& w) { sftp::encode_name(w, id, entries); });
                send_payload(*h.st, body);
            });
            auto expanded = co_await h.client.expand_path("/tmp");
            REQUIRE_FALSE(expanded.ec);
            REQUIRE(expanded.value.size() == 1);
            REQUIRE(expanded.value[0].filename == "/tmp");
            co_return corral::join;
        };
    }());
}

TEST_CASE("sftp users-groups name-count mismatch is a protocol violation", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        co_await handshake(h, 3, k_users);
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto id = co_await expect_request(*h.st, sftp::msg::extended);
                const std::string_view users[] = {"root"};
                const std::string_view groups[] = {"root", "staff"};
                const auto body = encoded([&](wire::writer& w) {
                    sftp::encode_users_groups_by_id_reply(w, id, users, groups);
                });
                send_payload(*h.st, body);
            });
            const std::uint32_t uids[] = {0};
            const std::uint32_t gids[] = {0};
            auto names = co_await h.client.users_groups_by_id(uids, gids);
            REQUIRE(names.ec == errc::protocol_violation);
            REQUIRE(names.message.empty());
            co_return corral::join;
        };
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto id = co_await expect_request(*h.st, sftp::msg::remove);
                send_status(*h.st, id, sftp::status_code::ok, {});
            });
            auto removed = co_await h.client.remove("/still");
            REQUIRE_FALSE(removed.ec);
            co_return corral::join;
        };
    }());
}

TEST_CASE("sftp read_dir closes the handle on EOF and on status failure", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        co_await handshake(h);
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto opened = co_await expect_request(*h.st, sftp::msg::opendir);
                send_payload(*h.st, encoded([&](wire::writer& w) {
                    const std::byte raw[] = {std::byte{'D'}};
                    sftp::encode_handle(w, opened, raw);
                }));
                auto listed = co_await expect_request(*h.st, sftp::msg::readdir);
                const sftp::name_entry entries[] = {{"a", "a", {}}};
                send_payload(*h.st, encoded([&](wire::writer& w) {
                    sftp::encode_name(w, listed, entries);
                }));
                auto again = co_await expect_request(*h.st, sftp::msg::readdir);
                send_status(*h.st, again, sftp::status_code::eof, "end");
                auto closed = co_await expect_request(*h.st, sftp::msg::close);
                send_status(*h.st, closed, sftp::status_code::ok, {});
            });
            auto names = co_await h.client.read_dir("/d");
            REQUIRE_FALSE(names.ec);
            REQUIRE(names.value.size() == 1);
            REQUIRE(names.value[0].filename == "a");
            co_return corral::join;
        };
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto opened = co_await expect_request(*h.st, sftp::msg::opendir);
                send_payload(*h.st, encoded([&](wire::writer& w) {
                    const std::byte raw[] = {std::byte{'D'}};
                    sftp::encode_handle(w, opened, raw);
                }));
                auto listed = co_await expect_request(*h.st, sftp::msg::readdir);
                send_status(*h.st, listed, sftp::status_code::failure, "busy");
                auto closed = co_await expect_request(*h.st, sftp::msg::close);
                send_status(*h.st, closed, sftp::status_code::ok, {});
            });
            auto names = co_await h.client.read_dir("/d");
            REQUIRE(names.ec == sftp::status_code::failure);
            REQUIRE(names.message == "busy");
            co_return corral::join;
        };
    }());
}

TEST_CASE("cancelling read_dir does not send CLOSE", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        co_await handshake(h);
        corral::Event listed;
        CORRAL_WITH_NURSERY(outer) {
            outer.start([&]() -> corral::Task<void> {
                auto opened = co_await expect_request(*h.st, sftp::msg::opendir);
                send_payload(*h.st, encoded([&](wire::writer& w) {
                    const std::byte raw[] = {std::byte{'D'}};
                    sftp::encode_handle(w, opened, raw);
                }));
                auto id = co_await expect_request(*h.st, sftp::msg::readdir);
                (void)id;
                listed.trigger();
            });
            CORRAL_WITH_NURSERY(op) {
                op.start([&]() -> corral::Task<void> {
                    auto names = co_await h.client.read_dir("/d");
                    (void)names;
                });
                co_await listed;
                co_return corral::cancel;
            };
            co_return corral::join;
        };
        REQUIRE(h.st->outbox.empty());
    }());
}

TEST_CASE("sftp symlink uses the OpenSSH target-then-link order", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        co_await handshake(h);
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto payload = co_await next_payload(*h.st);
                REQUIRE(sftp::packet_type(payload) == sftp::msg::symlink);
                wire::reader r{std::span<const std::byte>(payload).subspan(5)};
                std::string_view first;
                std::string_view second;
                REQUIRE(r.read_string(first));
                REQUIRE(r.read_string(second));
                REQUIRE(first == "target");
                REQUIRE(second == "link");
                std::uint32_t id = 0;
                REQUIRE(sftp::packet_request_id(payload, id));
                send_status(*h.st, id, sftp::status_code::ok, {});
            });
            auto linked = co_await h.client.symlink("target", "link");
            REQUIRE_FALSE(linked.ec);
            co_return corral::join;
        };
    }());
}

TEST_CASE("sftp keeps an unknown status code in error_code::value", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        co_await handshake(h);
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto id = co_await expect_request(*h.st, sftp::msg::remove);
                const auto body = encoded([&](wire::writer& w) {
                    w.write_byte(static_cast<std::uint8_t>(sftp::msg::status));
                    w.write_uint32(id);
                    w.write_uint32(42);
                    w.write_string("odd");
                    w.write_string("en");
                });
                send_payload(*h.st, body);
            });
            auto removed = co_await h.client.remove("/x");
            REQUIRE(removed.ec.value() == 42);
            REQUIRE(removed.ec.category() == sftp::error_category());
            REQUIRE(removed.message == "odd");
            co_return corral::join;
        };
    }());
}

TEST_CASE("sftp handshake survives a failed limits query", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                co_await expect_init(*h.st);
                send_version(*h.st, 3, k_limits);
                auto id = co_await expect_request(*h.st, sftp::msg::extended);
                send_status(*h.st, id, sftp::status_code::op_unsupported, "no");
            });
            auto started = co_await h.client.start();
            REQUIRE_FALSE(started);
            co_return corral::join;
        };
        REQUIRE(h.client.supports(sftp::extension::limits));
        REQUIRE(h.client.limits().max_write_length == sftp::fallback_io_length);
    }());
}

TEST_CASE("sftp latches a client-direction packet and a truncated id", "[sftp][client]") {
    harness h;
    corral::run(h.loop, [&]() -> corral::Task<void> {
        co_await handshake(h);
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto id = co_await expect_request(*h.st, sftp::msg::stat);
                (void)id;
                const auto body = encoded([&](wire::writer& w) {
                    w.write_byte(static_cast<std::uint8_t>(sftp::msg::open));
                    w.write_uint32(1);
                });
                send_payload(*h.st, body);
            });
            auto st = co_await h.client.stat("/tmp");
            REQUIRE(st.ec == errc::protocol_violation);
            auto again = co_await h.client.remove("/tmp");
            REQUIRE(again.ec == st.ec);
            co_return corral::join;
        };
    }());

    harness short_id;
    corral::run(short_id.loop, [&]() -> corral::Task<void> {
        co_await handshake(short_id);
        CORRAL_WITH_NURSERY(n) {
            n.start([&]() -> corral::Task<void> {
                auto id = co_await expect_request(*short_id.st, sftp::msg::stat);
                (void)id;
                feed(*short_id.st, frame(std::vector<std::byte>{std::byte{101}}));
            });
            auto st = co_await short_id.client.stat("/tmp");
            REQUIRE(st.ec == errc::malformed_input);
            auto again = co_await short_id.client.stat("/tmp");
            REQUIRE(again.ec == st.ec);
            co_return corral::join;
        };
    }());
}

TEST_CASE("sftp drains channel stderr before the stdout window stalls", "[sftp][channel]") {
    client_options co;
    co.initial_window = 16;
    auto fp = make_facade_pair(std::move(co), {});
    auto accept_host = [](host_key_view) -> corral::Task<bool> { co_return true; };
    auto dummy_global = [](inbound_global_request) -> corral::Task<void> { co_return; };

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &fp.client);
            co_await n.start(&server_session::run, &fp.server);
            auto [cec, sec] = co_await corral::allOf(fp.client.handshake(accept_host), fp.server.handshake());
            REQUIRE_FALSE(cec);
            REQUIRE_FALSE(sec);
            auto [aec, auth] = co_await corral::allOf(
                fp.client.auth_password("alice", "s3cret"),
                fp.server.authenticate([](auth_request req) -> corral::Task<auth_verdict> {
                    if (req.method() == "password" && req.user() == "alice" && req.password() == "s3cret") {
                        co_return auth_verdict::success();
                    }
                    co_return auth_verdict::failure("password");
                }));
            REQUIRE_FALSE(std::get<0>(aec));
            REQUIRE(std::get<1>(aec).success);
            REQUIRE_FALSE(auth);

            std::vector<std::byte> version = frame(encoded([&](wire::writer& w) {
                sftp::encode_version(w, 3);
            }));
            corral::Event serving;
            n.start([&]() -> corral::Task<void> {
                serving.trigger();
                co_await fp.server.serve(
                    [&](inbound_channel_open open) -> corral::Task<void> {
                        channel ch = open.accept();
                        char junk[16];
                        std::memset(junk, 'E', sizeof junk);
                        auv::buffer err{junk, sizeof junk};
                        auto wrote_err = co_await ch.write_stderr(&err, 1);
                        REQUIRE_FALSE(wrote_err);
                        auv::buffer out{reinterpret_cast<char*>(version.data()), version.size()};
                        auto wrote = co_await ch.write(&out, 1);
                        REQUIRE_FALSE(wrote);
                    },
                    dummy_global);
            });
            co_await serving;
            auto opened = co_await fp.client.open_session_channel();
            REQUIRE_FALSE(opened.ec);
            sftp_options opts;
            opts.query_limits = false;
            basic_sftp_client<channel> sftp(std::move(opened.ch), opts);
            auto started = co_await sftp.start();
            REQUIRE_FALSE(started);
            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}


TEST_CASE("sftp cancels a channel request whose reply never arrives", "[sftp][channel]") {
    auto fp = make_facade_pair({}, {});
    auto accept_host = [](host_key_view) -> corral::Task<bool> { co_return true; };
    auto dummy_global = [](inbound_global_request) -> corral::Task<void> { co_return; };

    corral::run(fp.loop, [&]() -> corral::Task<void> {
        CORRAL_WITH_NURSERY(n) {
            co_await n.start(&client_session::run, &fp.client);
            co_await n.start(&server_session::run, &fp.server);
            auto [cec, sec] = co_await corral::allOf(fp.client.handshake(accept_host), fp.server.handshake());
            REQUIRE_FALSE(cec);
            REQUIRE_FALSE(sec);
            auto [aec, auth] = co_await corral::allOf(
                fp.client.auth_password("alice", "s3cret"),
                fp.server.authenticate([](auth_request req) -> corral::Task<auth_verdict> {
                    if (req.method() == "password" && req.user() == "alice" && req.password() == "s3cret") {
                        co_return auth_verdict::success();
                    }
                    co_return auth_verdict::failure("password");
                }));
            REQUIRE_FALSE(std::get<0>(aec));
            REQUIRE(std::get<1>(aec).success);
            REQUIRE_FALSE(auth);

            std::vector<std::byte> version = frame(encoded([&](wire::writer& w) {
                sftp::encode_version(w, 3);
            }));
            const auto init_len = frame(encoded([&](wire::writer& w) { sftp::encode_init(w); })).size();
            const auto stat_len = frame(encoded([&](wire::writer& w) {
                sftp::encode_path_request(w, sftp::msg::stat, 0, "/hang");
            })).size();
            corral::Event serving;
            corral::Event request_seen;
            bool server_reading = true;
            n.start([&]() -> corral::Task<void> {
                serving.trigger();
                co_await fp.server.serve(
                    [&](inbound_channel_open open) -> corral::Task<void> {
                        channel ch = open.accept();
                        auv::buffer out{reinterpret_cast<char*>(version.data()), version.size()};
                        auto wrote = co_await ch.write(&out, 1);
                        REQUIRE_FALSE(wrote);
                        char buf[256];
                        auv::buffer in{buf, sizeof buf};
                        std::size_t seen = 0;
                        for (;;) {
                            auto [ec, got] = co_await ch.read(
                                [](void* p) { return *static_cast<auv::buffer*>(p); }, &in);
                            if (ec) {
                                server_reading = false;
                                co_return;
                            }
                            seen += got;
                            if (seen >= init_len + stat_len) request_seen.trigger();
                        }
                    },
                    dummy_global);
            });
            co_await serving;
            auto opened = co_await fp.client.open_session_channel();
            REQUIRE_FALSE(opened.ec);
            sftp_options opts;
            opts.query_limits = false;
            basic_sftp_client<channel> sftp(std::move(opened.ch), opts);
            auto started = co_await sftp.start();
            REQUIRE_FALSE(started);
            CORRAL_WITH_NURSERY(op) {
                op.start([&]() -> corral::Task<void> { (void)co_await sftp.stat("/hang"); });
                co_await request_seen;
                co_return corral::cancel;
            };
            REQUIRE(server_reading);
            co_await fp.client.disconnect(disconnect_reason::by_application, "done");
            co_return corral::cancel;
        };
    }());
}
