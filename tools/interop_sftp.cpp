// OpenSSH SFTP interop. POSIX poll drives the coroutine facade; this tool does
// not link libuv (CI's interop job does not bootstrap it).
#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/keys/io.hpp>
#include <yanterm-ssh/sftp.hpp>

#include <corral/defs.h>
#include <corral/run.h>

#include <openssl/evp.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <grp.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

using namespace yanterm::ssh;

namespace sftp_interop {

constexpr std::size_t k_payload = 512u * 1024u + 1u;
constexpr int k_poll_timeout_ms = 60000;

struct options {
    std::string host = "127.0.0.1";
    int port = 22;
    std::string user;
    std::string identity;
    std::string workdir;
};

void usage(const char* argv0) {
    std::cerr << "Usage: " << argv0
              << " --host HOST --port PORT --user USER --identity PATH --workdir PATH\n";
}

bool parse_args(int argc, char** argv, options& opt) {
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto need = [&](std::string& dest) {
            if (i + 1 >= argc) return false;
            dest = argv[++i];
            return true;
        };
        if (a == "--host") {
            if (!need(opt.host)) return false;
        } else if (a == "--port") {
            std::string v;
            if (!need(v)) return false;
            opt.port = std::stoi(v);
        } else if (a == "--user") {
            if (!need(opt.user)) return false;
        } else if (a == "--identity") {
            if (!need(opt.identity)) return false;
        } else if (a == "--workdir") {
            if (!need(opt.workdir)) return false;
        } else if (a == "--help" || a == "-h") {
            usage(argv[0]);
            std::exit(0);
        } else {
            std::cerr << "unknown arg: " << a << '\n';
            return false;
        }
    }
    return !opt.user.empty() && !opt.identity.empty() && !opt.workdir.empty() && opt.port > 0;
}

struct sock_state {
    int fd = -1;
    bool want_read = false;
    bool want_write = false;
    bool timed_out = false;
    corral::ParkingLot read_lot;
    corral::ParkingLot write_lot;
};

struct poll_loop {
    sock_state* sock = nullptr;
    bool running_ = false;
    bool stopped_ = false;

    void stop() noexcept { stopped_ = true; }
    [[nodiscard]] bool running() const noexcept { return running_; }

    void run() {
        running_ = true;
        stopped_ = false;
        while (!stopped_) {
            // Resumed tasks schedule through the runner executor. Drain before
            // blocking so a completion that already queued stop() is observed.
            if (auto* ex = corral::currentRunExecutor()) ex->drain();
            if (stopped_) break;
            if (sock == nullptr || sock->fd < 0 || (!sock->want_read && !sock->want_write)) {
                std::cerr << "sftp interop: event loop idle with no socket interest\n";
                break;
            }
            pollfd pfd{};
            pfd.fd = sock->fd;
            if (sock->want_read) pfd.events = static_cast<short>(pfd.events | POLLIN);
            if (sock->want_write) pfd.events = static_cast<short>(pfd.events | POLLOUT);
            int rc = 0;
            do {
                rc = ::poll(&pfd, 1, k_poll_timeout_ms);
            } while (rc < 0 && errno == EINTR);
            if (stopped_) break;
            if (rc < 0) {
                std::cerr << "sftp interop: poll failed: " << std::strerror(errno) << '\n';
                break;
            }
            if (rc == 0) {
                std::cerr << "sftp interop: poll timed out\n";
                sock->timed_out = true;
                sock->read_lot.unparkAll();
                sock->write_lot.unparkAll();
                continue;
            }
            const bool bad = (pfd.revents & (POLLERR | POLLNVAL)) != 0;
            const bool readable = bad || (pfd.revents & (POLLIN | POLLHUP)) != 0;
            const bool writable = bad || (pfd.revents & POLLOUT) != 0;
            // unpark resumes inline. With no executor drain in progress,
            // runSoon() runs immediately, so the root task's stop() lands here.
            if (readable && sock->want_read) sock->read_lot.unparkAll();
            if (writable && sock->want_write) sock->write_lot.unparkAll();
        }
        running_ = false;
    }
};

class tcp_stream {
public:
    tcp_stream(poll_loop& loop, int fd) : loop_(&loop), st_(std::make_unique<sock_state>()) {
        st_->fd = fd;
        loop_->sock = st_.get();
    }

    tcp_stream(const tcp_stream&) = delete;
    tcp_stream& operator=(const tcp_stream&) = delete;

    tcp_stream(tcp_stream&& other) noexcept : loop_(other.loop_), st_(std::move(other.st_)) {
        other.loop_ = nullptr;
    }

    tcp_stream& operator=(tcp_stream&&) = delete;

    ~tcp_stream() { close_fd(); }

    corral::Task<auv::read_result> read(auv::read_allocator alloc_cb, void* alloc_arg) {
        if (!st_ || st_->fd < 0) co_return {auv::make_error_code(auv::errc::eof), 0};
        for (;;) {
            if (st_->timed_out) co_return {std::make_error_code(std::errc::timed_out), 0};
            auv::buffer buf = alloc_cb(alloc_arg);
            if (buf.data() == nullptr || buf.size() == 0) {
                co_return {std::make_error_code(std::errc::no_buffer_space), 0};
            }
            const ssize_t n = ::recv(st_->fd, buf.data(), buf.size(), 0);
            if (n > 0) co_return {std::error_code{}, static_cast<std::size_t>(n)};
            if (n == 0) co_return {auv::make_error_code(auv::errc::eof), 0};
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                st_->want_read = true;
                co_await st_->read_lot.park();
                st_->want_read = false;
                if (!st_ || st_->fd < 0) co_return {auv::make_error_code(auv::errc::eof), 0};
                continue;
            }
            co_return {std::error_code{errno, std::generic_category()}, 0};
        }
    }

    corral::Task<std::error_code> write(const auv::buffer* bufs, std::size_t nbufs) {
        if (!st_ || st_->fd < 0) co_return std::make_error_code(std::errc::not_connected);
        for (std::size_t i = 0; i < nbufs; ++i) {
            const auto* data = reinterpret_cast<const char*>(bufs[i].data());
            std::size_t left = bufs[i].size();
            while (left > 0) {
                if (st_->timed_out) co_return std::make_error_code(std::errc::timed_out);
                const ssize_t n = ::send(st_->fd, data, left, MSG_NOSIGNAL);
                if (n > 0) {
                    data += n;
                    left -= static_cast<std::size_t>(n);
                    continue;
                }
                if (n < 0 && errno == EINTR) continue;
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    st_->want_write = true;
                    co_await st_->write_lot.park();
                    st_->want_write = false;
                    if (!st_ || st_->fd < 0) co_return std::make_error_code(std::errc::not_connected);
                    continue;
                }
                const int err = n < 0 ? errno : EPIPE;
                co_return std::error_code{err, std::generic_category()};
            }
        }
        co_return std::error_code{};
    }

    corral::Task<std::error_code> shutdown() {
        if (st_ && st_->fd >= 0) ::shutdown(st_->fd, SHUT_WR);
        co_return std::error_code{};
    }

    corral::Task<void> close() {
        close_fd();
        co_return;
    }

    explicit operator auv::stream() && {
        auto owner = auv::detail::lifetime_owner::emplace<tcp_stream>(
            std::pmr::get_default_resource(), std::move(*this));
        tcp_stream* self = owner.get<tcp_stream>();
        return auv::stream::construct(self, auv::detail::stream_model<tcp_stream>::vtable(),
                                      std::move(owner));
    }

private:
    void close_fd() noexcept {
        if (!st_) return;
        if (loop_ != nullptr && loop_->sock == st_.get()) loop_->sock = nullptr;
        if (st_->fd >= 0) {
            ::close(st_->fd);
            st_->fd = -1;
        }
        st_->want_read = false;
        st_->want_write = false;
        st_->read_lot.unparkAll();
        st_->write_lot.unparkAll();
    }

    poll_loop* loop_ = nullptr;
    std::unique_ptr<sock_state> st_;
};

static_assert(auv::detail::stream_like<tcp_stream>);

int connect_tcp(const std::string& host, int port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    const int flags = ::fcntl(fd, F_GETFL, 0);
    if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        ::close(fd);
        return -1;
    }
    const int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<std::uint16_t>(port));
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        ::close(fd);
        return -1;
    }
    const int cr = ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (cr != 0 && errno != EINPROGRESS) {
        ::close(fd);
        return -1;
    }
    if (cr != 0) {
        pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLOUT;
        const int pr = ::poll(&pfd, 1, 5000);
        int soerr = 0;
        socklen_t sl = sizeof(soerr);
        if (pr <= 0 || ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) < 0 || soerr != 0) {
            ::close(fd);
            return -1;
        }
    }
    return fd;
}

void pass(const char* step) { std::cout << "sftp_ok " << step << std::endl; }

void skip(const char* name) { std::cout << "skip " << name << std::endl; }

template <class T>
bool failed(const char* step, const sftp::result<T>& r) {
    if (!r.ec) return false;
    std::cerr << "FAIL " << step << " " << r.ec.category().name() << ":" << r.ec.value() << " "
              << r.ec.message();
    if (!r.message.empty()) std::cerr << " (" << r.message << ")";
    std::cerr << std::endl;
    return true;
}

std::string hex_of(const unsigned char* p, std::size_t n) {
    static constexpr char k[] = "0123456789abcdef";
    std::string s(n * 2, '0');
    for (std::size_t i = 0; i < n; ++i) {
        s[i * 2] = k[p[i] >> 4];
        s[i * 2 + 1] = k[p[i] & 0x0f];
    }
    return s;
}

bool sha256(std::span<const std::byte> data, unsigned char out[32]) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr) return false;
    const bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1
        && EVP_DigestUpdate(ctx, data.data(), data.size()) == 1
        && EVP_DigestFinal_ex(ctx, out, nullptr) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}

std::string join_path(std::string_view dir, std::string_view name) {
    std::string out;
    out.reserve(dir.size() + 1 + name.size());
    out.append(dir);
    out.push_back('/');
    out.append(name);
    return out;
}

corral::Task<int> exercise(client_session& sess, std::string user, const keys::private_key& key,
                           std::string workdir) {
    if (auto ec = co_await sess.handshake([](const host_key_view&) -> corral::Task<bool> {
            co_return true;
        })) {
        std::cerr << "FAIL handshake " << ec.message() << std::endl;
        co_return 1;
    }
    auto [aec, auth] = co_await sess.auth_publickey(user, key);
    if (aec || !auth.success) {
        std::cerr << "FAIL auth " << aec.message() << std::endl;
        co_return 1;
    }

    auto opened = co_await open_sftp(sess);
    if (std::get<0>(opened) || !std::get<1>(opened)) {
        std::cerr << "FAIL handshake " << std::get<0>(opened).message() << std::endl;
        co_return 1;
    }
    auto client = std::move(std::get<1>(opened));
    pass("handshake");

    const std::string dir = join_path(workdir, "d");
    const std::string blob = join_path(dir, "blob");
    const std::string blob2 = join_path(dir, "blob2");
    const std::string link = join_path(dir, "link");
    auto made = co_await client->mkdir(dir);
    if (failed("mkdir", made)) co_return 1;
    auto listed = co_await client->read_dir(dir);
    if (failed("read_dir", listed)) co_return 1;
    pass("mkdir");

    std::vector<std::byte> payload(k_payload);
    for (std::size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<std::byte>(static_cast<unsigned>(i * 131u + 17u) & 0xffu);
    }
    auto wr = co_await client->open(blob, sftp::open_flags::write | sftp::open_flags::creat
                                             | sftp::open_flags::trunc);
    if (failed("open", wr)) co_return 1;
    auto wrote = co_await client->write_all(wr.value, 0, payload);
    if (failed("write_all", wrote)) co_return 1;
    if (client->supports(sftp::extension::fsync)) {
        auto synced = co_await client->fsync(wr.value);
        if (failed("fsync", synced)) co_return 1;
        pass("fsync");
    } else {
        skip("fsync@openssh.com");
    }
    auto closed = co_await client->close(wr.value);
    if (failed("close", closed)) co_return 1;

    auto rd = co_await client->open(blob, sftp::open_flags::read);
    if (failed("open", rd)) co_return 1;
    std::vector<std::byte> got(payload.size());
    auto nread = co_await client->read_all(rd.value, 0, got);
    if (failed("read_all", nread)) co_return 1;
    closed = co_await client->close(rd.value);
    if (failed("close", closed)) co_return 1;
    if (nread.value != payload.size() || got != payload) {
        unsigned char expect_dig[32]{};
        unsigned char got_dig[32]{};
        const auto got_span = std::span<const std::byte>(got.data(), std::min(got.size(), nread.value));
        if (!sha256(payload, expect_dig) || !sha256(got_span, got_dig)) {
            std::cerr << "FAIL upload sha256\n";
            co_return 1;
        }
        std::cerr << "FAIL upload size=" << nread.value << " expect=" << payload.size()
                  << " sha256=" << hex_of(got_dig, 32) << " expect_sha256=" << hex_of(expect_dig, 32)
                  << std::endl;
        co_return 1;
    }
    unsigned char dig[32]{};
    if (!sha256(got, dig)) {
        std::cerr << "FAIL upload sha256\n";
        co_return 1;
    }
    std::cout << "sftp_ok upload sha256=" << hex_of(dig, 32) << std::endl;

    auto st = co_await client->stat(blob);
    if (failed("stat", st)) co_return 1;
    if ((st.value.flags & sftp::attr_flags::size) == 0 || st.value.size != payload.size()) {
        std::cerr << "FAIL stat size\n";
        co_return 1;
    }
    auto lst = co_await client->lstat(blob);
    if (failed("lstat", lst)) co_return 1;
    if ((lst.value.flags & sftp::attr_flags::size) == 0 || lst.value.size != payload.size()) {
        std::cerr << "FAIL lstat size\n";
        co_return 1;
    }
    sftp::attrs mode;
    mode.flags = sftp::attr_flags::permissions;
    mode.permissions = 0644;
    auto set = co_await client->setstat(blob, mode);
    if (failed("setstat", set)) co_return 1;
    st = co_await client->stat(blob);
    if (failed("stat", st)) co_return 1;
    if ((st.value.flags & sftp::attr_flags::permissions) == 0
        || (st.value.permissions & 0777) != 0644) {
        std::cerr << "FAIL stat mode\n";
        co_return 1;
    }
    pass("stat");

    auto linked = co_await client->symlink("blob", link);
    if (failed("symlink", linked)) co_return 1;
    auto target = co_await client->readlink(link);
    if (failed("readlink", target)) co_return 1;
    if (target.value.size() != 1 || target.value.front().filename != "blob") {
        std::cerr << "FAIL readlink\n";
        co_return 1;
    }
    lst = co_await client->lstat(link);
    if (failed("lstat", lst)) co_return 1;
    if ((lst.value.flags & sftp::attr_flags::permissions) == 0
        || (lst.value.permissions & S_IFMT) != S_IFLNK) {
        std::cerr << "FAIL lstat symlink\n";
        co_return 1;
    }
    pass("symlink");

    auto renamed = co_await client->rename(blob, blob2);
    if (failed("rename", renamed)) co_return 1;
    pass("rename");

    std::string data_path = blob2;
    std::vector<std::string> extra_files;
    if (client->supports(sftp::extension::posix_rename)) {
        const std::string other = join_path(dir, "other");
        auto placeholder = co_await client->open(
            other, sftp::open_flags::write | sftp::open_flags::creat | sftp::open_flags::trunc);
        if (failed("posix_rename", placeholder)) co_return 1;
        const std::byte byte{std::byte{'x'}};
        auto tiny = co_await client->write(placeholder.value, 0, std::span<const std::byte>(&byte, 1));
        if (failed("posix_rename", tiny)) co_return 1;
        closed = co_await client->close(placeholder.value);
        if (failed("posix_rename", closed)) co_return 1;
        auto moved = co_await client->posix_rename(blob2, other);
        if (failed("posix_rename", moved)) co_return 1;
        data_path = other;
        pass("posix-rename@openssh.com");
    } else {
        skip("posix-rename@openssh.com");
    }

    if (client->supports(sftp::extension::statvfs)) {
        auto vfs = co_await client->statvfs(dir);
        if (failed("statvfs", vfs)) co_return 1;
        if (vfs.value.bsize == 0 || vfs.value.namemax == 0) {
            std::cerr << "FAIL statvfs\n";
            co_return 1;
        }
        pass("statvfs@openssh.com");
    } else {
        skip("statvfs@openssh.com");
    }

    if (client->supports(sftp::extension::fstatvfs)) {
        auto handle = co_await client->open(data_path, sftp::open_flags::read);
        if (failed("fstatvfs", handle)) co_return 1;
        auto vfs = co_await client->fstatvfs(handle.value);
        if (failed("fstatvfs", vfs)) co_return 1;
        closed = co_await client->close(handle.value);
        if (failed("fstatvfs", closed)) co_return 1;
        if (vfs.value.bsize == 0) {
            std::cerr << "FAIL fstatvfs\n";
            co_return 1;
        }
        pass("fstatvfs@openssh.com");
    } else {
        skip("fstatvfs@openssh.com");
    }

    if (client->supports(sftp::extension::hardlink)) {
        const std::string hl = data_path + ".hl";
        auto hard = co_await client->hardlink(data_path, hl);
        if (failed("hardlink", hard)) co_return 1;
        extra_files.push_back(hl);
        pass("hardlink@openssh.com");
    } else {
        skip("hardlink@openssh.com");
    }

    if (client->supports(sftp::extension::lsetstat)) {
        sftp::attrs times;
        times.flags = sftp::attr_flags::acmodtime;
        times.atime = 1;
        times.mtime = 2;
        auto stamped = co_await client->lsetstat(link, times);
        if (failed("lsetstat", stamped)) co_return 1;
        lst = co_await client->lstat(link);
        if (failed("lsetstat", lst)) co_return 1;
        if ((lst.value.flags & sftp::attr_flags::acmodtime) == 0 || lst.value.mtime != 2) {
            std::cerr << "FAIL lsetstat mtime\n";
            co_return 1;
        }
        pass("lsetstat@openssh.com");
    } else {
        skip("lsetstat@openssh.com");
    }

    if (client->supports(sftp::extension::limits)) {
        auto lim = co_await client->query_limits();
        if (failed("limits", lim)) co_return 1;
        if (lim.value.max_packet_length == 0) {
            std::cerr << "FAIL limits\n";
            co_return 1;
        }
        pass("limits@openssh.com");
    } else {
        skip("limits@openssh.com");
    }

    if (client->supports(sftp::extension::expand_path)) {
        auto expanded = co_await client->expand_path(dir);
        if (failed("expand_path", expanded)) co_return 1;
        if (expanded.value.empty() || expanded.value.front().filename.empty()) {
            std::cerr << "FAIL expand_path\n";
            co_return 1;
        }
        pass("expand-path@openssh.com");
    } else {
        skip("expand-path@openssh.com");
    }

    if (client->supports(sftp::extension::copy_data)) {
        const std::string copy = join_path(dir, "copy");
        auto src = co_await client->open(data_path, sftp::open_flags::read);
        if (failed("copy_data", src)) co_return 1;
        auto dst = co_await client->open(
            copy, sftp::open_flags::write | sftp::open_flags::creat | sftp::open_flags::trunc);
        if (failed("copy_data", dst)) co_return 1;
        auto copied = co_await client->copy_data(src.value, 0, 0, dst.value, 0);
        if (failed("copy_data", copied)) co_return 1;
        closed = co_await client->close(src.value);
        if (failed("copy_data", closed)) co_return 1;
        closed = co_await client->close(dst.value);
        if (failed("copy_data", closed)) co_return 1;
        st = co_await client->stat(copy);
        if (failed("copy_data", st)) co_return 1;
        if ((st.value.flags & sftp::attr_flags::size) == 0 || st.value.size != payload.size()) {
            std::cerr << "FAIL copy_data size\n";
            co_return 1;
        }
        extra_files.push_back(copy);
        pass("copy-data");
    } else {
        skip("copy-data");
    }

    if (client->supports(sftp::extension::home_directory)) {
        // OpenSSH 9.6 resolves only the username string; 10.x also treats
        // an empty name as the logged-in user. Pass the account we authenticated.
        auto home = co_await client->home_directory(user);
        if (failed("home_directory", home)) co_return 1;
        if (home.value.empty()) {
            std::cerr << "FAIL home_directory\n";
            co_return 1;
        }
        if (const passwd* pw = ::getpwuid(::getuid())) {
            if (home.value != pw->pw_dir) {
                std::cerr << "FAIL home_directory got=" << home.value << " expect=" << pw->pw_dir
                          << std::endl;
                co_return 1;
            }
        }
        pass("home-directory");
    } else {
        skip("home-directory");
    }

    if (client->supports(sftp::extension::users_groups_by_id)) {
        const std::uint32_t uid = static_cast<std::uint32_t>(::getuid());
        const std::uint32_t gid = static_cast<std::uint32_t>(::getgid());
        auto names = co_await client->users_groups_by_id(std::span<const std::uint32_t>(&uid, 1),
                                                         std::span<const std::uint32_t>(&gid, 1));
        if (failed("users_groups_by_id", names)) co_return 1;
        if (names.value.users.size() != 1 || names.value.groups.size() != 1
            || names.value.users.front().empty() || names.value.groups.front().empty()) {
            std::cerr << "FAIL users_groups_by_id\n";
            co_return 1;
        }
        if (const passwd* pw = ::getpwuid(uid)) {
            if (names.value.users.front() != pw->pw_name) {
                std::cerr << "FAIL users_groups_by_id user\n";
                co_return 1;
            }
        }
        if (const group* gr = ::getgrgid(gid)) {
            if (names.value.groups.front() != gr->gr_name) {
                std::cerr << "FAIL users_groups_by_id group\n";
                co_return 1;
            }
        }
        pass("users-groups-by-id@openssh.com");
    } else {
        skip("users-groups-by-id@openssh.com");
    }

    for (const auto& path : extra_files) {
        auto rm = co_await client->remove(path);
        if (failed("remove", rm)) co_return 1;
    }
    auto rm = co_await client->remove(data_path);
    if (failed("remove", rm)) co_return 1;
    rm = co_await client->remove(link);
    if (failed("remove", rm)) co_return 1;
    auto rdrm = co_await client->rmdir(dir);
    if (failed("rmdir", rdrm)) co_return 1;
    pass("remove");
    co_return 0;
}

corral::Task<int> session_main(client_session& sess, std::string user, const keys::private_key& key,
                               std::string workdir) {
    int rc = 1;
    co_await run_with(sess, [&]() -> corral::Task<void> {
        rc = co_await exercise(sess, std::move(user), key, std::move(workdir));
    });
    co_return rc;
}

}  // namespace sftp_interop

namespace corral {
template <>
struct EventLoopTraits<sftp_interop::poll_loop> {
    static EventLoopID eventLoopID(sftp_interop::poll_loop& loop) { return EventLoopID(&loop); }
    static void run(sftp_interop::poll_loop& loop) { loop.run(); }
    static void stop(sftp_interop::poll_loop& loop) { loop.stop(); }
    static bool isRunning(sftp_interop::poll_loop& loop) noexcept { return loop.running(); }
};
}  // namespace corral

int main(int argc, char** argv) {
    using namespace sftp_interop;
    std::signal(SIGPIPE, SIG_IGN);
    options opt;
    try {
        if (!parse_args(argc, argv, opt)) {
            usage(argv[0]);
            return 2;
        }
    } catch (const std::exception& ex) {
        std::cerr << ex.what() << '\n';
        return 2;
    }

    crypto::openssl_backend backend;
    const auto provider = crypto::provider::wrap(backend);
    keys::private_key key;
    if (auto ec = keys::io::load_private_key(opt.identity.c_str(), provider, {}, key)) {
        std::cerr << "FAIL identity " << ec.message() << std::endl;
        return 1;
    }

    const int fd = connect_tcp(opt.host, opt.port);
    if (fd < 0) {
        std::cerr << "FAIL connect\n";
        return 1;
    }

    poll_loop loop;
    tcp_stream sock(loop, fd);
    client_options copts;
    copts.preferred_kex = "curve25519-sha256";
    copts.preferred_host_key = "ssh-ed25519";
    copts.preferred_cipher = "chacha20-poly1305@openssh.com";
    copts.preferred_mac = "hmac-sha2-256-etm@openssh.com";
    client_session sess(static_cast<auv::stream>(std::move(sock)), provider, std::move(copts));
    return corral::run(loop, session_main(sess, opt.user, key, opt.workdir));
}
