#pragma once

#include <yanterm-ssh/keys/io.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/keys/impl/io.ipp is an implementation file, not a public header."
#endif

#include <yanterm-ssh/detail/error.hpp>

#include <cerrno>
#include <string>
#include <utility>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#else
#include <filesystem>
#include <fstream>
#endif

namespace yanterm::ssh::keys::io {

#ifndef _WIN32

namespace detail {

struct unique_fd {
    int fd = -1;

    unique_fd() = default;
    explicit unique_fd(int f) noexcept : fd(f) {}
    ~unique_fd() { reset(); }

    unique_fd(const unique_fd&) = delete;
    unique_fd& operator=(const unique_fd&) = delete;

    unique_fd(unique_fd&& o) noexcept : fd(o.fd) { o.fd = -1; }
    unique_fd& operator=(unique_fd&& o) noexcept {
        if (this != &o) {
            reset();
            fd = o.fd;
            o.fd = -1;
        }
        return *this;
    }

    void reset() noexcept {
        if (fd >= 0) {
            ::close(fd);
            fd = -1;
        }
    }

    [[nodiscard]] int get() const noexcept { return fd; }
};

[[nodiscard]] YANTERM_SSH_INLINE std::error_code last_sys_error() noexcept {
    return {errno, std::system_category()};
}

[[nodiscard]] YANTERM_SSH_INLINE bool invalid_path(const char* path) noexcept {
    return path == nullptr || path[0] == '\0';
}

YANTERM_SSH_INLINE std::error_code write_all(int fd, std::span<const std::byte> data) {
    std::size_t off = 0;
    while (off < data.size()) {
        const ssize_t n = ::write(fd, data.data() + off, data.size() - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return last_sys_error();
        }
        if (n == 0) return std::make_error_code(std::errc::io_error);
        off += static_cast<std::size_t>(n);
    }
    return {};
}

YANTERM_SSH_INLINE std::error_code read_all(int fd, std::span<std::byte> data) {
    std::size_t off = 0;
    while (off < data.size()) {
        const ssize_t n = ::read(fd, data.data() + off, data.size() - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return last_sys_error();
        }
        if (n == 0) return std::make_error_code(std::errc::io_error);
        off += static_cast<std::size_t>(n);
    }
    return {};
}

YANTERM_SSH_INLINE std::error_code fsync_retry(int fd) {
    while (::fsync(fd) != 0) {
        if (errno == EINTR) continue;
        return last_sys_error();
    }
    return {};
}

}  // namespace detail

YANTERM_SSH_INLINE std::error_code read_file(const char* path, std::vector<std::byte>& out) {
    if (detail::invalid_path(path)) return std::make_error_code(std::errc::invalid_argument);
    detail::unique_fd fd{::open(path, O_RDONLY | O_CLOEXEC)};
    if (fd.get() < 0) return detail::last_sys_error();

    struct stat st {};
    if (::fstat(fd.get(), &st) != 0) return detail::last_sys_error();
    if (!S_ISREG(st.st_mode) || st.st_size < 0) {
        return std::make_error_code(std::errc::invalid_argument);
    }

    std::vector<std::byte> buf(static_cast<std::size_t>(st.st_size));
    if (auto ec = detail::read_all(fd.get(), buf)) return ec;
    out = std::move(buf);
    return {};
}

YANTERM_SSH_INLINE std::error_code check_private_key_permissions(const char* path) {
    if (detail::invalid_path(path)) return std::make_error_code(std::errc::invalid_argument);
    struct stat st {};
    if (::stat(path, &st) != 0) return detail::last_sys_error();
    if ((st.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        return code::insecure_permissions;
    }
    return {};
}

YANTERM_SSH_INLINE std::error_code atomic_write(const char* path, std::span<const std::byte> data) {
    if (detail::invalid_path(path)) return std::make_error_code(std::errc::invalid_argument);
    const std::string tmp = std::string{path} + ".tmp";
    detail::unique_fd fd{::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644)};
    if (fd.get() < 0) return detail::last_sys_error();
    if (auto ec = detail::write_all(fd.get(), data)) {
        ::unlink(tmp.c_str());
        return ec;
    }
    if (auto ec = detail::fsync_retry(fd.get())) {
        ::unlink(tmp.c_str());
        return ec;
    }
    fd.reset();
    if (::rename(tmp.c_str(), path) != 0) {
        const auto ec = detail::last_sys_error();
        ::unlink(tmp.c_str());
        return ec;
    }
    return {};
}

#else  // _WIN32

YANTERM_SSH_INLINE std::error_code check_private_key_permissions(const char* /*path*/) {
    return {};
}

YANTERM_SSH_INLINE std::error_code read_file(const char* path, std::vector<std::byte>& out) {
    if (path == nullptr || path[0] == '\0') {
        return std::make_error_code(std::errc::invalid_argument);
    }
    std::ifstream in{path, std::ios::binary};
    if (!in) return std::make_error_code(std::errc::io_error);
    in.seekg(0, std::ios::end);
    const auto n = static_cast<std::size_t>(in.tellg());
    in.seekg(0, std::ios::beg);
    std::vector<std::byte> buf(n);
    if (n > 0) {
        in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(n));
        if (!in) return std::make_error_code(std::errc::io_error);
    }
    out = std::move(buf);
    return {};
}

YANTERM_SSH_INLINE std::error_code atomic_write(const char* path, std::span<const std::byte> data) {
    if (path == nullptr || path[0] == '\0') {
        return std::make_error_code(std::errc::invalid_argument);
    }
    const std::string tmp = std::string{path} + ".tmp";
    {
        std::ofstream out{tmp, std::ios::binary | std::ios::trunc};
        if (!out) return std::make_error_code(std::errc::io_error);
        if (!data.empty()) {
            out.write(reinterpret_cast<const char*>(data.data()),
                      static_cast<std::streamsize>(data.size()));
        }
        out.flush();
        if (!out) return std::make_error_code(std::errc::io_error);
    }
    std::error_code ec;
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        std::filesystem::remove(tmp);
        return ec;
    }
    return {};
}

#endif

YANTERM_SSH_INLINE std::error_code load_private_key(const char* path, crypto::provider p,
                                        std::span<const std::byte> passphrase,
                                        private_key& out) {
    if (auto ec = check_private_key_permissions(path)) return ec;
    std::vector<std::byte> bytes;
    if (auto ec = read_file(path, bytes)) return ec;
    return private_key::parse(bytes, p, passphrase, out);
}

}  // namespace yanterm::ssh::keys::io
