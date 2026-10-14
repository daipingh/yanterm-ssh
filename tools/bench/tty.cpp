#include "tty.h"

#include <yanterm-ssh/crypto/algorithms.hpp>
#include <yanterm-ssh/detail/error.hpp>
#include <yanterm-ssh/error.hpp>

#include <array>
#include <cerrno>
#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

#ifndef _WIN32
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#else
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace ssh = yanterm::ssh;

namespace bench {
namespace {

constexpr std::size_t k_max_passphrase = 1024;

#ifndef _WIN32

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

struct echo_off {
    int fd = -1;
    termios old{};
    bool armed = false;
    explicit echo_off(int f) : fd(f) {
        if (tcgetattr(fd, &old) != 0) return;
        termios raw = old;
        raw.c_lflag &= static_cast<tcflag_t>(~(ECHO | ECHOE | ECHOK | ECHONL));
        if (tcsetattr(fd, TCSAFLUSH, &raw) != 0) return;
        armed = true;
    }
    ~echo_off() {
        if (armed) (void)tcsetattr(fd, TCSAFLUSH, &old);
    }
    echo_off(const echo_off&) = delete;
    echo_off& operator=(const echo_off&) = delete;
};

std::error_code write_all(int fd, std::string_view s) {
    while (!s.empty()) {
        const ssize_t n = ::write(fd, s.data(), s.size());
        if (n < 0) {
            if (errno == EINTR) continue;
            return {errno, std::system_category()};
        }
        if (n == 0) return std::make_error_code(std::errc::io_error);
        s.remove_prefix(static_cast<std::size_t>(n));
    }
    return {};
}

std::error_code read_line(int fd, ssh::crypto::secure_bytes& out) {
    std::array<std::byte, k_max_passphrase> buf{};
    std::size_t n = 0;
    for (;;) {
        if (n >= buf.size()) return std::make_error_code(std::errc::message_size);
        unsigned char ch = 0;
        const ssize_t r = ::read(fd, &ch, 1);
        if (r < 0) {
            if (errno == EINTR) continue;
            return {errno, std::system_category()};
        }
        if (r == 0) {
            if (n == 0) return std::make_error_code(std::errc::io_error);
            break;
        }
        if (ch == '\n') break;
        if (ch == '\r') continue;
        buf[n++] = static_cast<std::byte>(ch);
    }
    out.assign(std::span<const std::byte>{buf.data(), n});
    ssh::crypto::secure_zero(std::span<std::byte>{buf.data(), buf.size()});
    return {};
}

#else

struct echo_off {
    HANDLE h = INVALID_HANDLE_VALUE;
    DWORD old = 0;
    bool armed = false;
    explicit echo_off(HANDLE handle) : h(handle) {
        if (!GetConsoleMode(h, &old)) return;
        if (!SetConsoleMode(h, old & ~ENABLE_ECHO_INPUT)) return;
        armed = true;
    }
    ~echo_off() {
        if (armed) (void)SetConsoleMode(h, old);
    }
    echo_off(const echo_off&) = delete;
    echo_off& operator=(const echo_off&) = delete;
};

std::error_code write_all(HANDLE h, std::string_view s) {
    while (!s.empty()) {
        DWORD n = 0;
        if (!WriteFile(h, s.data(), static_cast<DWORD>(s.size()), &n, nullptr)) {
            return {static_cast<int>(GetLastError()), std::system_category()};
        }
        if (n == 0) return std::make_error_code(std::errc::io_error);
        s.remove_prefix(static_cast<std::size_t>(n));
    }
    return {};
}

std::error_code read_line(HANDLE hin, ssh::crypto::secure_bytes& out) {
    std::array<wchar_t, k_max_passphrase> wbuf{};
    DWORD n = 0;
    if (!ReadConsoleW(hin, wbuf.data(), static_cast<DWORD>(wbuf.size() - 1), &n, nullptr)) {
        return {static_cast<int>(GetLastError()), std::system_category()};
    }
    while (n > 0 && (wbuf[n - 1] == L'\n' || wbuf[n - 1] == L'\r')) --n;
    if (n == 0 && GetLastError() == ERROR_OPERATION_ABORTED) {
        return std::make_error_code(std::errc::io_error);
    }
    if (n == 0) {
        out.assign({});
        return {};
    }
    const int bytes = WideCharToMultiByte(CP_UTF8, 0, wbuf.data(), static_cast<int>(n),
                                          nullptr, 0, nullptr, nullptr);
    if (bytes <= 0) return std::make_error_code(std::errc::illegal_byte_sequence);
    std::string utf8(static_cast<std::size_t>(bytes), '\0');
    if (WideCharToMultiByte(CP_UTF8, 0, wbuf.data(), static_cast<int>(n), utf8.data(), bytes,
                            nullptr, nullptr) <= 0) {
        ssh::crypto::secure_zero(std::as_writable_bytes(std::span{utf8}));
        return std::make_error_code(std::errc::illegal_byte_sequence);
    }
    out.assign(std::span<const std::byte>{reinterpret_cast<const std::byte*>(utf8.data()),
                                          utf8.size()});
    ssh::crypto::secure_zero(std::as_writable_bytes(std::span{utf8}));
    ssh::crypto::secure_zero(std::as_writable_bytes(std::span{wbuf}));
    return {};
}

#endif

}  // namespace

std::error_code read_controlling_tty_passphrase(std::string_view prompt,
                                                ssh::crypto::secure_bytes& out) {
#ifndef _WIN32
    unique_fd tty{::open("/dev/tty", O_RDWR | O_CLOEXEC)};
    if (tty.get() < 0) return ssh::make_error_code(ssh::code::passphrase_required);
    echo_off guard{tty.get()};
    if (!guard.armed) return ssh::make_error_code(ssh::code::passphrase_required);
    if (auto ec = write_all(tty.get(), prompt)) return ec;
    if (auto ec = read_line(tty.get(), out)) {
        (void)write_all(tty.get(), "\n");
        return ec;
    }
    return write_all(tty.get(), "\n");
#else
    HANDLE hin = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                             OPEN_EXISTING, 0, nullptr);
    if (hin == INVALID_HANDLE_VALUE) return ssh::make_error_code(ssh::code::passphrase_required);
    HANDLE hout = CreateFileW(L"CONOUT$", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                              0, nullptr);
    if (hout == INVALID_HANDLE_VALUE) {
        CloseHandle(hin);
        return ssh::make_error_code(ssh::code::passphrase_required);
    }
    echo_off guard{hin};
    if (!guard.armed) {
        CloseHandle(hout);
        CloseHandle(hin);
        return ssh::make_error_code(ssh::code::passphrase_required);
    }
    auto finish = [&](std::error_code ec) {
        CloseHandle(hout);
        CloseHandle(hin);
        return ec;
    };
    if (auto ec = write_all(hout, prompt)) return finish(ec);
    if (auto ec = read_line(hin, out)) {
        (void)write_all(hout, "\n");
        return finish(ec);
    }
    if (auto ec = write_all(hout, "\n")) return finish(ec);
    return finish({});
#endif
}

}  // namespace bench
