#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/error.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <system_error>
#include <type_traits>
#include <vector>

namespace yanterm::ssh::sftp {

inline constexpr std::uint32_t protocol_version = 3;
inline constexpr std::uint32_t default_max_packet_length = 262144;
inline constexpr std::uint32_t fallback_io_length = 32768;
inline constexpr std::size_t max_handle_length = 256;

enum class msg : std::uint8_t {
    init = 1,
    version = 2,
    open = 3,
    close = 4,
    read = 5,
    write = 6,
    lstat = 7,
    fstat = 8,
    setstat = 9,
    fsetstat = 10,
    opendir = 11,
    readdir = 12,
    remove = 13,
    mkdir = 14,
    rmdir = 15,
    realpath = 16,
    stat = 17,
    rename = 18,
    readlink = 19,
    symlink = 20,
    status = 101,
    handle = 102,
    data = 103,
    name = 104,
    attrs = 105,
    extended = 200,
    extended_reply = 201,
};

enum class status_code : std::uint32_t {
    ok = 0,
    eof = 1,
    no_such_file = 2,
    permission_denied = 3,
    failure = 4,
    bad_message = 5,
    no_connection = 6,
    connection_lost = 7,
    op_unsupported = 8,
};

namespace open_flags {
inline constexpr std::uint32_t read = 0x00000001;
inline constexpr std::uint32_t write = 0x00000002;
inline constexpr std::uint32_t append = 0x00000004;
inline constexpr std::uint32_t creat = 0x00000008;
inline constexpr std::uint32_t trunc = 0x00000010;
inline constexpr std::uint32_t excl = 0x00000020;
}  // namespace open_flags

namespace attr_flags {
inline constexpr std::uint32_t size = 0x00000001;
inline constexpr std::uint32_t uidgid = 0x00000002;
inline constexpr std::uint32_t permissions = 0x00000004;
inline constexpr std::uint32_t acmodtime = 0x00000008;
inline constexpr std::uint32_t extended = 0x80000000;
}  // namespace attr_flags

struct attrs {
    std::uint32_t flags = 0;
    std::uint64_t size = 0;
    std::uint32_t uid = 0;
    std::uint32_t gid = 0;
    std::uint32_t permissions = 0;
    std::uint32_t atime = 0;
    std::uint32_t mtime = 0;
};

struct name_entry {
    std::string filename;
    std::string longname;
    attrs attributes;
};

struct limits_info {
    std::uint64_t max_packet_length = default_max_packet_length;
    std::uint64_t max_read_length = fallback_io_length;
    std::uint64_t max_write_length = fallback_io_length;
    std::uint64_t max_open_handles = 0;
};

struct statvfs_info {
    std::uint64_t bsize = 0;
    std::uint64_t frsize = 0;
    std::uint64_t blocks = 0;
    std::uint64_t bfree = 0;
    std::uint64_t bavail = 0;
    std::uint64_t files = 0;
    std::uint64_t ffree = 0;
    std::uint64_t favail = 0;
    std::uint64_t fsid = 0;
    std::uint64_t flag = 0;
    std::uint64_t namemax = 0;
};

enum class extension : std::uint16_t {
    posix_rename = 0,
    statvfs,
    fstatvfs,
    hardlink,
    fsync,
    lsetstat,
    limits,
    expand_path,
    copy_data,
    home_directory,
    users_groups_by_id,
};

class extension_set {
public:
    constexpr extension_set() = default;

    constexpr void set(extension e) noexcept { bits_ |= bit(e); }
    [[nodiscard]] constexpr bool contains(extension e) const noexcept { return (bits_ & bit(e)) != 0; }
    [[nodiscard]] constexpr std::uint32_t bits() const noexcept { return bits_; }

private:
    [[nodiscard]] static constexpr std::uint32_t bit(extension e) noexcept {
        return std::uint32_t{1} << static_cast<unsigned>(e);
    }

    std::uint32_t bits_ = 0;
};

[[nodiscard]] const std::error_category& error_category() noexcept;
[[nodiscard]] std::error_code make_error_code(status_code e) noexcept;

template <class T = void>
struct result {
    std::error_code ec;
    std::string message;
    T value{};
};

template <>
struct result<void> {
    std::error_code ec;
    std::string message;
};

namespace detail {

class sftp_error_category final : public std::error_category {
public:
    [[nodiscard]] const char* name() const noexcept override { return "yanterm-ssh.sftp"; }
    [[nodiscard]] std::string message(int value) const override;
    [[nodiscard]] std::error_condition default_error_condition(int value) const noexcept override;
};

}  // namespace detail

inline const std::error_category& error_category() noexcept {
    static const detail::sftp_error_category instance;
    return instance;
}

inline std::error_code make_error_code(status_code e) noexcept {
    return {static_cast<int>(static_cast<std::uint32_t>(e)), error_category()};
}

inline std::string detail::sftp_error_category::message(int value) const {
    switch (static_cast<status_code>(static_cast<std::uint32_t>(value))) {
    case status_code::ok:                return "success";
    case status_code::eof:               return "end of file";
    case status_code::no_such_file:      return "no such file";
    case status_code::permission_denied: return "permission denied";
    case status_code::failure:           return "failure";
    case status_code::bad_message:       return "bad message";
    case status_code::no_connection:     return "no connection";
    case status_code::connection_lost:   return "connection lost";
    case status_code::op_unsupported:    return "operation unsupported";
    }
    return "unknown SFTP status";
}

inline std::error_condition detail::sftp_error_category::default_error_condition(int value) const noexcept {
    switch (static_cast<status_code>(static_cast<std::uint32_t>(value))) {
    case status_code::no_such_file:
        return std::make_error_condition(std::errc::no_such_file_or_directory);
    case status_code::permission_denied:
        return std::make_error_condition(std::errc::permission_denied);
    case status_code::op_unsupported:
        return std::make_error_condition(std::errc::operation_not_supported);
    case status_code::no_connection:
    case status_code::connection_lost:
        return make_error_condition(errc::session_closed);
    case status_code::bad_message:
        return make_error_condition(errc::protocol_violation);
    case status_code::ok:
    case status_code::eof:
    case status_code::failure:
        break;
    }
    return {value, *this};
}

}  // namespace yanterm::ssh::sftp

template <>
struct std::is_error_code_enum<yanterm::ssh::sftp::status_code> : std::true_type {};
