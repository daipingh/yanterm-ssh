#pragma once

#include <yanterm-ssh/detail/config.hpp>
#include <yanterm-ssh/sftp/types.hpp>
#include <yanterm-ssh/wire/types.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace yanterm::ssh::sftp {

struct extension_pair {
    std::string_view name;
    std::string_view version;
};

struct status_reply {
    std::uint32_t id = 0;
    status_code code = status_code::failure;
    std::string_view message;
    std::string_view language;
};

struct handle_reply {
    std::uint32_t id = 0;
    std::span<const std::byte> handle;
};

struct data_reply {
    std::uint32_t id = 0;
    std::span<const std::byte> data;
};

struct name_entry_view {
    std::string_view filename;
    std::string_view longname;
    attrs attributes;
};

struct name_reply_view {
    std::uint32_t id = 0;
    std::vector<name_entry_view> entries;
};

struct attrs_reply {
    std::uint32_t id = 0;
    attrs attributes;
};

struct version_reply {
    std::uint32_t version = 0;
    std::vector<extension_pair> extensions;
};

struct users_groups_reply_view {
    std::uint32_t id = 0;
    std::vector<std::string_view> users;
    std::vector<std::string_view> groups;
};

[[nodiscard]] std::uint32_t decode_frame_header(std::span<const std::byte> header) noexcept;
void encode_frame_header(wire::writer& w, std::uint32_t length);

[[nodiscard]] msg packet_type(std::span<const std::byte> payload) noexcept;
[[nodiscard]] bool packet_request_id(std::span<const std::byte> payload, std::uint32_t& id) noexcept;

void encode_init(wire::writer& w, std::uint32_t version = protocol_version);
bool decode_init(std::span<const std::byte> payload, std::uint32_t& version) noexcept;
void encode_version(wire::writer& w, std::uint32_t version, std::span<const extension_pair> extensions = {});
bool decode_version(std::span<const std::byte> payload, version_reply& out);

void encode_attrs(wire::writer& w, const attrs& a);
bool decode_attrs(wire::reader& r, attrs& out) noexcept;

void encode_open(wire::writer& w, std::uint32_t id, std::string_view path,
                 std::uint32_t pflags, const attrs& a = {});
bool decode_open(std::span<const std::byte> payload, std::uint32_t& id,
                 std::string_view& path, std::uint32_t& pflags, attrs& a) noexcept;
void encode_close(wire::writer& w, std::uint32_t id, std::span<const std::byte> handle);
bool decode_handle_request(std::span<const std::byte> payload, msg expected,
                           std::uint32_t& id, std::span<const std::byte>& handle) noexcept;
void encode_read(wire::writer& w, std::uint32_t id, std::span<const std::byte> handle,
                 std::uint64_t offset, std::uint32_t length);
bool decode_read(std::span<const std::byte> payload, std::uint32_t& id,
                 std::span<const std::byte>& handle, std::uint64_t& offset,
                 std::uint32_t& length) noexcept;
void encode_write_header(wire::writer& w, std::uint32_t id, std::span<const std::byte> handle,
                         std::uint64_t offset, std::uint32_t length);
bool decode_write(std::span<const std::byte> payload, std::uint32_t& id,
                  std::span<const std::byte>& handle, std::uint64_t& offset,
                  std::span<const std::byte>& data) noexcept;

void encode_path_request(wire::writer& w, msg type, std::uint32_t id, std::string_view path);
bool decode_path_request(std::span<const std::byte> payload, msg expected,
                         std::uint32_t& id, std::string_view& path) noexcept;
void encode_setstat(wire::writer& w, msg type, std::uint32_t id, std::string_view path, const attrs& a);
bool decode_setstat(std::span<const std::byte> payload, msg expected,
                    std::uint32_t& id, std::string_view& path, attrs& a) noexcept;
void encode_fsetstat(wire::writer& w, std::uint32_t id, std::span<const std::byte> handle, const attrs& a);
bool decode_fsetstat(std::span<const std::byte> payload, std::uint32_t& id,
                     std::span<const std::byte>& handle, attrs& a) noexcept;
void encode_rename(wire::writer& w, std::uint32_t id, std::string_view oldpath, std::string_view newpath);
bool decode_rename(std::span<const std::byte> payload, msg expected, std::uint32_t& id,
                   std::string_view& oldpath, std::string_view& newpath) noexcept;
// OpenSSH retained a reversed SYMLINK argument order (PROTOCOL 4.1):
// targetpath, then linkpath.
void encode_symlink(wire::writer& w, std::uint32_t id, std::string_view targetpath,
                    std::string_view linkpath);

void encode_status(wire::writer& w, std::uint32_t id, status_code code,
                   std::string_view message = {}, std::string_view language = {});
bool decode_status(std::span<const std::byte> payload, status_reply& out) noexcept;
void encode_handle(wire::writer& w, std::uint32_t id, std::span<const std::byte> handle);
bool decode_handle(std::span<const std::byte> payload, handle_reply& out) noexcept;
void encode_data(wire::writer& w, std::uint32_t id, std::span<const std::byte> data);
bool decode_data(std::span<const std::byte> payload, data_reply& out) noexcept;
void encode_name(wire::writer& w, std::uint32_t id, std::span<const name_entry> entries);
bool decode_name(std::span<const std::byte> payload, name_reply_view& out);
void encode_attrs_reply(wire::writer& w, std::uint32_t id, const attrs& a);
bool decode_attrs_reply(std::span<const std::byte> payload, attrs_reply& out) noexcept;

void encode_extended(wire::writer& w, std::uint32_t id, std::string_view request);
void encode_posix_rename(wire::writer& w, std::uint32_t id, std::string_view oldpath, std::string_view newpath);
void encode_statvfs(wire::writer& w, std::uint32_t id, std::string_view path);
void encode_fstatvfs(wire::writer& w, std::uint32_t id, std::span<const std::byte> handle);
void encode_hardlink(wire::writer& w, std::uint32_t id, std::string_view oldpath, std::string_view newpath);
void encode_fsync(wire::writer& w, std::uint32_t id, std::span<const std::byte> handle);
void encode_lsetstat(wire::writer& w, std::uint32_t id, std::string_view path, const attrs& a);
void encode_limits(wire::writer& w, std::uint32_t id);
void encode_expand_path(wire::writer& w, std::uint32_t id, std::string_view path);
void encode_copy_data(wire::writer& w, std::uint32_t id, std::span<const std::byte> src,
                      std::uint64_t src_off, std::uint64_t len, std::span<const std::byte> dst,
                      std::uint64_t dst_off);
void encode_home_directory(wire::writer& w, std::uint32_t id, std::string_view user);
void encode_users_groups_by_id(wire::writer& w, std::uint32_t id,
                               std::span<const std::uint32_t> uids,
                               std::span<const std::uint32_t> gids);

void encode_extended_reply(wire::writer& w, std::uint32_t id);
void encode_statvfs_reply(wire::writer& w, std::uint32_t id, const statvfs_info& info);
bool decode_statvfs_reply(std::span<const std::byte> payload, std::uint32_t& id,
                          statvfs_info& info) noexcept;
void encode_limits_reply(wire::writer& w, std::uint32_t id, const limits_info& info);
bool decode_limits_reply(std::span<const std::byte> payload, std::uint32_t& id,
                         limits_info& info) noexcept;
void encode_users_groups_by_id_reply(wire::writer& w, std::uint32_t id,
                                     std::span<const std::string_view> users,
                                     std::span<const std::string_view> groups);
bool decode_users_groups_by_id_reply(std::span<const std::byte> payload,
                                     std::uint32_t expected_users,
                                     std::uint32_t expected_groups,
                                     users_groups_reply_view& out);

[[nodiscard]] extension_set advertised_extensions(std::span<const extension_pair> extensions) noexcept;

}  // namespace yanterm::ssh::sftp

#if defined(YANTERM_SSH_HEADER_ONLY)
#include <yanterm-ssh/sftp/impl/packets.ipp>
#endif
