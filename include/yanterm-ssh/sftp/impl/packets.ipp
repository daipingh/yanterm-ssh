#pragma once

#include <yanterm-ssh/sftp/packets.hpp>

#if !defined(YANTERM_SSH_HEADER_ONLY) && !defined(YANTERM_SSH_SOURCE)
#error "yanterm-ssh/sftp/impl/packets.ipp is an implementation file, not a public header."
#endif

#include <algorithm>
#include <limits>

namespace yanterm::ssh::sftp {
namespace detail {

YANTERM_SSH_INLINE void write_type_id(wire::writer& w, msg type, std::uint32_t id) {
    w.write_byte(static_cast<std::uint8_t>(type));
    w.write_uint32(id);
}

YANTERM_SSH_INLINE bool read_type_id(wire::reader& r, msg expected, std::uint32_t& id) noexcept {
    std::uint8_t type = 0;
    return r.read_byte(type) && type == static_cast<std::uint8_t>(expected) && r.read_uint32(id);
}

YANTERM_SSH_INLINE bool finish(wire::reader& r, bool allow_tail = false) noexcept {
    return r.ok() && (allow_tail || r.empty());
}

YANTERM_SSH_INLINE void write_span_string(wire::writer& w, std::span<const std::byte> s) {
    w.write_string(s);
}

YANTERM_SSH_INLINE bool read_handle(wire::reader& r, std::span<const std::byte>& handle) noexcept {
    return r.read_string(handle) && handle.size() <= max_handle_length;
}

YANTERM_SSH_INLINE void write_extended_string(wire::writer& w, std::uint32_t id, std::string_view name) {
    write_type_id(w, msg::extended, id);
    w.write_string(name);
}

YANTERM_SSH_INLINE bool read_string_list(wire::reader& r, std::uint32_t count,
                                         std::vector<std::string_view>& out) {
    if (count > r.remaining().size() / 4u) return false;
    out.clear();
    out.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        std::string_view s;
        if (!r.read_string(s)) return false;
        out.push_back(s);
    }
    return true;
}

YANTERM_SSH_INLINE bool read_attrs_after_flags(wire::reader& r, attrs& out) noexcept {
    if ((out.flags & attr_flags::size) != 0 && !r.read_uint64(out.size)) return false;
    if ((out.flags & attr_flags::uidgid) != 0
        && (!r.read_uint32(out.uid) || !r.read_uint32(out.gid))) {
        return false;
    }
    if ((out.flags & attr_flags::permissions) != 0 && !r.read_uint32(out.permissions)) return false;
    if ((out.flags & attr_flags::acmodtime) != 0
        && (!r.read_uint32(out.atime) || !r.read_uint32(out.mtime))) {
        return false;
    }
    if ((out.flags & attr_flags::extended) != 0) {
        std::uint32_t count = 0;
        if (!r.read_uint32(count)) return false;
        if (count > r.remaining().size() / 8u) return false;
        for (std::uint32_t i = 0; i < count; ++i) {
            std::string_view type;
            std::span<const std::byte> data;
            if (!r.read_string(type) || !r.read_string(data)) return false;
        }
    }
    return true;
}

}  // namespace detail

YANTERM_SSH_INLINE std::uint32_t decode_frame_header(std::span<const std::byte> header) noexcept {
    if (header.size() != 4) return 0;
    return (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(header[0])) << 24)
        | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(header[1])) << 16)
        | (static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(header[2])) << 8)
        | static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(header[3]));
}

YANTERM_SSH_INLINE void encode_frame_header(wire::writer& w, std::uint32_t length) {
    w.write_uint32(length);
}

YANTERM_SSH_INLINE msg packet_type(std::span<const std::byte> payload) noexcept {
    if (payload.empty()) return static_cast<msg>(0);
    return static_cast<msg>(std::to_integer<std::uint8_t>(payload[0]));
}

YANTERM_SSH_INLINE bool packet_request_id(std::span<const std::byte> payload, std::uint32_t& id) noexcept {
    if (payload.size() < 5) return false;
    wire::reader r{payload.subspan(1)};
    return r.read_uint32(id);
}

YANTERM_SSH_INLINE void encode_init(wire::writer& w, std::uint32_t version) {
    w.write_byte(static_cast<std::uint8_t>(msg::init));
    w.write_uint32(version);
}

YANTERM_SSH_INLINE bool decode_init(std::span<const std::byte> payload, std::uint32_t& version) noexcept {
    wire::reader r{payload};
    std::uint8_t type = 0;
    return r.read_byte(type) && type == static_cast<std::uint8_t>(msg::init)
        && r.read_uint32(version) && r.empty();
}

YANTERM_SSH_INLINE void encode_version(wire::writer& w, std::uint32_t version,
                                       std::span<const extension_pair> extensions) {
    w.write_byte(static_cast<std::uint8_t>(msg::version));
    w.write_uint32(version);
    for (const auto& ext : extensions) {
        w.write_string(ext.name);
        w.write_string(ext.version);
    }
}

YANTERM_SSH_INLINE bool decode_version(std::span<const std::byte> payload, version_reply& out) {
    wire::reader r{payload};
    std::uint8_t type = 0;
    if (!r.read_byte(type) || type != static_cast<std::uint8_t>(msg::version)
        || !r.read_uint32(out.version)) {
        return false;
    }
    out.extensions.clear();
    while (!r.empty()) {
        extension_pair ext;
        if (!r.read_string(ext.name) || !r.read_string(ext.version)) return false;
        out.extensions.push_back(ext);
    }
    return r.ok();
}

YANTERM_SSH_INLINE void encode_attrs(wire::writer& w, const attrs& a) {
    const std::uint32_t flags = a.flags & ~attr_flags::extended;
    w.write_uint32(flags);
    if ((flags & attr_flags::size) != 0) w.write_uint64(a.size);
    if ((flags & attr_flags::uidgid) != 0) {
        w.write_uint32(a.uid);
        w.write_uint32(a.gid);
    }
    if ((flags & attr_flags::permissions) != 0) w.write_uint32(a.permissions);
    if ((flags & attr_flags::acmodtime) != 0) {
        w.write_uint32(a.atime);
        w.write_uint32(a.mtime);
    }
}

YANTERM_SSH_INLINE bool decode_attrs(wire::reader& r, attrs& out) noexcept {
    out = {};
    return r.read_uint32(out.flags) && detail::read_attrs_after_flags(r, out);
}

YANTERM_SSH_INLINE void encode_open(wire::writer& w, std::uint32_t id, std::string_view path,
                                    std::uint32_t pflags, const attrs& a) {
    detail::write_type_id(w, msg::open, id);
    w.write_string(path);
    w.write_uint32(pflags);
    encode_attrs(w, a);
}

YANTERM_SSH_INLINE bool decode_open(std::span<const std::byte> payload, std::uint32_t& id,
                                    std::string_view& path, std::uint32_t& pflags,
                                    attrs& a) noexcept {
    wire::reader r{payload};
    return detail::read_type_id(r, msg::open, id) && r.read_string(path)
        && r.read_uint32(pflags) && decode_attrs(r, a) && r.empty();
}

YANTERM_SSH_INLINE void encode_close(wire::writer& w, std::uint32_t id, std::span<const std::byte> handle) {
    detail::write_type_id(w, msg::close, id);
    detail::write_span_string(w, handle);
}

YANTERM_SSH_INLINE bool decode_handle_request(std::span<const std::byte> payload, msg expected,
                                              std::uint32_t& id,
                                              std::span<const std::byte>& handle) noexcept {
    wire::reader r{payload};
    return detail::read_type_id(r, expected, id) && detail::read_handle(r, handle) && r.empty();
}

YANTERM_SSH_INLINE void encode_read(wire::writer& w, std::uint32_t id, std::span<const std::byte> handle,
                                    std::uint64_t offset, std::uint32_t length) {
    detail::write_type_id(w, msg::read, id);
    detail::write_span_string(w, handle);
    w.write_uint64(offset);
    w.write_uint32(length);
}

YANTERM_SSH_INLINE bool decode_read(std::span<const std::byte> payload, std::uint32_t& id,
                                    std::span<const std::byte>& handle, std::uint64_t& offset,
                                    std::uint32_t& length) noexcept {
    wire::reader r{payload};
    return detail::read_type_id(r, msg::read, id) && detail::read_handle(r, handle)
        && r.read_uint64(offset) && r.read_uint32(length) && r.empty();
}

YANTERM_SSH_INLINE void encode_write_header(wire::writer& w, std::uint32_t id,
                                            std::span<const std::byte> handle,
                                            std::uint64_t offset, std::uint32_t length) {
    detail::write_type_id(w, msg::write, id);
    detail::write_span_string(w, handle);
    w.write_uint64(offset);
    w.write_uint32(length);
}

YANTERM_SSH_INLINE bool decode_write(std::span<const std::byte> payload, std::uint32_t& id,
                                     std::span<const std::byte>& handle, std::uint64_t& offset,
                                     std::span<const std::byte>& data) noexcept {
    wire::reader r{payload};
    return detail::read_type_id(r, msg::write, id) && detail::read_handle(r, handle)
        && r.read_uint64(offset) && r.read_string(data) && r.empty();
}

YANTERM_SSH_INLINE void encode_path_request(wire::writer& w, msg type, std::uint32_t id,
                                            std::string_view path) {
    detail::write_type_id(w, type, id);
    w.write_string(path);
}

YANTERM_SSH_INLINE bool decode_path_request(std::span<const std::byte> payload, msg expected,
                                            std::uint32_t& id, std::string_view& path) noexcept {
    wire::reader r{payload};
    return detail::read_type_id(r, expected, id) && r.read_string(path) && r.empty();
}

YANTERM_SSH_INLINE void encode_setstat(wire::writer& w, msg type, std::uint32_t id,
                                       std::string_view path, const attrs& a) {
    detail::write_type_id(w, type, id);
    w.write_string(path);
    encode_attrs(w, a);
}

YANTERM_SSH_INLINE bool decode_setstat(std::span<const std::byte> payload, msg expected,
                                       std::uint32_t& id, std::string_view& path,
                                       attrs& a) noexcept {
    wire::reader r{payload};
    return detail::read_type_id(r, expected, id) && r.read_string(path)
        && decode_attrs(r, a) && r.empty();
}

YANTERM_SSH_INLINE void encode_fsetstat(wire::writer& w, std::uint32_t id,
                                        std::span<const std::byte> handle, const attrs& a) {
    detail::write_type_id(w, msg::fsetstat, id);
    detail::write_span_string(w, handle);
    encode_attrs(w, a);
}

YANTERM_SSH_INLINE bool decode_fsetstat(std::span<const std::byte> payload, std::uint32_t& id,
                                        std::span<const std::byte>& handle, attrs& a) noexcept {
    wire::reader r{payload};
    return detail::read_type_id(r, msg::fsetstat, id) && detail::read_handle(r, handle)
        && decode_attrs(r, a) && r.empty();
}

YANTERM_SSH_INLINE void encode_rename(wire::writer& w, std::uint32_t id,
                                      std::string_view oldpath, std::string_view newpath) {
    detail::write_type_id(w, msg::rename, id);
    w.write_string(oldpath);
    w.write_string(newpath);
}

YANTERM_SSH_INLINE bool decode_rename(std::span<const std::byte> payload, msg expected,
                                      std::uint32_t& id, std::string_view& oldpath,
                                      std::string_view& newpath) noexcept {
    wire::reader r{payload};
    return detail::read_type_id(r, expected, id) && r.read_string(oldpath)
        && r.read_string(newpath) && r.empty();
}

YANTERM_SSH_INLINE void encode_symlink(wire::writer& w, std::uint32_t id,
                                       std::string_view targetpath, std::string_view linkpath) {
    detail::write_type_id(w, msg::symlink, id);
    w.write_string(targetpath);
    w.write_string(linkpath);
}

YANTERM_SSH_INLINE void encode_status(wire::writer& w, std::uint32_t id, status_code code,
                                      std::string_view message, std::string_view language) {
    detail::write_type_id(w, msg::status, id);
    w.write_uint32(static_cast<std::uint32_t>(code));
    w.write_string(message);
    w.write_string(language);
}

YANTERM_SSH_INLINE bool decode_status(std::span<const std::byte> payload, status_reply& out) noexcept {
    wire::reader r{payload};
    std::uint32_t code = 0;
    if (!detail::read_type_id(r, msg::status, out.id) || !r.read_uint32(code)
        || !r.read_string(out.message) || !r.read_string(out.language) || !r.empty()) {
        return false;
    }
    out.code = static_cast<status_code>(code);
    return true;
}

YANTERM_SSH_INLINE void encode_handle(wire::writer& w, std::uint32_t id, std::span<const std::byte> handle) {
    detail::write_type_id(w, msg::handle, id);
    detail::write_span_string(w, handle);
}

YANTERM_SSH_INLINE bool decode_handle(std::span<const std::byte> payload, handle_reply& out) noexcept {
    wire::reader r{payload};
    return detail::read_type_id(r, msg::handle, out.id) && detail::read_handle(r, out.handle)
        && r.empty();
}

YANTERM_SSH_INLINE void encode_data(wire::writer& w, std::uint32_t id, std::span<const std::byte> data) {
    detail::write_type_id(w, msg::data, id);
    w.write_string(data);
}

YANTERM_SSH_INLINE bool decode_data(std::span<const std::byte> payload, data_reply& out) noexcept {
    wire::reader r{payload};
    return detail::read_type_id(r, msg::data, out.id) && r.read_string(out.data) && r.empty();
}

YANTERM_SSH_INLINE void encode_name(wire::writer& w, std::uint32_t id, std::span<const name_entry> entries) {
    detail::write_type_id(w, msg::name, id);
    w.write_uint32(static_cast<std::uint32_t>(entries.size()));
    for (const auto& e : entries) {
        w.write_string(e.filename);
        w.write_string(e.longname);
        encode_attrs(w, e.attributes);
    }
}

YANTERM_SSH_INLINE bool decode_name(std::span<const std::byte> payload, name_reply_view& out) {
    wire::reader r{payload};
    std::uint32_t count = 0;
    if (!detail::read_type_id(r, msg::name, out.id) || !r.read_uint32(count)) return false;
    if (count > r.remaining().size() / 12u) return false;
    out.entries.clear();
    out.entries.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        name_entry_view e;
        if (!r.read_string(e.filename) || !r.read_string(e.longname) || !decode_attrs(r, e.attributes)) {
            return false;
        }
        out.entries.push_back(e);
    }
    return r.empty();
}

YANTERM_SSH_INLINE void encode_attrs_reply(wire::writer& w, std::uint32_t id, const attrs& a) {
    detail::write_type_id(w, msg::attrs, id);
    encode_attrs(w, a);
}

YANTERM_SSH_INLINE bool decode_attrs_reply(std::span<const std::byte> payload, attrs_reply& out) noexcept {
    wire::reader r{payload};
    return detail::read_type_id(r, msg::attrs, out.id) && decode_attrs(r, out.attributes)
        && r.empty();
}

YANTERM_SSH_INLINE void encode_extended(wire::writer& w, std::uint32_t id, std::string_view request) {
    detail::write_extended_string(w, id, request);
}

YANTERM_SSH_INLINE void encode_posix_rename(wire::writer& w, std::uint32_t id,
                                            std::string_view oldpath, std::string_view newpath) {
    detail::write_extended_string(w, id, "posix-rename@openssh.com");
    w.write_string(oldpath);
    w.write_string(newpath);
}

YANTERM_SSH_INLINE void encode_statvfs(wire::writer& w, std::uint32_t id, std::string_view path) {
    detail::write_extended_string(w, id, "statvfs@openssh.com");
    w.write_string(path);
}

YANTERM_SSH_INLINE void encode_fstatvfs(wire::writer& w, std::uint32_t id,
                                        std::span<const std::byte> handle) {
    detail::write_extended_string(w, id, "fstatvfs@openssh.com");
    detail::write_span_string(w, handle);
}

YANTERM_SSH_INLINE void encode_hardlink(wire::writer& w, std::uint32_t id,
                                        std::string_view oldpath, std::string_view newpath) {
    detail::write_extended_string(w, id, "hardlink@openssh.com");
    w.write_string(oldpath);
    w.write_string(newpath);
}

YANTERM_SSH_INLINE void encode_fsync(wire::writer& w, std::uint32_t id,
                                     std::span<const std::byte> handle) {
    detail::write_extended_string(w, id, "fsync@openssh.com");
    detail::write_span_string(w, handle);
}

YANTERM_SSH_INLINE void encode_lsetstat(wire::writer& w, std::uint32_t id,
                                        std::string_view path, const attrs& a) {
    detail::write_extended_string(w, id, "lsetstat@openssh.com");
    w.write_string(path);
    encode_attrs(w, a);
}

YANTERM_SSH_INLINE void encode_limits(wire::writer& w, std::uint32_t id) {
    detail::write_extended_string(w, id, "limits@openssh.com");
}

YANTERM_SSH_INLINE void encode_expand_path(wire::writer& w, std::uint32_t id, std::string_view path) {
    detail::write_extended_string(w, id, "expand-path@openssh.com");
    w.write_string(path);
}

YANTERM_SSH_INLINE void encode_copy_data(wire::writer& w, std::uint32_t id,
                                         std::span<const std::byte> src, std::uint64_t src_off,
                                         std::uint64_t len, std::span<const std::byte> dst,
                                         std::uint64_t dst_off) {
    detail::write_extended_string(w, id, "copy-data");
    detail::write_span_string(w, src);
    w.write_uint64(src_off);
    w.write_uint64(len);
    detail::write_span_string(w, dst);
    w.write_uint64(dst_off);
}

YANTERM_SSH_INLINE void encode_home_directory(wire::writer& w, std::uint32_t id, std::string_view user) {
    detail::write_extended_string(w, id, "home-directory");
    w.write_string(user);
}

YANTERM_SSH_INLINE void encode_users_groups_by_id(wire::writer& w, std::uint32_t id,
                                                  std::span<const std::uint32_t> uids,
                                                  std::span<const std::uint32_t> gids) {
    detail::write_extended_string(w, id, "users-groups-by-id@openssh.com");
    w.write_uint32(static_cast<std::uint32_t>(uids.size() * 4u));
    for (std::uint32_t uid : uids) w.write_uint32(uid);
    w.write_uint32(static_cast<std::uint32_t>(gids.size() * 4u));
    for (std::uint32_t gid : gids) w.write_uint32(gid);
}

YANTERM_SSH_INLINE void encode_extended_reply(wire::writer& w, std::uint32_t id) {
    detail::write_type_id(w, msg::extended_reply, id);
}

YANTERM_SSH_INLINE void encode_statvfs_reply(wire::writer& w, std::uint32_t id, const statvfs_info& info) {
    encode_extended_reply(w, id);
    w.write_uint64(info.bsize);
    w.write_uint64(info.frsize);
    w.write_uint64(info.blocks);
    w.write_uint64(info.bfree);
    w.write_uint64(info.bavail);
    w.write_uint64(info.files);
    w.write_uint64(info.ffree);
    w.write_uint64(info.favail);
    w.write_uint64(info.fsid);
    w.write_uint64(info.flag);
    w.write_uint64(info.namemax);
}

YANTERM_SSH_INLINE bool decode_statvfs_reply(std::span<const std::byte> payload, std::uint32_t& id,
                                             statvfs_info& info) noexcept {
    wire::reader r{payload};
    return detail::read_type_id(r, msg::extended_reply, id)
        && r.read_uint64(info.bsize) && r.read_uint64(info.frsize)
        && r.read_uint64(info.blocks) && r.read_uint64(info.bfree)
        && r.read_uint64(info.bavail) && r.read_uint64(info.files)
        && r.read_uint64(info.ffree) && r.read_uint64(info.favail)
        && r.read_uint64(info.fsid) && r.read_uint64(info.flag)
        && r.read_uint64(info.namemax) && detail::finish(r, true);
}

YANTERM_SSH_INLINE void encode_limits_reply(wire::writer& w, std::uint32_t id, const limits_info& info) {
    encode_extended_reply(w, id);
    w.write_uint64(info.max_packet_length);
    w.write_uint64(info.max_read_length);
    w.write_uint64(info.max_write_length);
    w.write_uint64(info.max_open_handles);
}

YANTERM_SSH_INLINE bool decode_limits_reply(std::span<const std::byte> payload, std::uint32_t& id,
                                            limits_info& info) noexcept {
    wire::reader r{payload};
    return detail::read_type_id(r, msg::extended_reply, id)
        && r.read_uint64(info.max_packet_length) && r.read_uint64(info.max_read_length)
        && r.read_uint64(info.max_write_length) && r.read_uint64(info.max_open_handles)
        && detail::finish(r, true);
}

YANTERM_SSH_INLINE void encode_users_groups_by_id_reply(wire::writer& w, std::uint32_t id,
                                                        std::span<const std::string_view> users,
                                                        std::span<const std::string_view> groups) {
    encode_extended_reply(w, id);
    wire::writer names;
    for (auto s : users) names.write_string(s);
    w.write_string(names.data());
    names.clear();
    for (auto s : groups) names.write_string(s);
    w.write_string(names.data());
}

YANTERM_SSH_INLINE bool decode_users_groups_by_id_reply(std::span<const std::byte> payload,
                                                        std::uint32_t expected_users,
                                                        std::uint32_t expected_groups,
                                                        users_groups_reply_view& out) {
    wire::reader r{payload};
    std::span<const std::byte> users_blob;
    std::span<const std::byte> groups_blob;
    if (!detail::read_type_id(r, msg::extended_reply, out.id) || !r.read_string(users_blob)
        || !r.read_string(groups_blob) || !detail::finish(r, true)) {
        return false;
    }
    wire::reader users_r{users_blob};
    wire::reader groups_r{groups_blob};
    if (expected_users > users_blob.size() / 4u || expected_groups > groups_blob.size() / 4u) {
        return false;
    }
    if (!detail::read_string_list(users_r, expected_users, out.users) || !users_r.empty()) {
        return false;
    }
    if (!detail::read_string_list(groups_r, expected_groups, out.groups) || !groups_r.empty()) {
        return false;
    }
    return true;
}

YANTERM_SSH_INLINE extension_set advertised_extensions(std::span<const extension_pair> extensions) noexcept {
    extension_set set;
    for (const auto& e : extensions) {
        if (e.name == "posix-rename@openssh.com" && e.version == "1") set.set(extension::posix_rename);
        else if (e.name == "statvfs@openssh.com" && e.version == "2") set.set(extension::statvfs);
        else if (e.name == "fstatvfs@openssh.com" && e.version == "2") set.set(extension::fstatvfs);
        else if (e.name == "hardlink@openssh.com" && e.version == "1") set.set(extension::hardlink);
        else if (e.name == "fsync@openssh.com" && e.version == "1") set.set(extension::fsync);
        else if (e.name == "lsetstat@openssh.com" && e.version == "1") set.set(extension::lsetstat);
        else if (e.name == "limits@openssh.com" && e.version == "1") set.set(extension::limits);
        else if (e.name == "expand-path@openssh.com" && e.version == "1") set.set(extension::expand_path);
        else if (e.name == "copy-data" && e.version == "1") set.set(extension::copy_data);
        else if (e.name == "home-directory" && e.version == "1") set.set(extension::home_directory);
        else if (e.name == "users-groups-by-id@openssh.com" && e.version == "1") {
            set.set(extension::users_groups_by_id);
        }
    }
    return set;
}

}  // namespace yanterm::ssh::sftp
