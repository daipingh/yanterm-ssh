#include <yanterm-ssh/sftp/packets.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace yanterm::ssh::fuzz {

int fuzz_sftp_one(std::span<const std::byte> input) {
    if (input.size() > (1u << 20)) return 0;

    const auto selector = input.empty() ? 0u
                                         : static_cast<unsigned>(std::to_integer<std::uint8_t>(input[0])) % 14u;
    const auto payload = input.size() > 1 ? input.subspan(1) : std::span<const std::byte>{};

    switch (selector) {
    case 0: {
        sftp::version_reply version;
        (void)sftp::decode_version(payload, version);
        (void)sftp::advertised_extensions(version.extensions);
        break;
    }
    case 1: {
        std::uint32_t version = 0;
        (void)sftp::decode_init(payload, version);
        break;
    }
    case 2: {
        sftp::status_reply status;
        (void)sftp::decode_status(payload, status);
        break;
    }
    case 3: {
        sftp::handle_reply handle;
        (void)sftp::decode_handle(payload, handle);
        break;
    }
    case 4: {
        sftp::data_reply data;
        (void)sftp::decode_data(payload, data);
        break;
    }
    case 5: {
        sftp::name_reply_view names;
        (void)sftp::decode_name(payload, names);
        break;
    }
    case 6: {
        sftp::attrs_reply attrs;
        (void)sftp::decode_attrs_reply(payload, attrs);
        break;
    }
    case 7: {
        sftp::statvfs_info info;
        std::uint32_t id = 0;
        (void)sftp::decode_statvfs_reply(payload, id, info);
        break;
    }
    case 8: {
        sftp::limits_info info;
        std::uint32_t id = 0;
        (void)sftp::decode_limits_reply(payload, id, info);
        break;
    }
    case 9: {
        sftp::users_groups_reply_view names;
        const auto n = payload.empty() ? 0u : static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(payload[0]));
        (void)sftp::decode_users_groups_by_id_reply(payload, n % 4u, n % 3u, names);
        break;
    }
    case 10: {
        (void)sftp::decode_frame_header(payload.size() >= 4 ? payload.first(4) : payload);
        (void)sftp::packet_type(payload);
        std::uint32_t id = 0;
        (void)sftp::packet_request_id(payload, id);
        break;
    }
    case 11: {
        std::uint32_t id = 0;
        std::string_view path;
        std::uint32_t flags = 0;
        sftp::attrs attrs;
        (void)sftp::decode_open(payload, id, path, flags, attrs);
        break;
    }
    case 12: {
        std::uint32_t id = 0;
        std::span<const std::byte> handle;
        std::uint64_t offset = 0;
        std::uint32_t length = 0;
        (void)sftp::decode_read(payload, id, handle, offset, length);
        std::span<const std::byte> data;
        (void)sftp::decode_write(payload, id, handle, offset, data);
        break;
    }
    default: {
        std::uint32_t id = 0;
        std::string_view path;
        (void)sftp::decode_path_request(payload, sftp::msg::stat, id, path);
        std::string_view oldpath;
        std::string_view newpath;
        (void)sftp::decode_rename(payload, sftp::msg::rename, id, oldpath, newpath);
        break;
    }
    }
    return 0;
}

}  // namespace yanterm::ssh::fuzz

#if defined(YANTERM_SSH_FUZZER_STANDALONE)
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    return yanterm::ssh::fuzz::fuzz_sftp_one(
        std::span<const std::byte>{reinterpret_cast<const std::byte*>(data), size});
}
#endif
