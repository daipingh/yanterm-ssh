#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <vector>

namespace yanterm::ssh::fuzz {
int fuzz_keys_one(std::span<const std::byte> input);
int fuzz_wire_one(std::span<const std::byte> input);
int fuzz_connection_prekex_one(std::span<const std::byte> input);
int fuzz_sftp_one(std::span<const std::byte> input);
}  // namespace yanterm::ssh::fuzz

namespace {

bool replay_directory(const std::filesystem::path& dir,
                      int (*fn)(std::span<const std::byte>)) {
    std::error_code ec;
    if (!std::filesystem::exists(dir, ec) || !std::filesystem::is_directory(dir, ec)) {
        std::fprintf(stderr, "fuzz_replay: missing corpus directory: %s\n",
                     dir.string().c_str());
        return false;
    }

    std::vector<std::filesystem::path> files;
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (ec) {
            std::fprintf(stderr, "fuzz_replay: failed to iterate directory: %s\n",
                         dir.string().c_str());
            return false;
        }
        if (entry.is_regular_file(ec)) {
            files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end());

    if (files.empty()) {
        std::fprintf(stderr, "fuzz_replay: empty corpus directory: %s\n",
                     dir.string().c_str());
        return false;
    }

    for (const auto& path : files) {
        std::ifstream ifs(path, std::ios::binary | std::ios::ate);
        if (!ifs) {
            std::fprintf(stderr, "fuzz_replay: failed to open seed file: %s\n",
                         path.string().c_str());
            return false;
        }
        const auto end_pos = ifs.tellg();
        if (end_pos < 0) {
            std::fprintf(stderr, "fuzz_replay: failed to stat seed file: %s\n",
                         path.string().c_str());
            return false;
        }
        std::vector<std::byte> buf(static_cast<std::size_t>(end_pos));
        ifs.seekg(0, std::ios::beg);
        if (!buf.empty() &&
            !ifs.read(reinterpret_cast<char*>(buf.data()),
                      static_cast<std::streamsize>(buf.size()))) {
            std::fprintf(stderr, "fuzz_replay: failed to read seed file: %s\n",
                         path.string().c_str());
            return false;
        }
        (void)fn(buf);
    }

    // Exercise degenerate boundary inputs (empty and 1-byte).
    const std::byte one_byte{0};
    (void)fn({});
    (void)fn(std::span<const std::byte>{&one_byte, 1});
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    const std::filesystem::path root =
        (argc > 1) ? std::filesystem::path{argv[1]}
                   : std::filesystem::path{YANTERM_SSH_FUZZ_CORPUS_DIR};

    if (!replay_directory(root / "keys", &yanterm::ssh::fuzz::fuzz_keys_one)) {
        return 1;
    }
    if (!replay_directory(root / "wire", &yanterm::ssh::fuzz::fuzz_wire_one)) {
        return 1;
    }
    if (!replay_directory(root / "connection_prekex",
                          &yanterm::ssh::fuzz::fuzz_connection_prekex_one)) {
        return 1;
    }
    if (!replay_directory(root / "sftp", &yanterm::ssh::fuzz::fuzz_sftp_one)) {
        return 1;
    }
    return 0;
}
