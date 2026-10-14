#include <catch2/catch_test_macros.hpp>

#include <yanterm-ssh/crypto/openssl.hpp>
#include <yanterm-ssh/error.hpp>
#include <yanterm-ssh/keys/io.hpp>
#include <yanterm-ssh/keys/private_key.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#ifndef YANTERM_SSH_FIXTURE_DIR
#error "YANTERM_SSH_FIXTURE_DIR must be defined"
#endif

using namespace yanterm::ssh;

namespace {

crypto::provider prov() {
    static crypto::openssl_backend backend;
    return crypto::provider::wrap(backend);
}


struct tmp_sandbox {
    std::filesystem::path dir;

    tmp_sandbox() {
        auto tmpl = (std::filesystem::temp_directory_path() / "yanterm-ssh-io-XXXXXX").string();
        std::vector<char> buf(tmpl.begin(), tmpl.end());
        buf.push_back('\0');
        char* created = ::mkdtemp(buf.data());
        REQUIRE(created != nullptr);
        dir = created;
    }

    tmp_sandbox(const tmp_sandbox&) = delete;
    tmp_sandbox& operator=(const tmp_sandbox&) = delete;

    ~tmp_sandbox() {
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }

    std::string file(std::string_view name) const { return (dir / std::string{name}).string(); }
};

void write_mode(const std::string& path, std::string_view data, mode_t mode) {
    std::ofstream out{path, std::ios::binary | std::ios::trunc};
    REQUIRE(out);
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    REQUIRE(out);
    out.close();
    REQUIRE(::chmod(path.c_str(), mode) == 0);
}

std::vector<std::byte> load_fixture(std::string_view name) {
    const std::string path = std::string{YANTERM_SSH_FIXTURE_DIR} + "/" + std::string{name};
    std::ifstream in{path, std::ios::binary};
    REQUIRE(in);
    in.seekg(0, std::ios::end);
    const auto n = static_cast<std::size_t>(in.tellg());
    in.seekg(0, std::ios::beg);
    std::vector<std::byte> out(n);
    if (n > 0) {
        in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(n));
        REQUIRE(in);
    }
    return out;
}

}  // namespace

TEST_CASE("check_private_key_permissions rejects group/other bits", "[keys][io]") {
    tmp_sandbox tmp;
    const auto path = tmp.file("open.key");
    write_mode(path, "secret", 0644);
    REQUIRE(keys::io::check_private_key_permissions(path.c_str())
            == errc::insecure_permissions);
}

TEST_CASE("check_private_key_permissions accepts 0600", "[keys][io]") {
    tmp_sandbox tmp;
    const auto path = tmp.file("closed.key");
    write_mode(path, "secret", 0600);
    REQUIRE_FALSE(keys::io::check_private_key_permissions(path.c_str()));
}

TEST_CASE("atomic_write then read_file round-trips bytes", "[keys][io]") {
    tmp_sandbox tmp;
    const auto path = tmp.file("atomic.bin");
    const char payload[] = "hello atomic\nsecond line";
    const auto data = std::span<const std::byte>{
        reinterpret_cast<const std::byte*>(payload), sizeof(payload) - 1};
    REQUIRE_FALSE(keys::io::atomic_write(path.c_str(), data));
    std::vector<std::byte> back;
    REQUIRE_FALSE(keys::io::read_file(path.c_str(), back));
    REQUIRE(back.size() == data.size());
    REQUIRE(std::equal(data.begin(), data.end(), back.begin()));
    REQUIRE_FALSE(std::filesystem::exists(path + ".tmp"));
}

TEST_CASE("load_private_key refuses 0644 before parse", "[keys][io]") {
    tmp_sandbox tmp;
    const auto armored = load_fixture("id_ed25519");
    const auto path = tmp.file("id_ed25519");
    write_mode(path,
               std::string_view{reinterpret_cast<const char*>(armored.data()), armored.size()},
               0644);

    crypto::provider p = prov();
    keys::private_key k;
    REQUIRE(keys::io::load_private_key(path.c_str(), p, {}, k)
            == errc::insecure_permissions);
}

TEST_CASE("load_private_key parses 0600 armored OPENSSH PRIVATE KEY", "[keys][io]") {
    tmp_sandbox tmp;
    const auto armored = load_fixture("id_ed25519");
    const auto text = std::string_view{reinterpret_cast<const char*>(armored.data()),
                                       armored.size()};
    REQUIRE(text.find("-----BEGIN OPENSSH PRIVATE KEY-----") != std::string_view::npos);
    REQUIRE(text.find("-----END OPENSSH PRIVATE KEY-----") != std::string_view::npos);

    const auto path = tmp.file("id_ed25519");
    write_mode(path, text, 0600);

    crypto::provider p = prov();
    keys::private_key from_mem;
    REQUIRE_FALSE(keys::private_key::parse(armored, p, {}, from_mem));
    keys::private_key from_disk;
    REQUIRE_FALSE(keys::io::load_private_key(path.c_str(), p, {}, from_disk));
    REQUIRE(std::equal(from_mem.pub().blob().begin(), from_mem.pub().blob().end(),
                       from_disk.pub().blob().begin(), from_disk.pub().blob().end()));
}
