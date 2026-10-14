#include "header_only_all_headers.hpp"

int touch_headers_a();

int main() {
    const int a = touch_headers_a();
    const int b = static_cast<int>(std::error_code{} == yanterm::ssh::errc::transport_failed);
    struct : yanterm::ssh::core::handler {} app;
    yanterm::ssh::core::connection conn(yanterm::ssh::core::role::client, {}, {}, app);
    (void)conn.failure_detail();
    return (a == 0 && b == 0) ? 0 : 1;
}
