// Second translation unit that includes every public header. Together with
// header_only_consumer_main.cpp this catches missing `inline` on namespace-scope
// functions and variables, which only shows up as a duplicate symbol at link time.
#include "header_only_all_headers.hpp"

int touch_headers_a() {
    struct : yanterm::ssh::core::handler {} app;
    yanterm::ssh::core::connection conn(yanterm::ssh::core::role::client, {}, {}, app);
    (void)conn.failure_detail();
    return static_cast<int>(std::error_code{} == yanterm::ssh::errc::transport_failed);
}
