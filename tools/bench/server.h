#pragma once

#include "options.h"

#include <cstdint>

namespace bench {

int run_server(const server_config&);   // 返回进程退出码

struct channel_transfer {
    std::uint64_t to_client_bytes = 0, to_process_bytes = 0;
    double seconds = 0.0;
};

}
