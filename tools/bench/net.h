#pragma once

#include <auv/uv.hpp>
#include <corral/ParkingLot.h>
#include <corral/Task.h>
#include <uv.h>

#include <cstdint>
#include <memory>
#include <string_view>
#include <system_error>
#include <tuple>

namespace bench {

corral::Task<std::tuple<std::error_code, auv::stream>> tcp_connect(
    uv_loop_t& loop, std::string_view host, int port);

class tcp_listener {
public:
    tcp_listener(uv_loop_t& loop, std::string_view bind_addr, int port);
    tcp_listener(const tcp_listener&) = delete;
    tcp_listener& operator=(const tcp_listener&) = delete;
    tcp_listener(tcp_listener&&) = delete;
    tcp_listener& operator=(tcp_listener&&) = delete;
    ~tcp_listener();

    [[nodiscard]] std::error_code error() const noexcept;
    [[nodiscard]] std::uint16_t local_port() const noexcept;   // port=0 时为内核分配值
    corral::Task<std::tuple<std::error_code, auv::stream>> accept();

private:
    uv_loop_t* loop_ = nullptr;
    std::unique_ptr<uv_tcp_t, auv::handle_deleter> server_;
    std::error_code error_{};
    std::uint16_t port_ = 0;
    int pending_ = 0;
    int listen_status_ = 0;
    corral::ParkingLot waiters_;

    static void on_connection(uv_stream_t* server, int status);
};

void drain_and_close(uv_loop_t& loop);

}  // namespace bench
