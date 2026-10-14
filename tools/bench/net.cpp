#include "net.h"

#include <netdb.h>
#include <sys/socket.h>

#include <string>
#include <tuple>
#include <utility>

namespace bench {
namespace {

std::error_code resolve_host(std::string_view host, int port, auv::sockaddr_in46& out) {
    const std::string h{host};
    out = auv::sockaddr_in46(h, port);
    if (out) return {};

    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_family = AF_UNSPEC;
    addrinfo* res = nullptr;
    const int gai = ::getaddrinfo(h.c_str(), nullptr, &hints, &res);
    if (gai != 0 || res == nullptr || res->ai_addr == nullptr) {
        if (res) ::freeaddrinfo(res);
        return std::make_error_code(std::errc::host_unreachable);
    }
    out = auv::sockaddr_in46(res->ai_addr, port);
    ::freeaddrinfo(res);
    if (!out) return std::make_error_code(std::errc::address_family_not_supported);
    return {};
}

}  // namespace

void drain_and_close(uv_loop_t& loop) {
    uv_run(&loop, UV_RUN_DEFAULT);
    if (uv_loop_close(&loop) == 0) return;
    uv_walk(
        &loop,
        [](uv_handle_t* h, void*) {
            if (!uv_is_closing(h)) uv_close(h, nullptr);
        },
        nullptr);
    uv_run(&loop, UV_RUN_DEFAULT);
    uv_loop_close(&loop);
}

tcp_listener::tcp_listener(uv_loop_t& loop, std::string_view bind_addr, int port)
    : loop_(&loop) {
    auto tcp = auv::resource_tcp(&loop);
    const std::string addr{bind_addr};
    auv::sockaddr_in46 sa(addr, port);
    if (!sa) {
        error_ = std::make_error_code(std::errc::invalid_argument);
        return;
    }
    int r = uv_tcp_bind(tcp.get(), sa.get(), 0);
    if (r < 0) {
        error_ = auv::make_uv_error_code(r);
        return;
    }
    sockaddr_storage name{};
    int namelen = sizeof(name);
    r = uv_tcp_getsockname(tcp.get(), reinterpret_cast<sockaddr*>(&name), &namelen);
    if (r < 0) {
        error_ = auv::make_uv_error_code(r);
        return;
    }
    port_ = static_cast<std::uint16_t>(
        auv::sockaddr_in46(reinterpret_cast<sockaddr*>(&name)).port());
    tcp->data = this;
    r = uv_listen(reinterpret_cast<uv_stream_t*>(tcp.get()), 128, &on_connection);
    if (r < 0) {
        error_ = auv::make_uv_error_code(r);
        return;
    }
    server_ = std::move(tcp);
}

tcp_listener::~tcp_listener() {
    if (server_) server_->data = nullptr;
}

std::error_code tcp_listener::error() const noexcept { return error_; }

std::uint16_t tcp_listener::local_port() const noexcept { return port_; }

void tcp_listener::on_connection(uv_stream_t* server, int status) {
    auto* self = static_cast<tcp_listener*>(server->data);
    if (!self) return;
    if (status < 0) {
        self->listen_status_ = status;
        self->waiters_.unparkAll();
        return;
    }
    self->pending_ += 1;
    self->waiters_.unparkOne();
}

using stream_result = std::tuple<std::error_code, auv::stream>;

corral::Task<stream_result> tcp_listener::accept() {
    if (error_) co_return stream_result{error_, auv::stream{}};
    if (!server_) {
        co_return stream_result{std::make_error_code(std::errc::not_connected), auv::stream{}};
    }
    while (pending_ <= 0 && listen_status_ == 0) {
        co_await waiters_.park();
    }
    if (pending_ <= 0) {
        co_return stream_result{
            auv::make_uv_error_code(listen_status_ ? listen_status_ : UV_EINVAL), auv::stream{}};
    }
    pending_ -= 1;
    auto client = auv::resource_tcp(loop_);
    const int r = uv_accept(reinterpret_cast<uv_stream_t*>(server_.get()),
                            reinterpret_cast<uv_stream_t*>(client.get()));
    if (r < 0) co_return stream_result{auv::make_uv_error_code(r), auv::stream{}};
    (void)uv_tcp_nodelay(client.get(), 1);
    co_return stream_result{std::error_code{},
                            auv::stream::own(auv::make_uv_stream(std::move(client)))};
}

corral::Task<stream_result> tcp_connect(uv_loop_t& loop, std::string_view host, int port) {
    auv::sockaddr_in46 sa;
    if (auto ec = resolve_host(host, port, sa)) {
        co_return stream_result{ec, auv::stream{}};
    }
    auto tcp = auv::resource_tcp(&loop);
    (void)uv_tcp_nodelay(tcp.get(), 1);
    const int r = co_await auv::connect(tcp.get(), std::as_const(sa));
    if (r < 0) co_return stream_result{auv::make_uv_error_code(r), auv::stream{}};
    co_return stream_result{std::error_code{},
                            auv::stream::own(auv::make_uv_stream(std::move(tcp)))};
}

}  // namespace bench
