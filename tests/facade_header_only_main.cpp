#include <yanterm-ssh/channel.hpp>
#include <yanterm-ssh/session.hpp>

int touch_facade_a();

int main() {
    const int a = touch_facade_a();
    const int b = static_cast<int>(std::error_code{} == yanterm::ssh::errc::transport_failed);
    yanterm::ssh::client_session sess;
    (void)sess.failure_detail();
    return (a == 0 && b == 0) ? 0 : 1;
}
