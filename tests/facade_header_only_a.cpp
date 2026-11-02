#include <yanterm-ssh/channel.hpp>
#include <yanterm-ssh/session.hpp>
#include <yanterm-ssh/sftp.hpp>

int touch_facade_a() {
    yanterm::ssh::client_session sess;
    (void)sess.failure_detail();
    return static_cast<int>(std::error_code{} == yanterm::ssh::errc::transport_failed);
}
