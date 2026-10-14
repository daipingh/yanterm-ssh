import yanterm.ssh;

struct ready_bool {
    bool await_ready() const noexcept { return true; }

    template <class Handle>
    void await_suspend(Handle) const noexcept {}

    bool await_resume() const noexcept { return true; }
};

int main() {
    yanterm::ssh::client_session session;
    auto task = session.handshake(
        [](const yanterm::ssh::host_key_view&) {
            return ready_bool{};
        });
    yanterm::ssh::session_options options;
    yanterm::ssh::channel channel;
    (void)task;
    (void)channel;
    return options.max_channels == 0 ? 1 : 0;
}
