#include "client.h"
#include "options.h"
#include "server.h"

#include <iostream>
#include <string_view>

#ifndef _WIN32
#include <csignal>
#endif

int main(int argc, char** argv) {
#ifndef _WIN32
    ::signal(SIGPIPE, SIG_IGN);
#endif
    for (int i = 1; i < argc; ++i) {
        const std::string_view a = argv[i];
        if (a == "--help" || a == "-h") {
            std::cout << bench::usage_text();
            return 0;
        }
    }

    std::string error;
    auto parsed = bench::parse_command(argc, argv, error);
    if (!parsed) {
        std::cerr << error;
        if (!error.empty() && error.back() != '\n') std::cerr << '\n';
        return 2;
    }
    switch (parsed->cmd) {
    case bench::subcommand::server:
        return bench::run_server(parsed->server);
    case bench::subcommand::spawn_server:
    case bench::subcommand::spawn_sshd:
    case bench::subcommand::connect:
        return bench::run_client(parsed->client);
    }
    return 2;
}
