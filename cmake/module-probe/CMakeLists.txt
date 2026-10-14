cmake_minimum_required(VERSION 3.28)
project(yanterm_ssh_module_probe LANGUAGES CXX)

cmake_policy(SET CMP0155 NEW)

add_library(yanterm-ssh-module-probe STATIC)
target_sources(yanterm-ssh-module-probe
    PUBLIC
        FILE_SET CXX_MODULES
        FILES probe.cppm
)
target_compile_features(yanterm-ssh-module-probe PUBLIC cxx_std_20)
set_target_properties(yanterm-ssh-module-probe PROPERTIES
    CXX_SCAN_FOR_MODULES ON
)

add_executable(yanterm-ssh-module-probe-importer importer.cpp)
target_link_libraries(yanterm-ssh-module-probe-importer
    PRIVATE yanterm-ssh-module-probe
)
set_target_properties(yanterm-ssh-module-probe-importer PROPERTIES
    CXX_SCAN_FOR_MODULES ON
)
