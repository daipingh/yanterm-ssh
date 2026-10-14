function(yanterm_ssh_probe_modules out_var)
    set(${out_var} FALSE PARENT_SCOPE)

    if(CMAKE_VERSION VERSION_LESS "3.28")
        message(STATUS "yanterm-ssh: module smoke skipped (CMake < 3.28)")
        return()
    endif()
    if(NOT CMAKE_GENERATOR MATCHES "^Ninja")
        message(STATUS "yanterm-ssh: module smoke skipped (generator is not Ninja)")
        return()
    endif()

    execute_process(
        COMMAND "${CMAKE_MAKE_PROGRAM}" --version
        RESULT_VARIABLE _ninja_result
        OUTPUT_VARIABLE _ninja_version
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if(NOT _ninja_result EQUAL 0 OR _ninja_version VERSION_LESS "1.11")
        message(STATUS "yanterm-ssh: module smoke skipped (Ninja < 1.11)")
        return()
    endif()

    set(_probe_flags "-DCMAKE_CXX_STANDARD=20")
    if(CMAKE_CXX_COMPILER)
        list(APPEND _probe_flags
            "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
        )
    endif()
    if(CMAKE_CXX_COMPILER_CLANG_SCAN_DEPS)
        list(APPEND _probe_flags
            "-DCMAKE_CXX_COMPILER_CLANG_SCAN_DEPS=${CMAKE_CXX_COMPILER_CLANG_SCAN_DEPS}"
        )
    endif()
    if(NOT CMAKE_CXX_FLAGS STREQUAL "")
        list(APPEND _probe_flags
            "-DCMAKE_CXX_FLAGS=${CMAKE_CXX_FLAGS}"
        )
    endif()
    if(CMAKE_TOOLCHAIN_FILE)
        list(APPEND _probe_flags
            "-DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}"
        )
    endif()

    # Run the probe in a child CMake. try_compile turns a generate-time failure
    # (compiler has no C++ module dependency scanner) into a fatal error in the
    # parent project, so the skip below never runs. A child process keeps that
    # failure local: non-zero means the probe failed and module tests are skipped.
    set(_probe_bin "${CMAKE_CURRENT_BINARY_DIR}/module-probe")
    execute_process(
        COMMAND "${CMAKE_COMMAND}"
            -S "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/module-probe"
            -B "${_probe_bin}"
            -G "${CMAKE_GENERATOR}"
            "-DCMAKE_MAKE_PROGRAM=${CMAKE_MAKE_PROGRAM}"
            ${_probe_flags}
        RESULT_VARIABLE _probe_configure
        OUTPUT_VARIABLE _module_probe_output
        ERROR_VARIABLE _module_probe_error
    )
    set(_probe_build 1)
    if(_probe_configure EQUAL 0)
        execute_process(
            COMMAND "${CMAKE_COMMAND}" --build "${_probe_bin}"
                --target yanterm-ssh-module-probe-importer
            RESULT_VARIABLE _probe_build
            OUTPUT_VARIABLE _module_probe_build_output
            ERROR_VARIABLE _module_probe_build_error
        )
    endif()
    if(NOT _probe_configure EQUAL 0 OR NOT _probe_build EQUAL 0)
        message(STATUS "yanterm-ssh: module smoke skipped (probe failed)")
        if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
            if(NOT CMAKE_CXX_COMPILER_CLANG_SCAN_DEPS OR
               NOT EXISTS "${CMAKE_CXX_COMPILER_CLANG_SCAN_DEPS}")
                message(STATUS
                    "yanterm-ssh: Clang C++ modules need clang-scan-deps "
                    "(install clang-tools-18)")
            endif()
        endif()
        return()
    endif()

    set(${out_var} TRUE PARENT_SCOPE)
endfunction()
