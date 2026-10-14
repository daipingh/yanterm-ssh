# Statically link libgcc/libstdc++ into test/tool binaries.
# With ENABLE_ASAN, also static-link libasan/libubsan. GCC's driver still
# emits libubsan.a after libstdc++.a; --whole-archive stdc++ pulls in
# __dynamic_cast that ubsan needs.
function(yanterm_ssh_link_static_libstdcxx target)
    if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        return()
    endif()

    if(YANTERM_SSH_STATIC_LIBSTDCXX)
        unset(options)
        if(YANTERM_SSH_ENABLE_ASAN)
            list(APPEND options "-static-libasan" "-static-libubsan")
            if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
                list(APPEND options "-Wl,-Bstatic,--whole-archive,-lstdc++,--no-whole-archive,-Bdynamic")
            endif()
        endif()
        list(APPEND options "-static-libgcc" "-static-libstdc++")
        target_link_options(${target} PRIVATE ${options})
    endif()
endfunction()
