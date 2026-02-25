cmake_minimum_required(VERSION 3.16)
project(ida_mcp VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Use dynamic CRT on MSVC (must match IDA's runtime)
if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL")
endif()

option(BUILD_TESTS "Build unit tests" ON)
option(BUILD_PLUGIN "Build IDA plugin (requires IDA SDK)" ON)

# ─── Find IDA SDK (only if building plugin) ─────────────────────
if(BUILD_PLUGIN)
    list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
    find_package(IDASdk REQUIRED)

    # ─── Platform defines ───────────────────────────────────────
    if(WIN32)
        set(IDA_PLATFORM_DEFINE "__NT__")
    elseif(APPLE)
        set(IDA_PLATFORM_DEFINE "__MAC__")
    else()
        set(IDA_PLATFORM_DEFINE "__LINUX__")
    endif()

    # ─── Plugin target ──────────────────────────────────────────
    set(PLUGIN_SOURCES
        src/plugin.cpp
        src/jsonrpc.cpp
        src/server.cpp
        src/mcp.cpp
        src/sync.cpp
        src/dialog_suppress.cpp
        src/utils.cpp
        src/tools/core.cpp
        src/tools/analysis.cpp
        src/tools/memory.cpp
        src/tools/modify.cpp
        src/tools/types.cpp
        src/tools/stack.cpp
        src/tools/decompiler.cpp
        src/resources/resources.cpp
    )

    add_library(ida_mcp SHARED ${PLUGIN_SOURCES})

    # No "lib" prefix on the output
    set_target_properties(ida_mcp PROPERTIES
        PREFIX ""
        OUTPUT_NAME "ida_mcp"
    )

    # Platform-specific suffix
    if(WIN32)
        set_target_properties(ida_mcp PROPERTIES SUFFIX ".dll")
    elseif(APPLE)
        set_target_properties(ida_mcp PROPERTIES SUFFIX ".dylib")
    else()
        set_target_properties(ida_mcp PROPERTIES SUFFIX ".so")
    endif()

    target_include_directories(ida_mcp PRIVATE
        ${IDASDK_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}/deps
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )

    target_compile_definitions(ida_mcp PRIVATE
        __IDP__
        __PLUGIN__
        __EA64__
        ${IDA_PLATFORM_DEFINE}
        # cpp-httplib: disable SSL (we don't need it for localhost)
        CPPHTTPLIB_NO_OPENSSL
    )

    # MSVC-specific compile options
    if(MSVC)
        target_compile_options(ida_mcp PRIVATE
            /W3 /utf-8 /EHsc /permissive-
            /wd4267  # size_t to int conversion (IDA SDK / vendor headers)
            /wd4244  # narrowing conversions
            /wd4996  # deprecated CRT functions
        )
    endif()

    if(IDASDK_LIBRARIES)
        target_link_libraries(ida_mcp PRIVATE ${IDASDK_LIBRARIES})
    endif()

    # Platform-specific link flags
    if(WIN32)
        target_link_libraries(ida_mcp PRIVATE ws2_32)
    else()
        target_link_libraries(ida_mcp PRIVATE pthread)
        if(NOT APPLE)
            # Linux: allow undefined symbols (resolved by IDA at load time)
            target_link_options(ida_mcp PRIVATE
                "LINKER:--allow-shlib-undefined"
                "LINKER:--unresolved-symbols=ignore-all"
            )
        else()
            target_link_options(ida_mcp PRIVATE
                "LINKER:-undefined,dynamic_lookup"
            )
        endif()
    endif()
endif()

# ─── Unit Tests (no IDA SDK required) ───────────────────────────
if(BUILD_TESTS)
    enable_testing()

    add_executable(ida_mcp_tests
        tests/test_main.cpp
        tests/test_jsonrpc.cpp
        tests/test_utils.cpp
        # Sources under test (IDA-independent parts)
        src/jsonrpc.cpp
        src/utils.cpp
    )

    target_include_directories(ida_mcp_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/deps
        ${CMAKE_CURRENT_SOURCE_DIR}/src
    )

    target_compile_definitions(ida_mcp_tests PRIVATE
        IDA_MCP_TESTING
        __EA64__
        CPPHTTPLIB_NO_OPENSSL
        CPPHTTPLIB_NO_EXCEPTIONS
    )

    if(MSVC)
        target_compile_options(ida_mcp_tests PRIVATE
            /W3 /utf-8 /EHsc /permissive-
            /wd4267 /wd4244 /wd4996
        )
    endif()

    if(WIN32)
        target_link_libraries(ida_mcp_tests PRIVATE ws2_32)
    else()
        target_link_libraries(ida_mcp_tests PRIVATE pthread)
    endif()

    add_test(NAME unit_tests COMMAND ida_mcp_tests)
endif()
