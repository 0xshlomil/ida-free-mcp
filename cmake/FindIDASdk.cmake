# FindIDASdk.cmake - Locate the IDA SDK
#
# Usage:
#   find_package(IDASdk REQUIRED)
#
# Sets:
#   IDASDK_FOUND        - TRUE if the SDK was found
#   IDASDK_INCLUDE_DIRS - Include directories
#   IDASDK_LIBRARIES    - Libraries to link
#   IDASDK_LIB_DIR      - Library directory for the current platform

# Allow setting via environment variable or CMake variable
if(NOT IDASDK)
    set(IDASDK "$ENV{IDASDK}")
endif()

if(NOT IDASDK)
    message(FATAL_ERROR
        "IDA SDK not found. Set IDASDK environment variable or pass -DIDASDK=/path/to/sdk")
endif()

# Verify the SDK directory exists
if(NOT EXISTS "${IDASDK}/include/ida.hpp")
    message(FATAL_ERROR "Invalid IDA SDK path: ${IDASDK} (ida.hpp not found)")
endif()

set(IDASDK_INCLUDE_DIRS "${IDASDK}/include")

# Determine platform-specific library directory
if(WIN32)
    set(_IDA_PLATFORM "win")
    set(_IDA_LIB_SUFFIX ".lib")
elseif(APPLE)
    set(_IDA_PLATFORM "mac")
    set(_IDA_LIB_SUFFIX ".dylib")
else()
    set(_IDA_PLATFORM "linux")
    set(_IDA_LIB_SUFFIX ".so")
endif()

# Determine architecture prefix (override with -DIDA_ARCH=arm64|x64 for multi-arch builds)
if(DEFINED IDA_ARCH)
    set(_IDA_ARCH "${IDA_ARCH}")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64|ARM64")
    set(_IDA_ARCH "arm64")
else()
    set(_IDA_ARCH "x64")
endif()

# IDA 9.0+ uses {arch}_{platform}_{compiler}_64 for 64-bit plugins
# Try compiler-specific directories first, then fall back to generic
if(WIN32 AND MSVC)
    set(IDASDK_LIB_DIR "${IDASDK}/lib/${_IDA_ARCH}_${_IDA_PLATFORM}_vc_64")
elseif(APPLE)
    set(IDASDK_LIB_DIR "${IDASDK}/lib/${_IDA_ARCH}_${_IDA_PLATFORM}_clang_64")
endif()

if(NOT IDASDK_LIB_DIR OR NOT EXISTS "${IDASDK_LIB_DIR}")
    set(IDASDK_LIB_DIR "${IDASDK}/lib/${_IDA_ARCH}_${_IDA_PLATFORM}_gcc_64")
endif()

# Fallback to alternative directory names
if(NOT EXISTS "${IDASDK_LIB_DIR}")
    set(IDASDK_LIB_DIR "${IDASDK}/lib/${_IDA_ARCH}_${_IDA_PLATFORM}_64")
endif()

if(NOT EXISTS "${IDASDK_LIB_DIR}")
    # Try to find any matching lib dir
    file(GLOB _IDA_LIB_DIRS "${IDASDK}/lib/${_IDA_ARCH}_${_IDA_PLATFORM}*")
    if(_IDA_LIB_DIRS)
        list(GET _IDA_LIB_DIRS 0 IDASDK_LIB_DIR)
    endif()
endif()

# Find ida library
find_library(IDASDK_IDA_LIBRARY
    NAMES ida
    PATHS "${IDASDK_LIB_DIR}"
    NO_DEFAULT_PATH
)

if(IDASDK_IDA_LIBRARY)
    set(IDASDK_LIBRARIES "${IDASDK_IDA_LIBRARY}")
else()
    # On Linux, we may need to link against libida.so at runtime
    # The library might only exist in the IDA installation directory
    set(IDASDK_LIBRARIES "")
    message(STATUS "IDA library not found in SDK (will link at runtime): ${IDASDK_LIB_DIR}")
endif()

set(IDASDK_FOUND TRUE)

message(STATUS "IDA SDK found: ${IDASDK}")
message(STATUS "IDA SDK includes: ${IDASDK_INCLUDE_DIRS}")
message(STATUS "IDA SDK lib dir: ${IDASDK_LIB_DIR}")
