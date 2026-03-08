cmake_minimum_required(VERSION 3.14)
project(libsum2 VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Options ---
option(SUM2_BUILD_ONBOARD   "Build device-side library (C99)"     ON)
option(SUM2_BUILD_OFFBOARD  "Build server-side library (C++17)"   ON)
option(SUM2_BUILD_TOOLS     "Build CLI tools"                     OFF)
option(SUM2_BUILD_TESTS     "Build tests"                         OFF)

option(SUM2_CRYPTO_MBEDTLS  "Use mbedTLS crypto backend"          OFF)
option(SUM2_CRYPTO_OPENSSL  "Use OpenSSL crypto backend"          ON)

# --- 3rdparty: libcsuit (brings QCBOR + t_cose) ---
# libcsuit's own CMake handles QCBOR and t_cose submodules
if(SUM2_CRYPTO_MBEDTLS)
    set(MBEDTLS ON CACHE BOOL "Use MbedTLS in libcsuit" FORCE)
endif()
add_subdirectory(3rdparty/libcsuit)

# --- Onboard (device-side, C99) ---
if(SUM2_BUILD_ONBOARD)
    add_subdirectory(onboard)
endif()

# --- Offboard (server-side, C++17) ---
if(SUM2_BUILD_OFFBOARD)
    add_subdirectory(offboard)
endif()

# --- CLI Tools ---
if(SUM2_BUILD_TOOLS)
    add_subdirectory(tools)
endif()

# --- Tests ---
if(SUM2_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
