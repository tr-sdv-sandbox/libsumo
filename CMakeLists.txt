cmake_minimum_required(VERSION 3.14)
project(libsumo VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Options ---
option(SUMO_BUILD_ONBOARD   "Build device-side library (C99)"     ON)
option(SUMO_BUILD_OFFBOARD  "Build server-side library (C++17)"   ON)
option(SUMO_BUILD_TOOLS     "Build CLI tools"                     OFF)
option(SUMO_BUILD_TESTS     "Build tests"                         OFF)

option(SUMO_CRYPTO_MBEDTLS  "Use mbedTLS crypto backend"          OFF)
option(SUMO_CRYPTO_OPENSSL  "Use OpenSSL crypto backend"          ON)

# --- 3rdparty: libcsuit (Makefile-based, builds QCBOR + t_cose + libcsuit) ---
set(LIBCSUIT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/libcsuit)
set(QCBOR_DIR    ${LIBCSUIT_DIR}/3rdparty/QCBOR)
set(TCOSE_DIR    ${LIBCSUIT_DIR}/3rdparty/t_cose)

if(SUMO_CRYPTO_MBEDTLS)
    set(LIBCSUIT_MBEDTLS_FLAG "MBEDTLS=1")
    set(MBEDTLS_DIR ${LIBCSUIT_DIR}/3rdparty/mbedtls)
else()
    set(LIBCSUIT_MBEDTLS_FLAG "MBEDTLS=0")
endif()

# Build libcsuit and its dependencies via their Makefile
include(ExternalProject)
ExternalProject_Add(libcsuit_ext
    SOURCE_DIR       ${LIBCSUIT_DIR}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND     ${CMAKE_COMMAND} -E env
        "CFLAGS=-Os -DSUIT_MAX_DEPENDENCY_NUM=4 -DSUIT_MAX_ARRAY_LENGTH=24"
        make -C ${LIBCSUIT_DIR} build_deps ${LIBCSUIT_MBEDTLS_FLAG}
        && ${CMAKE_COMMAND} -E env
        "CFLAGS=-Os -DSUIT_MAX_DEPENDENCY_NUM=4 -DSUIT_MAX_ARRAY_LENGTH=24"
        make -C ${LIBCSUIT_DIR} libcsuit.a ${LIBCSUIT_MBEDTLS_FLAG}
    INSTALL_COMMAND   ""
    BUILD_IN_SOURCE   TRUE
    BUILD_BYPRODUCTS
        ${LIBCSUIT_DIR}/libcsuit.a
        ${QCBOR_DIR}/libqcbor.a
        ${TCOSE_DIR}/libt_cose.a
)

# Import pre-built static libraries
add_library(qcbor STATIC IMPORTED)
set_target_properties(qcbor PROPERTIES
    IMPORTED_LOCATION ${QCBOR_DIR}/libqcbor.a
    INTERFACE_INCLUDE_DIRECTORIES ${QCBOR_DIR}/inc
)

add_library(t_cose STATIC IMPORTED)
set_target_properties(t_cose PROPERTIES
    IMPORTED_LOCATION ${TCOSE_DIR}/libt_cose.a
    INTERFACE_INCLUDE_DIRECTORIES ${TCOSE_DIR}/inc
)

add_library(csuit STATIC IMPORTED)
set_target_properties(csuit PROPERTIES
    IMPORTED_LOCATION ${LIBCSUIT_DIR}/libcsuit.a
    INTERFACE_INCLUDE_DIRECTORIES ${LIBCSUIT_DIR}/inc
)
add_dependencies(csuit libcsuit_ext)

# Crypto backend
if(SUMO_CRYPTO_MBEDTLS)
    add_library(mbedcrypto STATIC IMPORTED)
    set_target_properties(mbedcrypto PROPERTIES
        IMPORTED_LOCATION ${MBEDTLS_DIR}/library/libmbedcrypto.a
        INTERFACE_INCLUDE_DIRECTORIES ${MBEDTLS_DIR}/include
    )
    set(SUMO_CRYPTO_LIB mbedcrypto)
else()
    find_package(OpenSSL REQUIRED)
    set(SUMO_CRYPTO_LIB OpenSSL::Crypto)
endif()

# Bundle all 3rdparty libs into one interface target for convenience
add_library(sumo_3rdparty INTERFACE)
target_link_libraries(sumo_3rdparty INTERFACE csuit t_cose qcbor ${SUMO_CRYPTO_LIB} m)
# Must match the CFLAGS passed to libcsuit build above
target_compile_definitions(sumo_3rdparty INTERFACE
    SUIT_MAX_DEPENDENCY_NUM=4
    SUIT_MAX_ARRAY_LENGTH=24
)

# --- Onboard (device-side, C99) ---
if(SUMO_BUILD_ONBOARD)
    add_subdirectory(onboard)
endif()

# --- Offboard (server-side, C++17) ---
if(SUMO_BUILD_OFFBOARD)
    add_subdirectory(offboard)
endif()

# --- CLI Tools ---
if(SUMO_BUILD_TOOLS)
    add_subdirectory(tools)
endif()

# --- Tests ---
if(SUMO_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
