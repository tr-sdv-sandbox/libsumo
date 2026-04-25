# libsumo onboard — device-side SUIT manifest validation & decryption (C99)

add_library(sumo_onboard STATIC
    src/validator.c
    src/decryptor.c
    src/decompressor.c
    src/policy.c
    src/orchestrator.c
)

target_include_directories(sumo_onboard
    PUBLIC  include
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(ZSTD REQUIRED libzstd)

target_link_libraries(sumo_onboard
    PUBLIC  sumo_3rdparty ${ZSTD_LIBRARIES}
)
target_include_directories(sumo_onboard PRIVATE ${ZSTD_INCLUDE_DIRS})

# Platform sources — select one at build time
if(SUMO_PLATFORM_ESP32)
    target_sources(sumo_onboard PRIVATE platform/platform_esp32.c)
    target_compile_definitions(sumo_onboard PRIVATE SUMO_PLATFORM_ESP32=1)
elseif(SUMO_PLATFORM_ZEPHYR)
    target_sources(sumo_onboard PRIVATE platform/platform_zephyr.c)
    target_compile_definitions(sumo_onboard PRIVATE SUMO_PLATFORM_ZEPHYR=1)
else()
    target_sources(sumo_onboard PRIVATE platform/platform_linux.c)
    target_compile_definitions(sumo_onboard PRIVATE SUMO_PLATFORM_LINUX=1)
    # Linux requires libcurl for HTTP(S) fetch. file:// keeps working
    # without it, but we depend on libcurl unconditionally on Linux so
    # the platform backend has a single, predictable feature set.
    find_package(CURL REQUIRED)
    target_link_libraries(sumo_onboard PUBLIC CURL::libcurl)
endif()
