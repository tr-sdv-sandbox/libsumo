# libsum2 onboard — device-side SUIT manifest validation & decryption (C99)

add_library(sum2_onboard STATIC
    src/validator.c
    src/decryptor.c
    src/decompressor.c
    src/policy.c
    src/orchestrator.c
)

target_include_directories(sum2_onboard
    PUBLIC  include
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(ZSTD REQUIRED libzstd)

target_link_libraries(sum2_onboard
    PUBLIC  sum2_3rdparty ${ZSTD_LIBRARIES}
)
target_include_directories(sum2_onboard PRIVATE ${ZSTD_INCLUDE_DIRS})

# Platform sources — select one at build time
if(SUM2_PLATFORM_ESP32)
    target_sources(sum2_onboard PRIVATE platform/platform_esp32.c)
    target_compile_definitions(sum2_onboard PRIVATE SUM2_PLATFORM_ESP32=1)
elseif(SUM2_PLATFORM_ZEPHYR)
    target_sources(sum2_onboard PRIVATE platform/platform_zephyr.c)
    target_compile_definitions(sum2_onboard PRIVATE SUM2_PLATFORM_ZEPHYR=1)
else()
    target_sources(sum2_onboard PRIVATE platform/platform_linux.c)
    target_compile_definitions(sum2_onboard PRIVATE SUM2_PLATFORM_LINUX=1)
endif()
