# libsum2 onboard — device-side SUIT manifest validation & decryption (C99)

add_library(sum2_onboard STATIC
    src/validator.c
    src/decryptor.c
    src/policy.c
    src/orchestrator.c
)

target_include_directories(sum2_onboard
    PUBLIC  include
    PRIVATE ${CMAKE_SOURCE_DIR}/3rdparty/libcsuit/inc
            ${CMAKE_SOURCE_DIR}/3rdparty/libcsuit/3rdparty/QCBOR/inc
            ${CMAKE_SOURCE_DIR}/3rdparty/libcsuit/3rdparty/t_cose/inc
)

target_link_libraries(sum2_onboard
    PUBLIC  csuit
)

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
