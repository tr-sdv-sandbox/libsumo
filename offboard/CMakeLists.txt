# libsum2 offboard — server-side SUIT manifest generation & signing (C++17)

add_library(sum2_offboard STATIC
    src/csuit_wrapper.c
    src/image_builder.cpp
    src/campaign_builder.cpp
    src/encryptor.cpp
    src/keygen.cpp
)

target_include_directories(sum2_offboard
    PUBLIC  include
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(ZSTD REQUIRED libzstd)

target_link_libraries(sum2_offboard
    PUBLIC  sum2_3rdparty ${ZSTD_LIBRARIES}
)
target_include_directories(sum2_offboard PRIVATE ${ZSTD_INCLUDE_DIRS})
