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

target_link_libraries(sum2_offboard
    PUBLIC  sum2_3rdparty
)
