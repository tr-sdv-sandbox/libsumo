# libsum2 offboard — server-side SUIT manifest generation & signing (C++17)

add_library(sum2_offboard STATIC
    src/image_builder.cpp
    src/campaign_builder.cpp
    src/encryptor.cpp
    src/keygen.cpp
)

target_include_directories(sum2_offboard
    PUBLIC  include
    PRIVATE ${CMAKE_SOURCE_DIR}/3rdparty/libcsuit/inc
            ${CMAKE_SOURCE_DIR}/3rdparty/libcsuit/3rdparty/QCBOR/inc
            ${CMAKE_SOURCE_DIR}/3rdparty/libcsuit/3rdparty/t_cose/inc
)

target_link_libraries(sum2_offboard
    PUBLIC  csuit
)
