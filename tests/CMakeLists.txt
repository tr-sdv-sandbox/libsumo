# libsum2 tests — requires GTest
find_package(GTest REQUIRED)

set(LIBCSUIT_TESTFILES "${CMAKE_SOURCE_DIR}/3rdparty/libcsuit/testfiles")

# --- Onboard tests (validator + decryptor, C API tested from C++) ---
add_executable(sum2_onboard_tests
    onboard/validator_test.cpp
    onboard/decryptor_test.cpp
    onboard/decryptor_test_helper.c
)

target_link_libraries(sum2_onboard_tests PRIVATE
    sum2_onboard
    sum2_3rdparty
    GTest::gtest
    GTest::gtest_main
)

target_compile_definitions(sum2_onboard_tests PRIVATE
    LIBCSUIT_TESTFILES="${LIBCSUIT_TESTFILES}"
)

gtest_discover_tests(sum2_onboard_tests)
