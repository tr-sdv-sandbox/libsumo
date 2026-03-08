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

# --- E2E tests (offboard build → onboard validate + decrypt) ---
add_executable(sum2_e2e_tests
    e2e/e2e_test.cpp
)

target_link_libraries(sum2_e2e_tests PRIVATE
    sum2_offboard
    sum2_onboard
    sum2_3rdparty
    GTest::gtest
    GTest::gtest_main
)

gtest_discover_tests(sum2_e2e_tests)
