# libsumo tests — requires GTest
find_package(GTest REQUIRED)

set(LIBCSUIT_TESTFILES "${CMAKE_SOURCE_DIR}/3rdparty/libcsuit/testfiles")

# --- Onboard tests (validator + decryptor, C API tested from C++) ---
add_executable(sumo_onboard_tests
    onboard/validator_test.cpp
    onboard/decryptor_test.cpp
    onboard/decryptor_test_helper.c
)

target_link_libraries(sumo_onboard_tests PRIVATE
    sumo_onboard
    sumo_3rdparty
    GTest::gtest
    GTest::gtest_main
)

target_compile_definitions(sumo_onboard_tests PRIVATE
    LIBCSUIT_TESTFILES="${LIBCSUIT_TESTFILES}"
)

gtest_discover_tests(sumo_onboard_tests)

# --- E2E tests (offboard build → onboard validate + decrypt) ---
add_executable(sumo_e2e_tests
    e2e/e2e_test.cpp
    e2e/keygen_e2e_test.cpp
    e2e/campaign_e2e_test.cpp
    e2e/orchestrator_e2e_test.cpp
    e2e/policy_e2e_test.cpp
    e2e/device_id_e2e_test.cpp
    e2e/security_version_e2e_test.cpp
    e2e/multi_device_key_e2e_test.cpp
    e2e/linux_platform_e2e_test.cpp
    e2e/linux_http_fetch_e2e_test.cpp
)

target_link_libraries(sumo_e2e_tests PRIVATE
    sumo_offboard
    sumo_onboard
    sumo_3rdparty
    GTest::gtest
    GTest::gtest_main
)

gtest_discover_tests(sumo_e2e_tests)
