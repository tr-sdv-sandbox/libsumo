/**
 * @file policy_e2e_test.cpp
 * @brief E2E tests for policy persistence: load/save rollback counters.
 *
 * Tests drive the Policy API design. Expected to fail until policy stubs
 * are implemented.
 */
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

#include "sum2/image_builder.h"
#include "sum2/encryptor.h"
#include "sum2/validator.h"
#include "sum2/policy.h"

#include "e2e_test_helpers.h"

class PolicyTest : public ::testing::Test {
protected:
    FakeStorageOps storage_;
};

/**
 * Pre-store a rejection timestamp. After loading, manifests with
 * older trusted_time should be rejected.
 */
TEST_F(PolicyTest, PolicyLoadTimestamp) {
    /* Store reject_before = 1700000000 (Nov 2023) */
    storage_.i64_store["sum2_reject_before"] = 1700000000;

    sum2_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    auto sops = storage_.ops();
    int rc = sum2_policy_load(v, &sops);
    EXPECT_EQ(rc, SUM2_OK);

    /* Build a manifest to test against */
    auto fw = std::vector<uint8_t>(64, 0x11);
    auto digest = sum2::Sha256(fw);
    sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});

    auto envelope = sum2::ImageManifestBuilder()
        .SetComponentId({"ecu-a", "firmware"})
        .SetSequenceNumber(100)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .SetPayloadDigest(digest.data(), digest.size(), fw.size())
        .SetPayloadUri("https://example.com/fw.bin")
        .Build(signing_key);

    /* Validate with trusted_time BEFORE reject_before → should fail */
    sum2_manifest_t *m1 = nullptr;
    rc = sum2_validate_envelope(
        v, envelope.data(), envelope.size(),
        1699999999,  /* 1 second before cutoff */
        &m1);
    EXPECT_EQ(rc, SUM2_ERR_REVOKED)
        << "Should reject: trusted_time < reject_before";
    EXPECT_EQ(m1, nullptr);

    /* Validate with trusted_time AFTER reject_before → should pass */
    sum2_manifest_t *m2 = nullptr;
    rc = sum2_validate_envelope(
        v, envelope.data(), envelope.size(),
        1700000001,  /* 1 second after cutoff */
        &m2);
    EXPECT_EQ(rc, SUM2_OK)
        << "Should accept: trusted_time > reject_before";

    if (m2) sum2_manifest_free(m2);
    sum2_validator_free(v);
}

/**
 * Pre-store a sequence number. After loading, manifests with
 * lower sequence should be rejected.
 */
TEST_F(PolicyTest, PolicyLoadSequenceNumber) {
    /* Store global min sequence = 5 */
    storage_.u64_store["sum2_seq"] = 5;

    sum2_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    auto sops = storage_.ops();
    ASSERT_EQ(sum2_policy_load(v, &sops), SUM2_OK);

    sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});

    auto fw = std::vector<uint8_t>(64, 0x22);
    auto digest = sum2::Sha256(fw);

    /* Manifest with seq=6 → should pass */
    auto env_6 = sum2::ImageManifestBuilder()
        .SetComponentId({"ecu-a", "firmware"})
        .SetSequenceNumber(6)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .SetPayloadDigest(digest.data(), digest.size(), fw.size())
        .SetPayloadUri("https://example.com/fw.bin")
        .Build(signing_key);

    sum2_manifest_t *m6 = nullptr;
    EXPECT_EQ(sum2_validate_envelope(
        v, env_6.data(), env_6.size(), 0, &m6), SUM2_OK)
        << "seq=6 should pass min_seq=5";
    if (m6) sum2_manifest_free(m6);

    /* Manifest with seq=5 → should fail (must be strictly greater) */
    auto env_5 = sum2::ImageManifestBuilder()
        .SetComponentId({"ecu-a", "firmware"})
        .SetSequenceNumber(5)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .SetPayloadDigest(digest.data(), digest.size(), fw.size())
        .SetPayloadUri("https://example.com/fw.bin")
        .Build(signing_key);

    sum2_manifest_t *m5 = nullptr;
    EXPECT_EQ(sum2_validate_envelope(
        v, env_5.data(), env_5.size(), 0, &m5),
        SUM2_ERR_ROLLBACK_REJECTED)
        << "seq=5 should fail min_seq=5 (strict >)";
    EXPECT_EQ(m5, nullptr);

    sum2_validator_free(v);
}

/**
 * Validate manifest, save policy, verify storage has correct sequence.
 */
TEST_F(PolicyTest, PolicySaveAfterUpdate) {
    sum2_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    auto fw = std::vector<uint8_t>(64, 0x33);
    auto digest = sum2::Sha256(fw);
    sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});

    auto envelope = sum2::ImageManifestBuilder()
        .SetComponentId({"ecu-a", "firmware"})
        .SetSequenceNumber(42)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .SetPayloadDigest(digest.data(), digest.size(), fw.size())
        .SetPayloadUri("https://example.com/fw.bin")
        .Build(signing_key);

    sum2_manifest_t *manifest = nullptr;
    ASSERT_EQ(sum2_validate_envelope(
        v, envelope.data(), envelope.size(), 0, &manifest), SUM2_OK);

    /* Save policy */
    auto sops = storage_.ops();
    int rc = sum2_policy_save(manifest, &sops);
    EXPECT_EQ(rc, SUM2_OK);

    /* Verify storage was updated */
    EXPECT_FALSE(storage_.u64_store.empty())
        << "policy_save should have written to storage";

    /* Check that sequence 42 is stored somewhere */
    bool found_seq = false;
    for (auto &[key, val] : storage_.u64_store) {
        if (val == 42) { found_seq = true; break; }
    }
    EXPECT_TRUE(found_seq)
        << "Storage should contain sequence number 42";

    sum2_manifest_free(manifest);
    sum2_validator_free(v);
}

/**
 * Save → load round-trip: lower seq rejected, higher seq accepted.
 */
TEST_F(PolicyTest, PolicySaveThenLoadRoundTrip) {
    sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});

    auto fw = std::vector<uint8_t>(64, 0x44);
    auto digest = sum2::Sha256(fw);

    /* Build and validate manifest with seq=42 */
    auto envelope = sum2::ImageManifestBuilder()
        .SetComponentId({"ecu-a", "firmware"})
        .SetSequenceNumber(42)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .SetPayloadDigest(digest.data(), digest.size(), fw.size())
        .SetPayloadUri("https://example.com/fw.bin")
        .Build(signing_key);

    sum2_validator_t *v1 = CreateTestValidator();
    ASSERT_NE(v1, nullptr);

    sum2_manifest_t *manifest = nullptr;
    ASSERT_EQ(sum2_validate_envelope(
        v1, envelope.data(), envelope.size(), 0, &manifest), SUM2_OK);

    /* Save policy */
    auto sops = storage_.ops();
    ASSERT_EQ(sum2_policy_save(manifest, &sops), SUM2_OK);
    sum2_manifest_free(manifest);
    sum2_validator_free(v1);

    /* Fresh validator, load the persisted policy */
    sum2_validator_t *v2 = CreateTestValidator();
    ASSERT_NE(v2, nullptr);
    ASSERT_EQ(sum2_policy_load(v2, &sops), SUM2_OK);

    /* seq=40 should be rejected (40 <= 42) */
    auto env_40 = sum2::ImageManifestBuilder()
        .SetComponentId({"ecu-a", "firmware"})
        .SetSequenceNumber(40)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .SetPayloadDigest(digest.data(), digest.size(), fw.size())
        .SetPayloadUri("https://example.com/fw.bin")
        .Build(signing_key);

    sum2_manifest_t *m40 = nullptr;
    EXPECT_EQ(sum2_validate_envelope(
        v2, env_40.data(), env_40.size(), 0, &m40),
        SUM2_ERR_ROLLBACK_REJECTED);
    EXPECT_EQ(m40, nullptr);

    /* seq=50 should pass (50 > 42) */
    auto env_50 = sum2::ImageManifestBuilder()
        .SetComponentId({"ecu-a", "firmware"})
        .SetSequenceNumber(50)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .SetPayloadDigest(digest.data(), digest.size(), fw.size())
        .SetPayloadUri("https://example.com/fw.bin")
        .Build(signing_key);

    sum2_manifest_t *m50 = nullptr;
    EXPECT_EQ(sum2_validate_envelope(
        v2, env_50.data(), env_50.size(), 0, &m50), SUM2_OK);

    if (m50) sum2_manifest_free(m50);
    sum2_validator_free(v2);
}

/**
 * Empty storage: policy_load should succeed with no constraints applied.
 */
TEST_F(PolicyTest, PolicyLoadEmptyStorage) {
    sum2_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    auto sops = storage_.ops();
    int rc = sum2_policy_load(v, &sops);
    EXPECT_EQ(rc, SUM2_OK) << "Loading from empty storage should succeed";

    /* Any sequence should be accepted */
    auto fw = std::vector<uint8_t>(64, 0x55);
    auto digest = sum2::Sha256(fw);
    sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});

    auto envelope = sum2::ImageManifestBuilder()
        .SetComponentId({"ecu-a", "firmware"})
        .SetSequenceNumber(1)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .SetPayloadDigest(digest.data(), digest.size(), fw.size())
        .SetPayloadUri("https://example.com/fw.bin")
        .Build(signing_key);

    sum2_manifest_t *m = nullptr;
    EXPECT_EQ(sum2_validate_envelope(
        v, envelope.data(), envelope.size(), 0, &m), SUM2_OK)
        << "No stored policy: any seq should pass";

    if (m) sum2_manifest_free(m);
    sum2_validator_free(v);
}

/**
 * Storage read failure: policy_load should handle gracefully.
 */
TEST_F(PolicyTest, PolicyStorageReadFails) {
    storage_.fail_reads = true;

    sum2_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    auto sops = storage_.ops();
    int rc = sum2_policy_load(v, &sops);
    /* Should either succeed (skip missing keys) or return an error — not crash */
    (void)rc;

    sum2_validator_free(v);
}

/**
 * Storage write failure: policy_save should return error.
 */
TEST_F(PolicyTest, PolicyStorageWriteFails) {
    storage_.fail_writes = true;

    sum2_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    auto fw = std::vector<uint8_t>(64, 0x66);
    auto digest = sum2::Sha256(fw);
    sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});

    auto envelope = sum2::ImageManifestBuilder()
        .SetComponentId({"ecu-a", "firmware"})
        .SetSequenceNumber(99)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .SetPayloadDigest(digest.data(), digest.size(), fw.size())
        .SetPayloadUri("https://example.com/fw.bin")
        .Build(signing_key);

    sum2_manifest_t *manifest = nullptr;
    ASSERT_EQ(sum2_validate_envelope(
        v, envelope.data(), envelope.size(), 0, &manifest), SUM2_OK);

    auto sops = storage_.ops();
    int rc = sum2_policy_save(manifest, &sops);
    EXPECT_NE(rc, SUM2_OK) << "policy_save should fail when storage writes fail";

    sum2_manifest_free(manifest);
    sum2_validator_free(v);
}
