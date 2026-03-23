/**
 * @file campaign_e2e_test.cpp
 * @brief E2E tests for L1 campaign manifest building and validation.
 *
 * Tests drive the CampaignBuilder API design. Expected to fail until
 * campaign builder stubs are implemented.
 */
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

#include "sum2/image_builder.h"
#include "sum2/campaign_builder.h"
#include "sum2/encryptor.h"
#include "sum2/validator.h"

#include "e2e_test_helpers.h"

class CampaignTest : public ::testing::Test {
protected:
    /* Pre-built L2 image manifests for two ECUs */
    TestImage ecu_a_;
    TestImage ecu_b_;

    void SetUp() override {
        /* 4KB test firmware for each ECU */
        std::vector<uint8_t> fw_a(4096, 0xAA);
        std::vector<uint8_t> fw_b(4096, 0xBB);

        ecu_a_ = BuildTestImage(fw_a, {"ecu-a", "firmware"}, 10,
            "https://fw.example.com/ecu-a-v10.enc");
        ecu_b_ = BuildTestImage(fw_b, {"ecu-b", "firmware"}, 10,
            "https://fw.example.com/ecu-b-v10.enc");
    }
};

/**
 * Build a campaign manifest referencing two L2 image manifests by URI.
 * Validate it and check dependency count.
 */
TEST_F(CampaignTest, BuildCampaignTwoImages) {
    sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});

    auto campaign = sum2::CampaignBuilder()
        .SetSequenceNumber(100)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .AddImage("https://fw.example.com/ecu-a.suit", ecu_a_.envelope)
        .AddImage("https://fw.example.com/ecu-b.suit", ecu_b_.envelope)
        .Build(signing_key);

    ASSERT_FALSE(campaign.empty()) << "Campaign envelope should not be empty";

    /* Validate the campaign */
    sum2_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    sum2_manifest_t *manifest = nullptr;
    int rc = sum2_validate_envelope(
        v, campaign.data(), campaign.size(), 0, &manifest);
    ASSERT_EQ(rc, SUM2_OK) << "Campaign validation failed: " << rc;
    ASSERT_NE(manifest, nullptr);

    /* Campaign-specific checks */
    EXPECT_TRUE(sum2_manifest_is_campaign(manifest))
        << "Manifest should be identified as a campaign (has dependencies)";
    EXPECT_EQ(sum2_manifest_dependency_count(manifest), 2u);
    EXPECT_EQ(sum2_manifest_sequence_number(manifest), 100u);

    sum2_manifest_free(manifest);
    sum2_validator_free(v);
}

/**
 * Build campaign with an integrated (embedded) L2 manifest.
 */
TEST_F(CampaignTest, BuildCampaignIntegratedImage) {
    sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});

    auto campaign = sum2::CampaignBuilder()
        .SetSequenceNumber(101)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .AddIntegratedImage("#ecu-a", ecu_a_.envelope)
        .Build(signing_key);

    ASSERT_FALSE(campaign.empty());

    sum2_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    sum2_manifest_t *manifest = nullptr;
    ASSERT_EQ(sum2_validate_envelope(
        v, campaign.data(), campaign.size(), 0, &manifest), SUM2_OK);

    EXPECT_TRUE(sum2_manifest_is_campaign(manifest));
    EXPECT_EQ(sum2_manifest_dependency_count(manifest), 1u);

    sum2_manifest_free(manifest);
    sum2_validator_free(v);
}

/**
 * Mix external and integrated dependencies.
 */
TEST_F(CampaignTest, BuildCampaignMixed) {
    sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});

    auto campaign = sum2::CampaignBuilder()
        .SetSequenceNumber(102)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .AddImage("https://fw.example.com/ecu-b.suit", ecu_b_.envelope)
        .AddIntegratedImage("#ecu-a", ecu_a_.envelope)
        .Build(signing_key);

    ASSERT_FALSE(campaign.empty());

    sum2_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    sum2_manifest_t *manifest = nullptr;
    ASSERT_EQ(sum2_validate_envelope(
        v, campaign.data(), campaign.size(), 0, &manifest), SUM2_OK);

    EXPECT_TRUE(sum2_manifest_is_campaign(manifest));
    EXPECT_EQ(sum2_manifest_dependency_count(manifest), 2u);

    sum2_manifest_free(manifest);
    sum2_validator_free(v);
}

/**
 * Anti-rollback: campaign with seq=10 should pass min_seq=8,
 * campaign with seq=5 should fail.
 */
TEST_F(CampaignTest, CampaignRollbackProtection) {
    sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});

    auto campaign_10 = sum2::CampaignBuilder()
        .SetSequenceNumber(10)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .AddImage("https://fw.example.com/ecu-a.suit", ecu_a_.envelope)
        .Build(signing_key);
    ASSERT_FALSE(campaign_10.empty());

    auto campaign_5 = sum2::CampaignBuilder()
        .SetSequenceNumber(5)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .AddImage("https://fw.example.com/ecu-a.suit", ecu_a_.envelope)
        .Build(signing_key);
    ASSERT_FALSE(campaign_5.empty());

    /* Validator with min_seq=8 (global) */
    sum2_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);
    sum2_validator_set_min_sequence(v, nullptr, 0, 8);

    /* seq=10 should pass */
    sum2_manifest_t *m10 = nullptr;
    EXPECT_EQ(sum2_validate_envelope(
        v, campaign_10.data(), campaign_10.size(), 0, &m10), SUM2_OK);
    if (m10) sum2_manifest_free(m10);

    /* seq=5 should be rejected */
    sum2_manifest_t *m5 = nullptr;
    EXPECT_EQ(sum2_validate_envelope(
        v, campaign_5.data(), campaign_5.size(), 0, &m5),
        SUM2_ERR_ROLLBACK_REJECTED);
    EXPECT_EQ(m5, nullptr);

    sum2_validator_free(v);
}

/**
 * Campaign validated with wrong trust anchor should fail.
 */
TEST_F(CampaignTest, CampaignWrongSigningKey) {
    sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});

    auto campaign = sum2::CampaignBuilder()
        .SetSequenceNumber(103)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .AddImage("https://fw.example.com/ecu-a.suit", ecu_a_.envelope)
        .Build(signing_key);
    ASSERT_FALSE(campaign.empty());

    /* Create validator with a different key */
    uint8_t wrong_key[sizeof(kHmacCoseKey)];
    memcpy(wrong_key, kHmacCoseKey, sizeof(kHmacCoseKey));
    wrong_key[sizeof(wrong_key) - 1] ^= 0xFF;

    sum2_validator_t *v = sum2_validator_create(
        wrong_key, sizeof(wrong_key), nullptr);
    ASSERT_NE(v, nullptr);

    sum2_manifest_t *manifest = nullptr;
    int rc = sum2_validate_envelope(
        v, campaign.data(), campaign.size(), 0, &manifest);
    EXPECT_NE(rc, SUM2_OK) << "Should reject campaign with wrong key";
    EXPECT_EQ(manifest, nullptr);

    sum2_validator_free(v);
}

/**
 * Building a campaign with no images should fail.
 */
TEST_F(CampaignTest, CampaignEmptyFails) {
    sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});

    EXPECT_THROW(
        sum2::CampaignBuilder()
            .SetSequenceNumber(1)
            .SetVendorId(kTestVendor)
            .Build(signing_key),
        std::runtime_error)
        << "Building a campaign with no images should throw";
}

/**
 * Sequence number round-trip through campaign build → validate → accessor.
 */
TEST_F(CampaignTest, CampaignSequenceNumberRoundTrip) {
    sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});

    auto campaign = sum2::CampaignBuilder()
        .SetSequenceNumber(42)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .AddImage("https://fw.example.com/ecu-a.suit", ecu_a_.envelope)
        .Build(signing_key);
    ASSERT_FALSE(campaign.empty());

    sum2_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    sum2_manifest_t *manifest = nullptr;
    ASSERT_EQ(sum2_validate_envelope(
        v, campaign.data(), campaign.size(), 0, &manifest), SUM2_OK);

    EXPECT_EQ(sum2_manifest_sequence_number(manifest), 42u);

    sum2_manifest_free(manifest);
    sum2_validator_free(v);
}
