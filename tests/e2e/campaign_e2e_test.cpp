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

#include "sumo/image_builder.h"
#include "sumo/campaign_builder.h"
#include "sumo/encryptor.h"
#include "sumo/validator.h"

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
    sumo::CoseKey signing_key = sumo::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});

    auto campaign = sumo::CampaignBuilder()
        .SetSequenceNumber(100)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .AddImage("https://fw.example.com/ecu-a.suit", ecu_a_.envelope)
        .AddImage("https://fw.example.com/ecu-b.suit", ecu_b_.envelope)
        .Build(signing_key);

    ASSERT_FALSE(campaign.empty()) << "Campaign envelope should not be empty";

    /* Validate the campaign */
    sumo_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    sumo_manifest_t *manifest = nullptr;
    int rc = sumo_validate_envelope(
        v, campaign.data(), campaign.size(), 0, &manifest);
    ASSERT_EQ(rc, SUMO_OK) << "Campaign validation failed: " << rc;
    ASSERT_NE(manifest, nullptr);

    /* Campaign-specific checks */
    EXPECT_TRUE(sumo_manifest_is_campaign(manifest))
        << "Manifest should be identified as a campaign (has dependencies)";
    EXPECT_EQ(sumo_manifest_dependency_count(manifest), 2u);
    EXPECT_EQ(sumo_manifest_sequence_number(manifest), 100u);

    sumo_manifest_free(manifest);
    sumo_validator_free(v);
}

/**
 * Build campaign with an integrated (embedded) L2 manifest.
 */
TEST_F(CampaignTest, BuildCampaignIntegratedImage) {
    sumo::CoseKey signing_key = sumo::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});

    auto campaign = sumo::CampaignBuilder()
        .SetSequenceNumber(101)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .AddIntegratedImage("#ecu-a", ecu_a_.envelope)
        .Build(signing_key);

    ASSERT_FALSE(campaign.empty());

    sumo_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    sumo_manifest_t *manifest = nullptr;
    ASSERT_EQ(sumo_validate_envelope(
        v, campaign.data(), campaign.size(), 0, &manifest), SUMO_OK);

    EXPECT_TRUE(sumo_manifest_is_campaign(manifest));
    EXPECT_EQ(sumo_manifest_dependency_count(manifest), 1u);

    sumo_manifest_free(manifest);
    sumo_validator_free(v);
}

/**
 * Mix external and integrated dependencies.
 */
TEST_F(CampaignTest, BuildCampaignMixed) {
    sumo::CoseKey signing_key = sumo::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});

    auto campaign = sumo::CampaignBuilder()
        .SetSequenceNumber(102)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .AddImage("https://fw.example.com/ecu-b.suit", ecu_b_.envelope)
        .AddIntegratedImage("#ecu-a", ecu_a_.envelope)
        .Build(signing_key);

    ASSERT_FALSE(campaign.empty());

    sumo_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    sumo_manifest_t *manifest = nullptr;
    ASSERT_EQ(sumo_validate_envelope(
        v, campaign.data(), campaign.size(), 0, &manifest), SUMO_OK);

    EXPECT_TRUE(sumo_manifest_is_campaign(manifest));
    EXPECT_EQ(sumo_manifest_dependency_count(manifest), 2u);

    sumo_manifest_free(manifest);
    sumo_validator_free(v);
}

/**
 * Anti-rollback: campaign with seq=10 should pass min_seq=8,
 * campaign with seq=5 should fail.
 */
TEST_F(CampaignTest, CampaignRollbackProtection) {
    sumo::CoseKey signing_key = sumo::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});

    auto campaign_10 = sumo::CampaignBuilder()
        .SetSequenceNumber(10)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .AddImage("https://fw.example.com/ecu-a.suit", ecu_a_.envelope)
        .Build(signing_key);
    ASSERT_FALSE(campaign_10.empty());

    auto campaign_5 = sumo::CampaignBuilder()
        .SetSequenceNumber(5)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .AddImage("https://fw.example.com/ecu-a.suit", ecu_a_.envelope)
        .Build(signing_key);
    ASSERT_FALSE(campaign_5.empty());

    /* Validator with min_seq=8 (global) */
    sumo_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);
    sumo_validator_set_min_sequence(v, nullptr, 0, 8);

    /* seq=10 should pass */
    sumo_manifest_t *m10 = nullptr;
    EXPECT_EQ(sumo_validate_envelope(
        v, campaign_10.data(), campaign_10.size(), 0, &m10), SUMO_OK);
    if (m10) sumo_manifest_free(m10);

    /* seq=5 should be rejected */
    sumo_manifest_t *m5 = nullptr;
    EXPECT_EQ(sumo_validate_envelope(
        v, campaign_5.data(), campaign_5.size(), 0, &m5),
        SUMO_ERR_ROLLBACK_REJECTED);
    EXPECT_EQ(m5, nullptr);

    sumo_validator_free(v);
}

/**
 * Campaign validated with wrong trust anchor should fail.
 */
TEST_F(CampaignTest, CampaignWrongSigningKey) {
    sumo::CoseKey signing_key = sumo::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});

    auto campaign = sumo::CampaignBuilder()
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

    sumo_validator_t *v = sumo_validator_create(
        wrong_key, sizeof(wrong_key), nullptr);
    ASSERT_NE(v, nullptr);

    sumo_manifest_t *manifest = nullptr;
    int rc = sumo_validate_envelope(
        v, campaign.data(), campaign.size(), 0, &manifest);
    EXPECT_NE(rc, SUMO_OK) << "Should reject campaign with wrong key";
    EXPECT_EQ(manifest, nullptr);

    sumo_validator_free(v);
}

/**
 * Building a campaign with no images should fail.
 */
TEST_F(CampaignTest, CampaignEmptyFails) {
    sumo::CoseKey signing_key = sumo::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});

    EXPECT_THROW(
        sumo::CampaignBuilder()
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
    sumo::CoseKey signing_key = sumo::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});

    auto campaign = sumo::CampaignBuilder()
        .SetSequenceNumber(42)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .AddImage("https://fw.example.com/ecu-a.suit", ecu_a_.envelope)
        .Build(signing_key);
    ASSERT_FALSE(campaign.empty());

    sumo_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    sumo_manifest_t *manifest = nullptr;
    ASSERT_EQ(sumo_validate_envelope(
        v, campaign.data(), campaign.size(), 0, &manifest), SUMO_OK);

    EXPECT_EQ(sumo_manifest_sequence_number(manifest), 42u);

    sumo_manifest_free(manifest);
    sumo_validator_free(v);
}
