/**
 * @file orchestrator_e2e_test.cpp
 * @brief E2E tests for orchestrator: process_image, process_campaign, full pipeline.
 *
 * Tests drive the Orchestrator API design. Expected to fail until orchestrator
 * stubs are implemented.
 */
#include <gtest/gtest.h>
#include <cstring>
#include <numeric>
#include <vector>

#include <openssl/evp.h>

#include "sum2/image_builder.h"
#include "sum2/campaign_builder.h"
#include "sum2/encryptor.h"
#include "sum2/keygen.h"
#include "sum2/validator.h"
#include "sum2/decryptor.h"
#include "sum2/decompressor.h"
#include "sum2/orchestrator.h"
#include "sum2/policy.h"

#include "e2e_test_helpers.h"

/* ===== Image Processing Tests ===== */

class OrchestratorImageTest : public ::testing::Test {
protected:
    TestImage image_;
    FakePlatformOps platform_;

    void SetUp() override {
        /* 64KB test firmware */
        std::vector<uint8_t> fw(64 * 1024);
        for (size_t i = 0; i < fw.size(); i++)
            fw[i] = static_cast<uint8_t>(i ^ (i >> 8));

        image_ = BuildTestImage(fw, {"ecu-a", "firmware"}, 10,
            "https://fw.example.com/ecu-a-v10.enc");

        /* Pre-load ciphertext at the payload URI */
        platform_.fetch_store[image_.payload_uri] = image_.ciphertext;
    }
};

/**
 * Process a single encrypted image manifest with A128KW.
 * Verify the write callback receives correct decrypted firmware.
 */
TEST_F(OrchestratorImageTest, ProcessImageEncryptedA128KW) {
    sum2_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    sum2_manifest_t *manifest = nullptr;
    ASSERT_EQ(sum2_validate_envelope(
        v, image_.envelope.data(), image_.envelope.size(), 0, &manifest),
        SUM2_OK);

    auto ops = platform_.ops();
    int rc = sum2_process_image(v, manifest, &ops);
    EXPECT_EQ(rc, SUM2_OK) << "process_image failed: " << rc;

    /* Verify firmware was written correctly */
    EXPECT_FALSE(platform_.written.empty())
        << "Write callback should have been called";

    /* Find the written component data (any key) */
    size_t total_written = 0;
    for (auto &[key, data] : platform_.written) {
        total_written += data.size();
        /* If only one component, verify content matches */
        if (platform_.written.size() == 1) {
            EXPECT_EQ(data.size(), image_.plaintext.size());
            EXPECT_EQ(data, image_.plaintext);
        }
    }
    EXPECT_EQ(total_written, image_.plaintext.size());

    /* Verify sequence was persisted */
    EXPECT_FALSE(platform_.persisted_seqs.empty())
        << "persist_sequence should have been called";

    sum2_manifest_free(manifest);
    sum2_validator_free(v);
}

/**
 * Process with ECDH-ES+A128KW encryption.
 */
TEST_F(OrchestratorImageTest, ProcessImageEncryptedECDH) {
    /* Build ECDH-encrypted image */
    std::vector<uint8_t> fw(4096, 0xCC);

    sum2::CoseKey sender = sum2::CoseKey::FromCoseKeyBytes(
        {kEcdhSenderKey, sizeof(kEcdhSenderKey)});
    sum2::CoseKey recv = sum2::CoseKey::FromCoseKeyBytes(
        {kEcdhDeviceKeyPrivate, sizeof(kEcdhDeviceKeyPrivate)});

    std::vector<sum2::Recipient> recipients;
    recipients.push_back({std::move(recv), {0x6B, 0x69, 0x64}});

    auto encrypted = sum2::EncryptFirmwareEcdh(fw, sender, recipients);
    auto digest = sum2::Sha256(fw);

    sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});

    auto envelope = sum2::ImageManifestBuilder()
        .SetComponentId({"ecu-a", "firmware"})
        .SetSequenceNumber(20)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .SetPayloadDigest(digest.data(), digest.size(), fw.size())
        .SetPayloadUri("https://fw.example.com/ecu-a-ecdh.enc")
        .SetEncryptionInfo(encrypted.encryption_info)
        .Build(signing_key);

    /* Set up platform */
    FakePlatformOps plat;
    plat.fetch_store["https://fw.example.com/ecu-a-ecdh.enc"] = encrypted.ciphertext;

    /* Validator with ECDH device key */
    sum2_device_id_t device_id = {};
    memcpy(device_id.vendor_id, kTestVendor.bytes, 16);
    memcpy(device_id.class_id, kTestClass.bytes, 16);

    sum2_validator_t *v = sum2_validator_create(
        kHmacCoseKey, sizeof(kHmacCoseKey), &device_id);
    ASSERT_NE(v, nullptr);

    /* Register ECDH device private key on validator */
    ASSERT_EQ(sum2_validator_add_device_key(v,
        kEcdhDeviceKeyPrivate, sizeof(kEcdhDeviceKeyPrivate),
        nullptr, 0), SUM2_OK);

    sum2_manifest_t *manifest = nullptr;
    ASSERT_EQ(sum2_validate_envelope(
        v, envelope.data(), envelope.size(), 0, &manifest), SUM2_OK);

    auto ops = plat.ops();
    int rc = sum2_process_image(v, manifest, &ops);
    EXPECT_EQ(rc, SUM2_OK) << "ECDH process_image failed: " << rc;

    /* Verify decrypted output */
    size_t total = 0;
    for (auto &[key, data] : plat.written) total += data.size();
    EXPECT_EQ(total, fw.size());

    sum2_manifest_free(manifest);
    sum2_validator_free(v);
}

/**
 * Process compressed+encrypted firmware.
 * Orchestrator should decompress after decryption.
 */
TEST_F(OrchestratorImageTest, ProcessImageWithCompression) {
    std::vector<uint8_t> fw(64 * 1024);
    for (size_t i = 0; i < fw.size(); i++)
        fw[i] = static_cast<uint8_t>(i % 251);

    auto img = BuildTestImage(fw, {"ecu-a", "firmware"}, 30,
        "https://fw.example.com/ecu-a-v30.zst.enc", true /* compress */);

    FakePlatformOps plat;
    plat.fetch_store[img.payload_uri] = img.ciphertext;

    sum2_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    sum2_manifest_t *manifest = nullptr;
    ASSERT_EQ(sum2_validate_envelope(
        v, img.envelope.data(), img.envelope.size(), 0, &manifest), SUM2_OK);

    auto ops = plat.ops();
    int rc = sum2_process_image(v, manifest, &ops);
    EXPECT_EQ(rc, SUM2_OK) << "Compressed image processing failed: " << rc;

    /* Written data should be decompressed firmware */
    size_t total = 0;
    for (auto &[key, data] : plat.written) total += data.size();
    EXPECT_EQ(total, fw.size());

    sum2_manifest_free(manifest);
    sum2_validator_free(v);
}

/**
 * 1MB streaming: verify write callback is called multiple times.
 */
TEST_F(OrchestratorImageTest, ProcessImageStreaming1MB) {
    const size_t FW_SIZE = 1024 * 1024;
    std::vector<uint8_t> fw(FW_SIZE);
    for (size_t i = 0; i < FW_SIZE; i++)
        fw[i] = static_cast<uint8_t>(i ^ (i >> 8) ^ (i >> 16));

    auto img = BuildTestImage(fw, {"ecu-a", "firmware"}, 40,
        "https://fw.example.com/ecu-a-v40.enc");

    FakePlatformOps plat;
    plat.fetch_store[img.payload_uri] = img.ciphertext;

    sum2_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    sum2_manifest_t *manifest = nullptr;
    ASSERT_EQ(sum2_validate_envelope(
        v, img.envelope.data(), img.envelope.size(), 0, &manifest), SUM2_OK);

    auto ops = plat.ops();
    int rc = sum2_process_image(v, manifest, &ops);
    EXPECT_EQ(rc, SUM2_OK);

    /* Should have called write multiple times (streaming, not all at once) */
    EXPECT_GT(plat.write_call_count, 1)
        << "1MB should trigger multiple write calls (streaming)";

    size_t total = 0;
    for (auto &[key, data] : plat.written) total += data.size();
    EXPECT_EQ(total, FW_SIZE);

    sum2_manifest_free(manifest);
    sum2_validator_free(v);
}

/**
 * Fetch failure: orchestrator should propagate error, no write/persist.
 */
TEST_F(OrchestratorImageTest, ProcessImageFetchFails) {
    sum2_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    sum2_manifest_t *manifest = nullptr;
    ASSERT_EQ(sum2_validate_envelope(
        v, image_.envelope.data(), image_.envelope.size(), 0, &manifest),
        SUM2_OK);

    /* Empty platform — fetch will find nothing */
    FakePlatformOps empty_plat;
    auto ops = empty_plat.ops();

    int rc = sum2_process_image(v, manifest, &ops);
    EXPECT_NE(rc, SUM2_OK) << "Should fail when fetch returns error";

    EXPECT_TRUE(empty_plat.written.empty())
        << "No writes should occur on fetch failure";
    EXPECT_TRUE(empty_plat.persisted_seqs.empty())
        << "No sequence persist on fetch failure";

    sum2_manifest_free(manifest);
    sum2_validator_free(v);
}

/**
 * Write failure: orchestrator should stop and NOT persist sequence.
 */
TEST_F(OrchestratorImageTest, ProcessImageWriteFails) {
    sum2_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    sum2_manifest_t *manifest = nullptr;
    ASSERT_EQ(sum2_validate_envelope(
        v, image_.envelope.data(), image_.envelope.size(), 0, &manifest),
        SUM2_OK);

    /* Fail on 3rd write call */
    platform_.write_fail_on = 3;
    auto ops = platform_.ops();

    int rc = sum2_process_image(v, manifest, &ops);
    EXPECT_NE(rc, SUM2_OK) << "Should fail when write fails";

    EXPECT_TRUE(platform_.persisted_seqs.empty())
        << "Should NOT persist sequence when write fails (atomic semantics)";

    sum2_manifest_free(manifest);
    sum2_validator_free(v);
}

/**
 * Tampered ciphertext: GCM tag or digest check should catch it.
 */
TEST_F(OrchestratorImageTest, ProcessImageTamperedPayload) {
    sum2_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    sum2_manifest_t *manifest = nullptr;
    ASSERT_EQ(sum2_validate_envelope(
        v, image_.envelope.data(), image_.envelope.size(), 0, &manifest),
        SUM2_OK);

    /* Tamper the ciphertext */
    auto tampered = image_.ciphertext;
    tampered[tampered.size() / 2] ^= 0xFF;

    FakePlatformOps plat;
    plat.fetch_store[image_.payload_uri] = tampered;
    auto ops = plat.ops();

    int rc = sum2_process_image(v, manifest, &ops);
    EXPECT_NE(rc, SUM2_OK) << "Should detect tampered ciphertext";

    sum2_manifest_free(manifest);
    sum2_validator_free(v);
}

/* ===== Campaign Processing Tests ===== */

class OrchestratorCampaignTest : public ::testing::Test {
protected:
    TestImage ecu_a_;
    TestImage ecu_b_;
    std::vector<uint8_t> campaign_envelope_;

    void SetUp() override {
        std::vector<uint8_t> fw_a(4096, 0xAA);
        std::vector<uint8_t> fw_b(4096, 0xBB);

        ecu_a_ = BuildTestImage(fw_a, {"ecu-a", "firmware"}, 10,
            "https://fw.example.com/ecu-a-v10.enc");
        ecu_b_ = BuildTestImage(fw_b, {"ecu-b", "firmware"}, 10,
            "https://fw.example.com/ecu-b-v10.enc");

        /* Build campaign manifest */
        sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
            {kHmacCoseKey, sizeof(kHmacCoseKey)});

        campaign_envelope_ = sum2::CampaignBuilder()
            .SetSequenceNumber(50)
            .SetVendorId(kTestVendor)
            .SetClassId(kTestClass)
            .AddImage("https://fw.example.com/ecu-a.suit", ecu_a_.envelope)
            .AddImage("https://fw.example.com/ecu-b.suit", ecu_b_.envelope)
            .Build(signing_key);
    }
};

/**
 * Process campaign with two image dependencies.
 * Both should be fetched, validated, decrypted, and written.
 */
TEST_F(OrchestratorCampaignTest, ProcessCampaignTwoImages) {
    FakePlatformOps plat;
    /* L2 envelopes */
    plat.fetch_store["https://fw.example.com/ecu-a.suit"] = ecu_a_.envelope;
    plat.fetch_store["https://fw.example.com/ecu-b.suit"] = ecu_b_.envelope;
    /* Firmware payloads */
    plat.fetch_store[ecu_a_.payload_uri] = ecu_a_.ciphertext;
    plat.fetch_store[ecu_b_.payload_uri] = ecu_b_.ciphertext;

    sum2_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    sum2_manifest_t *campaign = nullptr;
    ASSERT_EQ(sum2_validate_envelope(
        v, campaign_envelope_.data(), campaign_envelope_.size(), 0, &campaign),
        SUM2_OK);

    auto ops = plat.ops();
    int rc = sum2_process_campaign(v, campaign, &ops);
    EXPECT_EQ(rc, SUM2_OK) << "Campaign processing failed: " << rc;

    /* Both components should have received firmware */
    size_t total = 0;
    for (auto &[key, data] : plat.written) total += data.size();
    EXPECT_EQ(total, ecu_a_.plaintext.size() + ecu_b_.plaintext.size());

    /* Sequences should be persisted for both */
    EXPECT_GE(plat.persisted_seqs.size(), 2u)
        << "Both component sequences should be persisted";

    sum2_manifest_free(campaign);
    sum2_validator_free(v);
}

/**
 * Campaign with integrated L2 manifest — no L2 envelope fetch needed.
 */
TEST_F(OrchestratorCampaignTest, ProcessCampaignIntegrated) {
    sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});

    auto campaign = sum2::CampaignBuilder()
        .SetSequenceNumber(51)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .AddIntegratedImage("#ecu-a", ecu_a_.envelope)
        .Build(signing_key);

    FakePlatformOps plat;
    /* Only firmware payload — L2 envelope is integrated */
    plat.fetch_store[ecu_a_.payload_uri] = ecu_a_.ciphertext;

    sum2_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    sum2_manifest_t *manifest = nullptr;
    ASSERT_EQ(sum2_validate_envelope(
        v, campaign.data(), campaign.size(), 0, &manifest), SUM2_OK);

    auto ops = plat.ops();
    int rc = sum2_process_campaign(v, manifest, &ops);
    EXPECT_EQ(rc, SUM2_OK);

    size_t total = 0;
    for (auto &[key, data] : plat.written) total += data.size();
    EXPECT_EQ(total, ecu_a_.plaintext.size());

    sum2_manifest_free(manifest);
    sum2_validator_free(v);
}

/**
 * L2 envelope fetch fails — campaign should abort.
 */
TEST_F(OrchestratorCampaignTest, ProcessCampaignL2FetchFails) {
    FakePlatformOps plat;
    /* Only provide ecu-a, NOT ecu-b L2 envelope */
    plat.fetch_store["https://fw.example.com/ecu-a.suit"] = ecu_a_.envelope;
    plat.fetch_store[ecu_a_.payload_uri] = ecu_a_.ciphertext;
    /* ecu-b.suit missing — will cause fetch failure */

    sum2_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    sum2_manifest_t *campaign = nullptr;
    ASSERT_EQ(sum2_validate_envelope(
        v, campaign_envelope_.data(), campaign_envelope_.size(), 0, &campaign),
        SUM2_OK);

    auto ops = plat.ops();
    int rc = sum2_process_campaign(v, campaign, &ops);
    EXPECT_NE(rc, SUM2_OK) << "Should fail when L2 fetch fails";

    sum2_manifest_free(campaign);
    sum2_validator_free(v);
}

/**
 * Tampered L2 envelope — campaign should detect auth failure.
 */
TEST_F(OrchestratorCampaignTest, ProcessCampaignL2AuthFails) {
    FakePlatformOps plat;

    /* Tamper ecu-a's L2 envelope */
    auto tampered_a = ecu_a_.envelope;
    tampered_a[tampered_a.size() / 2] ^= 0xFF;

    plat.fetch_store["https://fw.example.com/ecu-a.suit"] = tampered_a;
    plat.fetch_store["https://fw.example.com/ecu-b.suit"] = ecu_b_.envelope;
    plat.fetch_store[ecu_a_.payload_uri] = ecu_a_.ciphertext;
    plat.fetch_store[ecu_b_.payload_uri] = ecu_b_.ciphertext;

    sum2_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    sum2_manifest_t *campaign = nullptr;
    ASSERT_EQ(sum2_validate_envelope(
        v, campaign_envelope_.data(), campaign_envelope_.size(), 0, &campaign),
        SUM2_OK);

    auto ops = plat.ops();
    int rc = sum2_process_campaign(v, campaign, &ops);
    EXPECT_NE(rc, SUM2_OK) << "Should detect tampered L2 envelope";

    sum2_manifest_free(campaign);
    sum2_validator_free(v);
}

/* ===== Full Pipeline Test ===== */

/**
 * Ultimate integration test: keygen → encrypt → build L2 → build L1 →
 * policy_load → process_campaign → policy_save → verify rollback.
 */
TEST(FullPipelineTest, KeyGenThroughPolicy) {
    /* --- OFFBOARD: Generate keys --- */
    sum2::CoseKey signing_key = sum2::GenerateSigningKey(sum2::ES256);
    auto pub_bytes = signing_key.PublicKeyBytes();
    ASSERT_FALSE(pub_bytes.empty());

    sum2::CoseKey device_key = sum2::GenerateDeviceKey(sum2::ES256);
    auto device_pub = device_key.PublicKeyBytes();
    ASSERT_FALSE(device_pub.empty());

    /* --- OFFBOARD: Build L2 image manifests --- */
    std::vector<uint8_t> fw_a(8192, 0xAA);
    std::vector<uint8_t> fw_b(8192, 0xBB);

    /* Encrypt with generated device key */
    sum2::CoseKey recv_pub = sum2::CoseKey::FromCoseKeyBytes(device_pub);
    sum2::CoseKey sender = sum2::CoseKey::FromCoseKeyBytes(
        {kEcdhSenderKey, sizeof(kEcdhSenderKey)});

    std::vector<sum2::Recipient> recipients;
    recipients.push_back({std::move(recv_pub), {0x01}});

    auto enc_a = sum2::EncryptFirmwareEcdh(fw_a, sender, recipients);
    auto digest_a = sum2::Sha256(fw_a);

    auto env_a = sum2::ImageManifestBuilder()
        .SetComponentId({"ecu-a", "firmware"})
        .SetSequenceNumber(10)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .SetPayloadDigest(digest_a.data(), digest_a.size(), fw_a.size())
        .SetPayloadUri("https://fw.example.com/ecu-a.enc")
        .SetEncryptionInfo(enc_a.encryption_info)
        .Build(signing_key);

    /* --- OFFBOARD: Build L1 campaign --- */
    auto campaign = sum2::CampaignBuilder()
        .SetSequenceNumber(50)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .AddImage("https://fw.example.com/ecu-a.suit", env_a)
        .Build(signing_key);
    ASSERT_FALSE(campaign.empty());

    /* --- ONBOARD: Setup --- */
    sum2_device_id_t device_id = {};
    memcpy(device_id.vendor_id, kTestVendor.bytes, 16);
    memcpy(device_id.class_id, kTestClass.bytes, 16);

    sum2_validator_t *v = sum2_validator_create(
        pub_bytes.data(), pub_bytes.size(), &device_id);
    ASSERT_NE(v, nullptr);

    /* Register device key for decryption */
    auto full_device_key = sum2::SerializeKey(device_key, true);
    ASSERT_EQ(sum2_validator_add_device_key(v,
        full_device_key.data(), full_device_key.size(),
        nullptr, 0), SUM2_OK);

    /* Load policy from empty storage (no rollback constraints) */
    FakeStorageOps storage;
    auto storage_ops = storage.ops();
    sum2_policy_load(v, &storage_ops);

    /* --- ONBOARD: Process campaign --- */
    FakePlatformOps plat;
    plat.fetch_store["https://fw.example.com/ecu-a.suit"] = env_a;
    plat.fetch_store["https://fw.example.com/ecu-a.enc"] = enc_a.ciphertext;

    sum2_manifest_t *camp_manifest = nullptr;
    ASSERT_EQ(sum2_validate_envelope(
        v, campaign.data(), campaign.size(), 0, &camp_manifest), SUM2_OK);

    auto ops = plat.ops();
    int rc = sum2_process_campaign(v, camp_manifest, &ops);
    EXPECT_EQ(rc, SUM2_OK) << "Full pipeline campaign processing failed";

    /* Save policy after successful update */
    rc = sum2_policy_save(camp_manifest, &storage_ops);
    EXPECT_EQ(rc, SUM2_OK);

    /* --- Verify rollback protection works --- */
    sum2_validator_t *v2 = sum2_validator_create(
        pub_bytes.data(), pub_bytes.size(), &device_id);
    ASSERT_NE(v2, nullptr);

    /* Load persisted policy */
    sum2_policy_load(v2, &storage_ops);

    /* Try to process a campaign with lower sequence (seq=40 < 50) */
    auto old_campaign = sum2::CampaignBuilder()
        .SetSequenceNumber(40)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .AddImage("https://fw.example.com/ecu-a.suit", env_a)
        .Build(signing_key);

    sum2_manifest_t *old_manifest = nullptr;
    rc = sum2_validate_envelope(
        v2, old_campaign.data(), old_campaign.size(), 0, &old_manifest);
    EXPECT_EQ(rc, SUM2_ERR_ROLLBACK_REJECTED)
        << "Should reject campaign with seq < persisted seq";
    EXPECT_EQ(old_manifest, nullptr);

    sum2_manifest_free(camp_manifest);
    sum2_validator_free(v);
    sum2_validator_free(v2);
}
