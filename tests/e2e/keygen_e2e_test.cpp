/**
 * @file keygen_e2e_test.cpp
 * @brief E2E tests for key generation: generate → sign/encrypt → validate/decrypt.
 *
 * Tests drive the KeyGen API design. Expected to fail until keygen stubs
 * are implemented.
 */
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

#include "sum2/image_builder.h"
#include "sum2/encryptor.h"
#include "sum2/keygen.h"
#include "sum2/validator.h"
#include "sum2/decryptor.h"

#include "e2e_test_helpers.h"

class KeyGenTest : public ::testing::Test {};

/**
 * Generate an ES256 signing key, use it to sign a manifest,
 * then validate the manifest on the device side.
 */
TEST_F(KeyGenTest, GenerateSigningKeyES256) {
    /* Generate ES256 signing key */
    sum2::CoseKey key = sum2::GenerateSigningKey(sum2::ES256);

    auto pub_bytes = key.PublicKeyBytes();
    ASSERT_FALSE(pub_bytes.empty()) << "Generated key has no public bytes";

    /* Build a manifest signed with the generated key */
    auto firmware = std::vector<uint8_t>(64, 0xAB);
    auto digest = sum2::Sha256(firmware);

    auto envelope = sum2::ImageManifestBuilder()
        .SetComponentId({"ecu-a", "firmware"})
        .SetSequenceNumber(1)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .SetPayloadDigest(digest.data(), digest.size(), firmware.size())
        .SetPayloadUri("https://fw.example.com/ecu-a.bin")
        .Build(key);

    ASSERT_FALSE(envelope.empty());

    /* Validate with the generated key's public portion */
    sum2_device_id_t device_id = {};
    memcpy(device_id.vendor_id, kTestVendor.bytes, 16);
    memcpy(device_id.class_id, kTestClass.bytes, 16);

    sum2_validator_t *v = sum2_validator_create(
        pub_bytes.data(), pub_bytes.size(), &device_id);
    ASSERT_NE(v, nullptr);

    sum2_manifest_t *manifest = nullptr;
    int rc = sum2_validate_envelope(
        v, envelope.data(), envelope.size(), 0, &manifest);
    EXPECT_EQ(rc, SUM2_OK) << "Manifest signed with generated ES256 key should validate";

    if (manifest) sum2_manifest_free(manifest);
    sum2_validator_free(v);
}

/**
 * Generate an EdDSA signing key, sign and validate a manifest.
 */
TEST_F(KeyGenTest, GenerateSigningKeyEdDSA) {
    sum2::CoseKey key = sum2::GenerateSigningKey(sum2::EdDSA);

    auto pub_bytes = key.PublicKeyBytes();
    ASSERT_FALSE(pub_bytes.empty());

    auto firmware = std::vector<uint8_t>(64, 0xCD);
    auto digest = sum2::Sha256(firmware);

    auto envelope = sum2::ImageManifestBuilder()
        .SetComponentId({"ecu-b", "firmware"})
        .SetSequenceNumber(1)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .SetPayloadDigest(digest.data(), digest.size(), firmware.size())
        .SetPayloadUri("https://fw.example.com/ecu-b.bin")
        .Build(key);

    ASSERT_FALSE(envelope.empty());

    sum2_device_id_t device_id = {};
    memcpy(device_id.vendor_id, kTestVendor.bytes, 16);
    memcpy(device_id.class_id, kTestClass.bytes, 16);

    sum2_validator_t *v = sum2_validator_create(
        pub_bytes.data(), pub_bytes.size(), &device_id);
    ASSERT_NE(v, nullptr);

    sum2_manifest_t *manifest = nullptr;
    int rc = sum2_validate_envelope(
        v, envelope.data(), envelope.size(), 0, &manifest);
    EXPECT_EQ(rc, SUM2_OK) << "EdDSA-signed manifest should validate";

    if (manifest) sum2_manifest_free(manifest);
    sum2_validator_free(v);
}

/**
 * Generate a P-256 device key for ECDH-ES+A128KW.
 * Encrypt firmware with the public half, decrypt with the private half.
 */
TEST_F(KeyGenTest, GenerateDeviceKeyES256) {
    sum2::CoseKey device_key = sum2::GenerateDeviceKey(sum2::ES256);

    auto pub_bytes = device_key.PublicKeyBytes();
    ASSERT_FALSE(pub_bytes.empty());

    /* Encrypt firmware for this device */
    auto firmware = std::vector<uint8_t>(256, 0xEF);

    sum2::CoseKey sender = sum2::CoseKey::FromCoseKeyBytes(
        {kEcdhSenderKey, sizeof(kEcdhSenderKey)});

    /* Need a public-only key for the recipient */
    sum2::CoseKey recv_pub = sum2::CoseKey::FromCoseKeyBytes(pub_bytes);

    std::vector<sum2::Recipient> recipients;
    recipients.push_back({std::move(recv_pub), {0x01, 0x02}});

    auto encrypted = sum2::EncryptFirmwareEcdh(firmware, sender, recipients);
    ASSERT_FALSE(encrypted.ciphertext.empty());

    /* Build manifest */
    auto digest = sum2::Sha256(firmware);
    sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});

    auto envelope = sum2::ImageManifestBuilder()
        .SetComponentId({"ecu-a", "firmware"})
        .SetSequenceNumber(1)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .SetPayloadDigest(digest.data(), digest.size(), firmware.size())
        .SetPayloadUri("https://fw.example.com/ecu-a.enc")
        .SetEncryptionInfo(encrypted.encryption_info)
        .Build(signing_key);

    /* Validate */
    sum2_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    sum2_manifest_t *manifest = nullptr;
    ASSERT_EQ(sum2_validate_envelope(
        v, envelope.data(), envelope.size(), 0, &manifest), SUM2_OK);

    /* Decrypt with generated device key's full (private) serialization */
    auto full_key_bytes = sum2::SerializeKey(device_key, true);
    ASSERT_FALSE(full_key_bytes.empty());

    sum2_decryptor_t *dec = sum2_decryptor_create(
        manifest, 0, full_key_bytes.data(), full_key_bytes.size());
    ASSERT_NE(dec, nullptr) << "ECDH decryptor with generated key should work";

    std::vector<uint8_t> plaintext(encrypted.ciphertext.size());
    size_t pt_len = plaintext.size();
    ASSERT_EQ(sum2_decryptor_update(dec,
        encrypted.ciphertext.data(), encrypted.ciphertext.size(),
        plaintext.data(), &pt_len), 0);

    uint8_t final_buf[64];
    size_t final_len = sizeof(final_buf);
    ASSERT_EQ(sum2_decryptor_finalize(dec, final_buf, &final_len), 0);

    size_t total = pt_len + final_len;
    EXPECT_EQ(total, firmware.size());
    EXPECT_EQ(memcmp(plaintext.data(), firmware.data(), pt_len), 0);

    sum2_decryptor_free(dec);
    sum2_manifest_free(manifest);
    sum2_validator_free(v);
}

/**
 * Serialize a key to COSE_Key CBOR, reconstruct, sign+verify round-trip.
 */
TEST_F(KeyGenTest, SerializeKeyRoundTrip) {
    sum2::CoseKey original = sum2::GenerateSigningKey(sum2::ES256);

    /* Serialize with private key material */
    auto serialized = sum2::SerializeKey(original, true);
    ASSERT_FALSE(serialized.empty());

    /* Reconstruct */
    sum2::CoseKey reconstructed = sum2::CoseKey::FromCoseKeyBytes(serialized);

    /* Sign with reconstructed key */
    auto firmware = std::vector<uint8_t>(32, 0x42);
    auto digest = sum2::Sha256(firmware);

    auto envelope = sum2::ImageManifestBuilder()
        .SetComponentId({"test", "fw"})
        .SetSequenceNumber(1)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .SetPayloadDigest(digest.data(), digest.size(), firmware.size())
        .SetPayloadUri("https://example.com/fw.bin")
        .Build(reconstructed);

    ASSERT_FALSE(envelope.empty());

    /* Validate with original key's public bytes */
    auto pub_bytes = original.PublicKeyBytes();
    sum2_validator_t *v = sum2_validator_create(
        pub_bytes.data(), pub_bytes.size(), nullptr);
    ASSERT_NE(v, nullptr);

    sum2_manifest_t *manifest = nullptr;
    EXPECT_EQ(sum2_validate_envelope(
        v, envelope.data(), envelope.size(), 0, &manifest), SUM2_OK)
        << "Reconstructed key should produce valid signatures";

    if (manifest) sum2_manifest_free(manifest);
    sum2_validator_free(v);
}

/**
 * Serialize to PEM, reconstruct, sign+verify round-trip.
 */
TEST_F(KeyGenTest, SerializeKeyPemRoundTrip) {
    sum2::CoseKey original = sum2::GenerateSigningKey(sum2::ES256);

    auto pem = sum2::SerializeKeyPem(original, true);
    ASSERT_FALSE(pem.empty()) << "PEM serialization should produce output";

    sum2::CoseKey reconstructed = sum2::CoseKey::FromPem(pem);

    auto firmware = std::vector<uint8_t>(32, 0x77);
    auto digest = sum2::Sha256(firmware);

    auto envelope = sum2::ImageManifestBuilder()
        .SetComponentId({"test", "fw"})
        .SetSequenceNumber(1)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .SetPayloadDigest(digest.data(), digest.size(), firmware.size())
        .SetPayloadUri("https://example.com/fw.bin")
        .Build(reconstructed);

    ASSERT_FALSE(envelope.empty());

    auto pub_bytes = original.PublicKeyBytes();
    sum2_validator_t *v = sum2_validator_create(
        pub_bytes.data(), pub_bytes.size(), nullptr);
    ASSERT_NE(v, nullptr);

    sum2_manifest_t *manifest = nullptr;
    EXPECT_EQ(sum2_validate_envelope(
        v, envelope.data(), envelope.size(), 0, &manifest), SUM2_OK);

    if (manifest) sum2_manifest_free(manifest);
    sum2_validator_free(v);
}

/**
 * Two independently generated keys should have different public material.
 */
TEST_F(KeyGenTest, GeneratedKeysDiffer) {
    sum2::CoseKey key1 = sum2::GenerateSigningKey(sum2::ES256);
    sum2::CoseKey key2 = sum2::GenerateSigningKey(sum2::ES256);

    auto pub1 = key1.PublicKeyBytes();
    auto pub2 = key2.PublicKeyBytes();

    ASSERT_FALSE(pub1.empty());
    ASSERT_FALSE(pub2.empty());
    EXPECT_NE(pub1, pub2) << "Two generated keys should differ";
}
