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

#include "sumo/image_builder.h"
#include "sumo/encryptor.h"
#include "sumo/keygen.h"
#include "sumo/validator.h"
#include "sumo/decryptor.h"

#include "e2e_test_helpers.h"

class KeyGenTest : public ::testing::Test {};

/**
 * Generate an ES256 signing key, use it to sign a manifest,
 * then validate the manifest on the device side.
 */
TEST_F(KeyGenTest, GenerateSigningKeyES256) {
    /* Generate ES256 signing key */
    sumo::CoseKey key = sumo::GenerateSigningKey(sumo::ES256);

    auto pub_bytes = key.PublicKeyBytes();
    ASSERT_FALSE(pub_bytes.empty()) << "Generated key has no public bytes";

    /* Build a manifest signed with the generated key */
    auto firmware = std::vector<uint8_t>(64, 0xAB);
    auto digest = sumo::Sha256(firmware);

    auto envelope = sumo::ImageManifestBuilder()
        .SetComponentId({"ecu-a", "firmware"})
        .SetSequenceNumber(1)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .SetPayloadDigest(digest.data(), digest.size(), firmware.size())
        .SetPayloadUri("https://fw.example.com/ecu-a.bin")
        .Build(key);

    ASSERT_FALSE(envelope.empty());

    /* Validate with the generated key's public portion */
    sumo_device_id_t device_id = {};
    memcpy(device_id.vendor_id, kTestVendor.bytes, 16);
    memcpy(device_id.class_id, kTestClass.bytes, 16);

    sumo_validator_t *v = sumo_validator_create(
        pub_bytes.data(), pub_bytes.size(), &device_id);
    ASSERT_NE(v, nullptr);

    sumo_manifest_t *manifest = nullptr;
    int rc = sumo_validate_envelope(
        v, envelope.data(), envelope.size(), 0, &manifest);
    EXPECT_EQ(rc, SUMO_OK) << "Manifest signed with generated ES256 key should validate";

    if (manifest) sumo_manifest_free(manifest);
    sumo_validator_free(v);
}

/**
 * Generate an EdDSA signing key, sign and validate a manifest.
 */
TEST_F(KeyGenTest, GenerateSigningKeyEdDSA) {
    sumo::CoseKey key = sumo::GenerateSigningKey(sumo::EdDSA);

    auto pub_bytes = key.PublicKeyBytes();
    ASSERT_FALSE(pub_bytes.empty());

    auto firmware = std::vector<uint8_t>(64, 0xCD);
    auto digest = sumo::Sha256(firmware);

    auto envelope = sumo::ImageManifestBuilder()
        .SetComponentId({"ecu-b", "firmware"})
        .SetSequenceNumber(1)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .SetPayloadDigest(digest.data(), digest.size(), firmware.size())
        .SetPayloadUri("https://fw.example.com/ecu-b.bin")
        .Build(key);

    ASSERT_FALSE(envelope.empty());

    sumo_device_id_t device_id = {};
    memcpy(device_id.vendor_id, kTestVendor.bytes, 16);
    memcpy(device_id.class_id, kTestClass.bytes, 16);

    sumo_validator_t *v = sumo_validator_create(
        pub_bytes.data(), pub_bytes.size(), &device_id);
    ASSERT_NE(v, nullptr);

    sumo_manifest_t *manifest = nullptr;
    int rc = sumo_validate_envelope(
        v, envelope.data(), envelope.size(), 0, &manifest);
    EXPECT_EQ(rc, SUMO_OK) << "EdDSA-signed manifest should validate";

    if (manifest) sumo_manifest_free(manifest);
    sumo_validator_free(v);
}

/**
 * Generate a P-256 device key for ECDH-ES+A128KW.
 * Encrypt firmware with the public half, decrypt with the private half.
 */
TEST_F(KeyGenTest, GenerateDeviceKeyES256) {
    sumo::CoseKey device_key = sumo::GenerateDeviceKey(sumo::ES256);

    auto pub_bytes = device_key.PublicKeyBytes();
    ASSERT_FALSE(pub_bytes.empty());

    /* Encrypt firmware for this device */
    auto firmware = std::vector<uint8_t>(256, 0xEF);

    sumo::CoseKey sender = sumo::CoseKey::FromCoseKeyBytes(
        {kEcdhSenderKey, sizeof(kEcdhSenderKey)});

    /* Need a public-only key for the recipient */
    sumo::CoseKey recv_pub = sumo::CoseKey::FromCoseKeyBytes(pub_bytes);

    std::vector<sumo::Recipient> recipients;
    recipients.push_back({std::move(recv_pub), {0x01, 0x02}});

    auto encrypted = sumo::EncryptFirmwareEcdh(firmware, sender, recipients);
    ASSERT_FALSE(encrypted.ciphertext.empty());

    /* Build manifest */
    auto digest = sumo::Sha256(firmware);
    sumo::CoseKey signing_key = sumo::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});

    auto envelope = sumo::ImageManifestBuilder()
        .SetComponentId({"ecu-a", "firmware"})
        .SetSequenceNumber(1)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .SetPayloadDigest(digest.data(), digest.size(), firmware.size())
        .SetPayloadUri("https://fw.example.com/ecu-a.enc")
        .SetEncryptionInfo(encrypted.encryption_info)
        .Build(signing_key);

    /* Validate */
    sumo_validator_t *v = CreateTestValidator();
    ASSERT_NE(v, nullptr);

    sumo_manifest_t *manifest = nullptr;
    ASSERT_EQ(sumo_validate_envelope(
        v, envelope.data(), envelope.size(), 0, &manifest), SUMO_OK);

    /* Decrypt with generated device key's full (private) serialization */
    auto full_key_bytes = sumo::SerializeKey(device_key, true);
    ASSERT_FALSE(full_key_bytes.empty());

    sumo_decryptor_t *dec = sumo_decryptor_create(
        manifest, 0, full_key_bytes.data(), full_key_bytes.size());
    ASSERT_NE(dec, nullptr) << "ECDH decryptor with generated key should work";

    std::vector<uint8_t> plaintext(encrypted.ciphertext.size());
    size_t pt_len = plaintext.size();
    ASSERT_EQ(sumo_decryptor_update(dec,
        encrypted.ciphertext.data(), encrypted.ciphertext.size(),
        plaintext.data(), &pt_len), 0);

    uint8_t final_buf[64];
    size_t final_len = sizeof(final_buf);
    ASSERT_EQ(sumo_decryptor_finalize(dec, final_buf, &final_len), 0);

    size_t total = pt_len + final_len;
    EXPECT_EQ(total, firmware.size());
    EXPECT_EQ(memcmp(plaintext.data(), firmware.data(), pt_len), 0);

    sumo_decryptor_free(dec);
    sumo_manifest_free(manifest);
    sumo_validator_free(v);
}

/**
 * Serialize a key to COSE_Key CBOR, reconstruct, sign+verify round-trip.
 */
TEST_F(KeyGenTest, SerializeKeyRoundTrip) {
    sumo::CoseKey original = sumo::GenerateSigningKey(sumo::ES256);

    /* Serialize with private key material */
    auto serialized = sumo::SerializeKey(original, true);
    ASSERT_FALSE(serialized.empty());

    /* Reconstruct */
    sumo::CoseKey reconstructed = sumo::CoseKey::FromCoseKeyBytes(serialized);

    /* Sign with reconstructed key */
    auto firmware = std::vector<uint8_t>(32, 0x42);
    auto digest = sumo::Sha256(firmware);

    auto envelope = sumo::ImageManifestBuilder()
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
    sumo_validator_t *v = sumo_validator_create(
        pub_bytes.data(), pub_bytes.size(), nullptr);
    ASSERT_NE(v, nullptr);

    sumo_manifest_t *manifest = nullptr;
    EXPECT_EQ(sumo_validate_envelope(
        v, envelope.data(), envelope.size(), 0, &manifest), SUMO_OK)
        << "Reconstructed key should produce valid signatures";

    if (manifest) sumo_manifest_free(manifest);
    sumo_validator_free(v);
}

/**
 * Serialize to PEM, reconstruct, sign+verify round-trip.
 */
TEST_F(KeyGenTest, SerializeKeyPemRoundTrip) {
    sumo::CoseKey original = sumo::GenerateSigningKey(sumo::ES256);

    auto pem = sumo::SerializeKeyPem(original, true);
    ASSERT_FALSE(pem.empty()) << "PEM serialization should produce output";

    sumo::CoseKey reconstructed = sumo::CoseKey::FromPem(pem);

    auto firmware = std::vector<uint8_t>(32, 0x77);
    auto digest = sumo::Sha256(firmware);

    auto envelope = sumo::ImageManifestBuilder()
        .SetComponentId({"test", "fw"})
        .SetSequenceNumber(1)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .SetPayloadDigest(digest.data(), digest.size(), firmware.size())
        .SetPayloadUri("https://example.com/fw.bin")
        .Build(reconstructed);

    ASSERT_FALSE(envelope.empty());

    auto pub_bytes = original.PublicKeyBytes();
    sumo_validator_t *v = sumo_validator_create(
        pub_bytes.data(), pub_bytes.size(), nullptr);
    ASSERT_NE(v, nullptr);

    sumo_manifest_t *manifest = nullptr;
    EXPECT_EQ(sumo_validate_envelope(
        v, envelope.data(), envelope.size(), 0, &manifest), SUMO_OK);

    if (manifest) sumo_manifest_free(manifest);
    sumo_validator_free(v);
}

/**
 * Two independently generated keys should have different public material.
 */
TEST_F(KeyGenTest, GeneratedKeysDiffer) {
    sumo::CoseKey key1 = sumo::GenerateSigningKey(sumo::ES256);
    sumo::CoseKey key2 = sumo::GenerateSigningKey(sumo::ES256);

    auto pub1 = key1.PublicKeyBytes();
    auto pub2 = key2.PublicKeyBytes();

    ASSERT_FALSE(pub1.empty());
    ASSERT_FALSE(pub2.empty());
    EXPECT_NE(pub1, pub2) << "Two generated keys should differ";
}
