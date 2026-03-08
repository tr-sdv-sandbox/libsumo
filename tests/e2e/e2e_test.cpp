/**
 * @file e2e_test.cpp
 * @brief End-to-end tests: offboard build → onboard validate + decrypt.
 *
 * Tests the full pipeline:
 *   1. Offboard: encrypt firmware with A128KW
 *   2. Offboard: build SUIT manifest (HMAC256 / COSE_Mac0)
 *   3. Onboard: validate the manifest
 *   4. Onboard: stream-decrypt the ciphertext
 *   5. Verify plaintext matches
 */
#include <gtest/gtest.h>
#include <cstring>
#include <numeric>
#include <vector>
#include <string>

#include <openssl/evp.h>

/* Offboard C++ API */
#include "sum2/image_builder.h"
#include "sum2/encryptor.h"

/* Onboard C API */
#include "sum2/validator.h"
#include "sum2/decryptor.h"
#include "sum2/decompressor.h"

/* --- Test key material (same as libcsuit examples) --- */

/* HMAC256 COSE_Key: alg=5, k=32 bytes of 0x61 ("aaa...") */
static const uint8_t hmac256_cose_key[] = {
    0xA4,
       0x01, 0x04,                         /* kty: Symmetric */
       0x02, 0x58, 0x20,                   /* kid: 32 bytes */
          0x16, 0x60, 0x96, 0xC9, 0x21, 0x14, 0x91, 0x5B,
          0xE3, 0xC2, 0xFA, 0x50, 0x47, 0x9C, 0x43, 0x00,
          0x1E, 0x31, 0xA6, 0x75, 0xD0, 0x73, 0x22, 0x7F,
          0x44, 0xA2, 0x81, 0xD6, 0x0F, 0xF8, 0xFD, 0x79,
       0x03, 0x05,                         /* alg: HMAC256 (5) */
       0x20, 0x58, 0x20,                   /* -1 (k): 32 bytes */
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
};

/* A128KW COSE_Key: alg=-3, k=16 bytes of 0x61 */
static const uint8_t a128kw_cose_key[] = {
    0xA4,
       0x01, 0x04,                         /* kty: Symmetric */
       0x02, 0x58, 0x20,                   /* kid: 32 bytes */
          0x01, 0x4E, 0x1D, 0xDC, 0xBE, 0xE9, 0xB3, 0x87,
          0x75, 0xC9, 0xC9, 0x99, 0x85, 0x93, 0x21, 0x1C,
          0x22, 0x87, 0x68, 0x90, 0xF8, 0xB3, 0x76, 0x60,
          0x4F, 0xB2, 0x02, 0xA2, 0x65, 0x34, 0xEF, 0x8F,
       0x03, 0x22,                         /* alg: A128KW (-3) */
       0x20, 0x50,                         /* -1 (k): 16 bytes */
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
};

/* Raw KEK for the onboard decryptor (16 bytes of 0x61) */
static const uint8_t raw_kek[16] = {
    0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
    0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
};

/* ECDH-ES+A128KW P-256 keys (from libcsuit examples) */

/* Sender's (trust anchor) P-256 private key: alg=-29 */
static const uint8_t ecdh_sender_key[] = {
    0xA7,
       0x01, 0x02,                         /* kty: EC2 */
       0x02, 0x58, 0x20,                   /* kid: 32 bytes */
          0xCA, 0x9E, 0x35, 0xF2, 0x3B, 0x2B, 0x52, 0x5F,
          0xB4, 0xFC, 0x83, 0xF5, 0x12, 0xB0, 0xDC, 0xAC,
          0x4A, 0xC2, 0x9E, 0x45, 0x7E, 0x87, 0x3A, 0x5D,
          0x6A, 0x73, 0x13, 0xF7, 0x16, 0x90, 0xB3, 0x3C,
       0x03, 0x38, 0x1C,                   /* alg: ECDH-ES+A128KW (-29) */
       0x20, 0x01,                         /* crv: P-256 (1) */
       0x21, 0x58, 0x20,                   /* x: 32 bytes */
          0x84, 0x96, 0x81, 0x1A, 0xAE, 0x0B, 0xAA, 0xAB,
          0xD2, 0x61, 0x57, 0x18, 0x9E, 0xEC, 0xDA, 0x26,
          0xBE, 0xAA, 0x8B, 0xF1, 0x1B, 0x6F, 0x3F, 0xE6,
          0xE2, 0xB5, 0x65, 0x9C, 0x85, 0xDB, 0xC0, 0xAD,
       0x22, 0x58, 0x20,                   /* y: 32 bytes */
          0x3B, 0x1F, 0x2A, 0x4B, 0x6C, 0x09, 0x81, 0x31,
          0xC0, 0xA3, 0x6D, 0xAC, 0xD1, 0xD7, 0x8B, 0xD3,
          0x81, 0xDC, 0xDF, 0xB0, 0x9C, 0x05, 0x2D, 0xB3,
          0x39, 0x91, 0xDB, 0x73, 0x38, 0xB4, 0xA8, 0x96,
       0x23, 0x58, 0x20,                   /* d: 32 bytes */
          0x02, 0x96, 0x58, 0x8D, 0x90, 0x94, 0x18, 0xB3,
          0x39, 0xD1, 0x50, 0x42, 0x0A, 0x36, 0x12, 0xB5,
          0x7F, 0xB4, 0xF6, 0x31, 0xA6, 0x9F, 0x22, 0x4F,
          0xAE, 0x90, 0xCB, 0x4F, 0x3F, 0xE1, 0x89, 0x73,
};

/* Device's P-256 private key (for decryption): alg=-29 */
static const uint8_t ecdh_device_key_private[] = {
    0xA7,
       0x01, 0x02,                         /* kty: EC2 */
       0x02, 0x58, 0x20,                   /* kid: 32 bytes */
          0xE9, 0x67, 0x88, 0xB1, 0x0B, 0x16, 0x10, 0xAB,
          0xE4, 0x78, 0xF9, 0xCE, 0x8D, 0xCF, 0xE2, 0x30,
          0x4C, 0x09, 0x11, 0xDD, 0x8C, 0xFE, 0xAD, 0xDE,
          0x25, 0xEC, 0x30, 0xCC, 0xB5, 0xA7, 0xB5, 0xAF,
       0x03, 0x38, 0x1C,                   /* alg: ECDH-ES+A128KW (-29) */
       0x20, 0x01,                         /* crv: P-256 (1) */
       0x21, 0x58, 0x20,                   /* x: 32 bytes */
          0x58, 0x86, 0xCD, 0x61, 0xDD, 0x87, 0x58, 0x62,
          0xE5, 0xAA, 0xA8, 0x20, 0xE7, 0xA1, 0x52, 0x74,
          0xC9, 0x68, 0xA9, 0xBC, 0x96, 0x04, 0x8D, 0xDC,
          0xAC, 0xE3, 0x2F, 0x50, 0xC3, 0x65, 0x1B, 0xA3,
       0x22, 0x58, 0x20,                   /* y: 32 bytes */
          0x9E, 0xED, 0x81, 0x25, 0xE9, 0x32, 0xCD, 0x60,
          0xC0, 0xEA, 0xD3, 0x65, 0x0D, 0x0A, 0x48, 0x5C,
          0xF7, 0x26, 0xD3, 0x78, 0xD1, 0xB0, 0x16, 0xED,
          0x42, 0x98, 0xB2, 0x96, 0x1E, 0x25, 0x8F, 0x1B,
       0x23, 0x58, 0x20,                   /* d: 32 bytes */
          0x60, 0xFE, 0x6D, 0xD6, 0xD8, 0x5D, 0x57, 0x40,
          0xA5, 0x34, 0x9B, 0x6F, 0x91, 0x26, 0x7E, 0xEA,
          0xC5, 0xBA, 0x81, 0xB8, 0xCB, 0x53, 0xEE, 0x24,
          0x9E, 0x4B, 0x4E, 0xB1, 0x02, 0xC4, 0x76, 0xB3,
};

/* Device's P-256 public key (for encryption — no d): alg=-29 */
static const uint8_t ecdh_device_key_public[] = {
    0xA6,
       0x01, 0x02,                         /* kty: EC2 */
       0x02, 0x58, 0x20,                   /* kid: 32 bytes */
          0xE9, 0x67, 0x88, 0xB1, 0x0B, 0x16, 0x10, 0xAB,
          0xE4, 0x78, 0xF9, 0xCE, 0x8D, 0xCF, 0xE2, 0x30,
          0x4C, 0x09, 0x11, 0xDD, 0x8C, 0xFE, 0xAD, 0xDE,
          0x25, 0xEC, 0x30, 0xCC, 0xB5, 0xA7, 0xB5, 0xAF,
       0x03, 0x38, 0x1C,                   /* alg: ECDH-ES+A128KW (-29) */
       0x20, 0x01,                         /* crv: P-256 (1) */
       0x21, 0x58, 0x20,                   /* x: 32 bytes */
          0x58, 0x86, 0xCD, 0x61, 0xDD, 0x87, 0x58, 0x62,
          0xE5, 0xAA, 0xA8, 0x20, 0xE7, 0xA1, 0x52, 0x74,
          0xC9, 0x68, 0xA9, 0xBC, 0x96, 0x04, 0x8D, 0xDC,
          0xAC, 0xE3, 0x2F, 0x50, 0xC3, 0x65, 0x1B, 0xA3,
       0x22, 0x58, 0x20,                   /* y: 32 bytes */
          0x9E, 0xED, 0x81, 0x25, 0xE9, 0x32, 0xCD, 0x60,
          0xC0, 0xEA, 0xD3, 0x65, 0x0D, 0x0A, 0x48, 0x5C,
          0xF7, 0x26, 0xD3, 0x78, 0xD1, 0xB0, 0x16, 0xED,
          0x42, 0x98, 0xB2, 0x96, 0x1E, 0x25, 0x8F, 0x1B,
};

/* Test UUIDs */
static const sum2::Uuid test_vendor = {{
    0xFA, 0x6B, 0x4A, 0x53, 0xD5, 0xAD, 0x5F, 0xDF,
    0xBE, 0x9D, 0xE6, 0x63, 0xE4, 0xD4, 0x1F, 0xFE
}};

static const sum2::Uuid test_class = {{
    0x14, 0x92, 0xAF, 0x14, 0x25, 0x69, 0x5E, 0x48,
    0xBF, 0x42, 0x9B, 0x2D, 0x51, 0xF2, 0xAB, 0x45
}};

/* --- Test fixture --- */

class E2ETest : public ::testing::Test {
protected:
    /* Firmware plaintext */
    std::vector<uint8_t> firmware_;

    void SetUp() override {
        const char *text = "Hello, this is test firmware for e2e validation!";
        firmware_.assign(
            reinterpret_cast<const uint8_t *>(text),
            reinterpret_cast<const uint8_t *>(text) + strlen(text));
    }
};

TEST_F(E2ETest, EncryptBuildValidateDecrypt) {
    /* --- OFFBOARD: Encrypt firmware --- */
    sum2::CoseKey enc_key = sum2::CoseKey::FromCoseKeyBytes(
        {a128kw_cose_key, sizeof(a128kw_cose_key)});

    std::vector<sum2::Recipient> recipients;
    recipients.push_back({std::move(enc_key),
        std::vector<uint8_t>(std::begin(raw_kek), std::end(raw_kek))});

    sum2::EncryptedPayload encrypted =
        sum2::EncryptFirmware(firmware_, recipients);

    ASSERT_FALSE(encrypted.ciphertext.empty());
    ASSERT_FALSE(encrypted.encryption_info.empty());
    /* Ciphertext = plaintext + 16 bytes GCM tag */
    EXPECT_EQ(encrypted.ciphertext.size(), firmware_.size() + 16);

    /* --- OFFBOARD: Compute plaintext digest --- */
    auto digest = sum2::Sha256(firmware_);
    ASSERT_EQ(digest.size(), 32u);

    /* --- OFFBOARD: Build manifest --- */
    sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
        {hmac256_cose_key, sizeof(hmac256_cose_key)});

    auto envelope = sum2::ImageManifestBuilder()
        .SetComponentId({"ecu-a", "firmware"})
        .SetSequenceNumber(1)
        .SetVendorId(test_vendor)
        .SetClassId(test_class)
        .SetPayloadDigest(digest.data(), digest.size(), firmware_.size())
        .SetPayloadUri("https://fw.example.com/ecu-a.enc")
        .SetEncryptionInfo(encrypted.encryption_info)
        .Build(signing_key);

    ASSERT_FALSE(envelope.empty());

    /* --- ONBOARD: Validate manifest --- */
    sum2_device_id_t device_id = {};
    memcpy(device_id.vendor_id, test_vendor.bytes, 16);
    memcpy(device_id.class_id, test_class.bytes, 16);

    sum2_validator_t *validator = sum2_validator_create(
        hmac256_cose_key, sizeof(hmac256_cose_key), &device_id);
    ASSERT_NE(validator, nullptr);

    sum2_manifest_t *manifest = nullptr;
    int rc = sum2_validate_envelope(
        validator, envelope.data(), envelope.size(), 0, &manifest);
    ASSERT_EQ(rc, SUM2_OK) << "Validation failed with rc=" << rc;
    ASSERT_NE(manifest, nullptr);

    /* Verify manifest metadata */
    EXPECT_EQ(sum2_manifest_sequence_number(manifest), 1u);
    EXPECT_EQ(sum2_manifest_component_count(manifest), 1u);

    uint8_t vendor_out[16];
    EXPECT_EQ(sum2_manifest_vendor_id(manifest, 0, vendor_out), SUM2_OK);
    EXPECT_EQ(memcmp(vendor_out, test_vendor.bytes, 16), 0);

    /* Verify image digest and size are extractable */
    const uint8_t *manifest_digest = nullptr;
    size_t manifest_digest_len = 0;
    int digest_alg = 0;
    ASSERT_EQ(sum2_manifest_image_digest(manifest, 0,
        &manifest_digest, &manifest_digest_len, &digest_alg), SUM2_OK);
    EXPECT_EQ(manifest_digest_len, 32u);
    EXPECT_EQ(memcmp(manifest_digest, digest.data(), 32), 0);

    uint64_t manifest_size = 0;
    ASSERT_EQ(sum2_manifest_image_size(manifest, 0, &manifest_size), SUM2_OK);
    EXPECT_EQ(manifest_size, firmware_.size());

    /* --- ONBOARD: Decrypt firmware --- */
    sum2_decryptor_t *decryptor = sum2_decryptor_create(
        manifest, 0, raw_kek, sizeof(raw_kek));
    ASSERT_NE(decryptor, nullptr) << "Failed to create decryptor";

    /* Feed all ciphertext in one shot */
    std::vector<uint8_t> plaintext(encrypted.ciphertext.size());
    size_t pt_len = plaintext.size();
    rc = sum2_decryptor_update(
        decryptor,
        encrypted.ciphertext.data(), encrypted.ciphertext.size(),
        plaintext.data(), &pt_len);
    ASSERT_EQ(rc, 0) << "Decryptor update failed";

    /* Finalize and verify GCM tag */
    uint8_t final_buf[64];
    size_t final_len = sizeof(final_buf);
    rc = sum2_decryptor_finalize(decryptor, final_buf, &final_len);
    ASSERT_EQ(rc, 0) << "Decryptor finalize failed (GCM tag mismatch?)";

    /* Assemble full plaintext */
    size_t total = pt_len + final_len;
    EXPECT_EQ(total, firmware_.size());
    EXPECT_EQ(memcmp(plaintext.data(), firmware_.data(), pt_len), 0);

    sum2_decryptor_free(decryptor);
    sum2_manifest_free(manifest);
    sum2_validator_free(validator);
}

TEST_F(E2ETest, StreamingDecrypt) {
    /* Same as above but feed ciphertext in small chunks */
    sum2::CoseKey enc_key = sum2::CoseKey::FromCoseKeyBytes(
        {a128kw_cose_key, sizeof(a128kw_cose_key)});

    std::vector<sum2::Recipient> recipients;
    recipients.push_back({std::move(enc_key), {}});

    auto encrypted = sum2::EncryptFirmware(firmware_, recipients);
    auto digest = sum2::Sha256(firmware_);

    sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
        {hmac256_cose_key, sizeof(hmac256_cose_key)});

    auto envelope = sum2::ImageManifestBuilder()
        .SetComponentId({"ecu-a", "firmware"})
        .SetSequenceNumber(2)
        .SetVendorId(test_vendor)
        .SetClassId(test_class)
        .SetPayloadDigest(digest.data(), digest.size(), firmware_.size())
        .SetPayloadUri("https://fw.example.com/ecu-a.enc")
        .SetEncryptionInfo(encrypted.encryption_info)
        .Build(signing_key);

    sum2_device_id_t device_id = {};
    memcpy(device_id.vendor_id, test_vendor.bytes, 16);
    memcpy(device_id.class_id, test_class.bytes, 16);

    sum2_validator_t *validator = sum2_validator_create(
        hmac256_cose_key, sizeof(hmac256_cose_key), &device_id);
    ASSERT_NE(validator, nullptr);

    sum2_manifest_t *manifest = nullptr;
    ASSERT_EQ(sum2_validate_envelope(
        validator, envelope.data(), envelope.size(), 0, &manifest), SUM2_OK);

    sum2_decryptor_t *decryptor = sum2_decryptor_create(
        manifest, 0, raw_kek, sizeof(raw_kek));
    ASSERT_NE(decryptor, nullptr);

    /* Stream in 7-byte chunks */
    std::vector<uint8_t> all_pt;
    const size_t chunk = 7;
    for (size_t off = 0; off < encrypted.ciphertext.size(); off += chunk) {
        size_t n = std::min(chunk, encrypted.ciphertext.size() - off);
        uint8_t pt_buf[64];
        size_t pt_len = sizeof(pt_buf);
        int rc = sum2_decryptor_update(
            decryptor,
            encrypted.ciphertext.data() + off, n,
            pt_buf, &pt_len);
        ASSERT_EQ(rc, 0) << "chunk at offset " << off;
        all_pt.insert(all_pt.end(), pt_buf, pt_buf + pt_len);
    }

    uint8_t final_buf[64];
    size_t final_len = sizeof(final_buf);
    ASSERT_EQ(sum2_decryptor_finalize(decryptor, final_buf, &final_len), 0);
    all_pt.insert(all_pt.end(), final_buf, final_buf + final_len);

    EXPECT_EQ(all_pt.size(), firmware_.size());
    EXPECT_EQ(all_pt, firmware_);

    sum2_decryptor_free(decryptor);
    sum2_manifest_free(manifest);
    sum2_validator_free(validator);
}

TEST_F(E2ETest, WrongMacKeyRejectsManifest) {
    /* Build a valid manifest */
    auto digest = sum2::Sha256(firmware_);
    sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
        {hmac256_cose_key, sizeof(hmac256_cose_key)});

    auto envelope = sum2::ImageManifestBuilder()
        .SetComponentId({"ecu-a", "firmware"})
        .SetSequenceNumber(1)
        .SetVendorId(test_vendor)
        .SetClassId(test_class)
        .SetPayloadDigest(digest.data(), digest.size(), firmware_.size())
        .SetPayloadUri("https://fw.example.com/ecu-a.enc")
        .Build(signing_key);

    /* Try to validate with a DIFFERENT key */
    uint8_t wrong_key[sizeof(hmac256_cose_key)];
    memcpy(wrong_key, hmac256_cose_key, sizeof(hmac256_cose_key));
    wrong_key[sizeof(wrong_key) - 1] ^= 0xFF; /* flip last byte of k */

    sum2_validator_t *validator = sum2_validator_create(
        wrong_key, sizeof(wrong_key), nullptr);
    ASSERT_NE(validator, nullptr);

    sum2_manifest_t *manifest = nullptr;
    int rc = sum2_validate_envelope(
        validator, envelope.data(), envelope.size(), 0, &manifest);
    EXPECT_NE(rc, SUM2_OK) << "Should have rejected with wrong key";
    EXPECT_EQ(manifest, nullptr);

    sum2_validator_free(validator);
}

TEST_F(E2ETest, UnencryptedManifest) {
    /* Build manifest without encryption info */
    auto digest = sum2::Sha256(firmware_);
    sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
        {hmac256_cose_key, sizeof(hmac256_cose_key)});

    auto envelope = sum2::ImageManifestBuilder()
        .SetComponentId({"ecu-a", "firmware"})
        .SetSequenceNumber(1)
        .SetVendorId(test_vendor)
        .SetClassId(test_class)
        .SetPayloadDigest(digest.data(), digest.size(), firmware_.size())
        .SetPayloadUri("https://fw.example.com/ecu-a.bin")
        .Build(signing_key);

    sum2_device_id_t device_id = {};
    memcpy(device_id.vendor_id, test_vendor.bytes, 16);
    memcpy(device_id.class_id, test_class.bytes, 16);

    sum2_validator_t *validator = sum2_validator_create(
        hmac256_cose_key, sizeof(hmac256_cose_key), &device_id);
    ASSERT_NE(validator, nullptr);

    sum2_manifest_t *manifest = nullptr;
    ASSERT_EQ(sum2_validate_envelope(
        validator, envelope.data(), envelope.size(), 0, &manifest), SUM2_OK);
    ASSERT_NE(manifest, nullptr);

    EXPECT_EQ(sum2_manifest_sequence_number(manifest), 1u);

    /* No encryption info → decryptor should fail to create */
    sum2_decryptor_t *decryptor = sum2_decryptor_create(
        manifest, 0, raw_kek, sizeof(raw_kek));
    EXPECT_EQ(decryptor, nullptr) << "Should fail: no encryption info";

    sum2_manifest_free(manifest);
    sum2_validator_free(validator);
}

/**
 * Simulates a real A/B bank device update flow with a 1MB firmware image.
 *
 * Device has a fixed 4KB RAM buffer — never holds the full image.
 * After decryption, verifies SHA-256 digest matches the manifest
 * (exactly what a device would do before committing the bank swap).
 */
TEST_F(E2ETest, RealisticStreamingDecrypt1MB) {
    /* Generate a 1MB "firmware" with recognizable pattern */
    const size_t FW_SIZE = 1024 * 1024;
    std::vector<uint8_t> big_fw(FW_SIZE);
    for (size_t i = 0; i < FW_SIZE; i++)
        big_fw[i] = static_cast<uint8_t>(i ^ (i >> 8) ^ (i >> 16));

    /* --- OFFBOARD --- */
    sum2::CoseKey enc_key = sum2::CoseKey::FromCoseKeyBytes(
        {a128kw_cose_key, sizeof(a128kw_cose_key)});
    std::vector<sum2::Recipient> recipients;
    recipients.push_back({std::move(enc_key), {}});

    auto encrypted = sum2::EncryptFirmware(big_fw, recipients);
    ASSERT_EQ(encrypted.ciphertext.size(), FW_SIZE + 16);

    auto digest = sum2::Sha256(big_fw);

    sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
        {hmac256_cose_key, sizeof(hmac256_cose_key)});

    auto envelope = sum2::ImageManifestBuilder()
        .SetComponentId({"ecu-a", "firmware"})
        .SetSequenceNumber(10)
        .SetVendorId(test_vendor)
        .SetClassId(test_class)
        .SetPayloadDigest(digest.data(), digest.size(), FW_SIZE)
        .SetPayloadUri("https://fw.example.com/ecu-a-v10.enc")
        .SetEncryptionInfo(encrypted.encryption_info)
        .Build(signing_key);

    /* --- ONBOARD: Validate --- */
    sum2_device_id_t device_id = {};
    memcpy(device_id.vendor_id, test_vendor.bytes, 16);
    memcpy(device_id.class_id, test_class.bytes, 16);

    sum2_validator_t *validator = sum2_validator_create(
        hmac256_cose_key, sizeof(hmac256_cose_key), &device_id);
    ASSERT_NE(validator, nullptr);

    sum2_manifest_t *manifest = nullptr;
    ASSERT_EQ(sum2_validate_envelope(
        validator, envelope.data(), envelope.size(), 0, &manifest), SUM2_OK);

    /* Extract expected digest and size from manifest */
    const uint8_t *expected_digest = nullptr;
    size_t expected_digest_len = 0;
    ASSERT_EQ(sum2_manifest_image_digest(manifest, 0,
        &expected_digest, &expected_digest_len, nullptr), SUM2_OK);
    ASSERT_EQ(expected_digest_len, 32u);

    uint64_t expected_size = 0;
    ASSERT_EQ(sum2_manifest_image_size(manifest, 0, &expected_size), SUM2_OK);
    ASSERT_EQ(expected_size, FW_SIZE);

    /* --- ONBOARD: Stream-decrypt with 4KB buffer (simulating flash writes) --- */
    sum2_decryptor_t *decryptor = sum2_decryptor_create(
        manifest, 0, raw_kek, sizeof(raw_kek));
    ASSERT_NE(decryptor, nullptr);

    /* Incremental SHA-256 of decrypted output (would run on device) */
    EVP_MD_CTX *hash_ctx = EVP_MD_CTX_new();
    ASSERT_NE(hash_ctx, nullptr);
    EVP_DigestInit_ex(hash_ctx, EVP_sha256(), nullptr);

    const size_t CHUNK = 4096;  /* 4KB — typical flash page / network MTU */
    uint8_t pt_buf[CHUNK + 64]; /* small extra for AES block alignment */
    size_t total_decrypted = 0;

    for (size_t off = 0; off < encrypted.ciphertext.size(); off += CHUNK) {
        size_t n = std::min(CHUNK, encrypted.ciphertext.size() - off);
        size_t pt_len = sizeof(pt_buf);
        int rc = sum2_decryptor_update(
            decryptor,
            encrypted.ciphertext.data() + off, n,
            pt_buf, &pt_len);
        ASSERT_EQ(rc, 0) << "update failed at offset " << off;

        if (pt_len > 0) {
            /* "Write to flash bank B" — verify against original */
            ASSERT_LE(total_decrypted + pt_len, big_fw.size());
            EXPECT_EQ(memcmp(pt_buf, big_fw.data() + total_decrypted, pt_len), 0)
                << "mismatch at decrypted offset " << total_decrypted;

            /* Incremental hash */
            EVP_DigestUpdate(hash_ctx, pt_buf, pt_len);
            total_decrypted += pt_len;
        }
    }

    /* Finalize — verify GCM authentication tag */
    size_t final_len = sizeof(pt_buf);
    ASSERT_EQ(sum2_decryptor_finalize(decryptor, pt_buf, &final_len), 0)
        << "GCM tag verification failed";

    if (final_len > 0) {
        EVP_DigestUpdate(hash_ctx, pt_buf, final_len);
        total_decrypted += final_len;
    }

    EXPECT_EQ(total_decrypted, FW_SIZE);

    /* Verify digest matches manifest */
    uint8_t computed_digest[32];
    EVP_DigestFinal_ex(hash_ctx, computed_digest, nullptr);
    EVP_MD_CTX_free(hash_ctx);

    EXPECT_EQ(memcmp(computed_digest, expected_digest, 32), 0)
        << "Plaintext digest mismatch — firmware corrupted";

    sum2_decryptor_free(decryptor);
    sum2_manifest_free(manifest);
    sum2_validator_free(validator);
}

/**
 * Full pipeline with zstd compression:
 *   Offboard: compress → encrypt → build manifest (digest of PLAINTEXT)
 *   Device:   validate → stream decrypt → stream decompress → verify digest
 *
 * Uses 4KB buffers throughout — never holds the full image in RAM.
 */
TEST_F(E2ETest, CompressEncryptDecryptDecompress1MB) {
    /* 1MB firmware with repetitive content (compresses well) */
    const size_t FW_SIZE = 1024 * 1024;
    std::vector<uint8_t> big_fw(FW_SIZE);
    for (size_t i = 0; i < FW_SIZE; i++)
        big_fw[i] = static_cast<uint8_t>(i % 251);  /* modular pattern */

    /* --- OFFBOARD: compress → encrypt → manifest --- */
    auto compressed = sum2::CompressFirmware(big_fw);
    ASSERT_LT(compressed.size(), FW_SIZE)
        << "Compression should reduce size";

    sum2::CoseKey enc_key = sum2::CoseKey::FromCoseKeyBytes(
        {a128kw_cose_key, sizeof(a128kw_cose_key)});
    std::vector<sum2::Recipient> recipients;
    recipients.push_back({std::move(enc_key), {}});

    /* Encrypt the COMPRESSED data */
    auto encrypted = sum2::EncryptFirmware(compressed, recipients);

    /* Digest and size are of the PLAINTEXT (pre-compression) */
    auto digest = sum2::Sha256(big_fw);

    sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
        {hmac256_cose_key, sizeof(hmac256_cose_key)});

    auto envelope = sum2::ImageManifestBuilder()
        .SetComponentId({"ecu-a", "firmware"})
        .SetSequenceNumber(20)
        .SetVendorId(test_vendor)
        .SetClassId(test_class)
        .SetPayloadDigest(digest.data(), digest.size(), FW_SIZE)
        .SetPayloadUri("https://fw.example.com/ecu-a-v20.zst.enc")
        .SetEncryptionInfo(encrypted.encryption_info)
        .Build(signing_key);

    /* --- ONBOARD: validate --- */
    sum2_device_id_t device_id = {};
    memcpy(device_id.vendor_id, test_vendor.bytes, 16);
    memcpy(device_id.class_id, test_class.bytes, 16);

    sum2_validator_t *validator = sum2_validator_create(
        hmac256_cose_key, sizeof(hmac256_cose_key), &device_id);
    ASSERT_NE(validator, nullptr);

    sum2_manifest_t *manifest = nullptr;
    ASSERT_EQ(sum2_validate_envelope(
        validator, envelope.data(), envelope.size(), 0, &manifest), SUM2_OK);

    uint64_t expected_size = 0;
    ASSERT_EQ(sum2_manifest_image_size(manifest, 0, &expected_size), SUM2_OK);
    ASSERT_EQ(expected_size, FW_SIZE);

    const uint8_t *expected_digest = nullptr;
    size_t expected_digest_len = 0;
    ASSERT_EQ(sum2_manifest_image_digest(manifest, 0,
        &expected_digest, &expected_digest_len, nullptr), SUM2_OK);

    /* --- ONBOARD: stream decrypt → decompress --- */
    sum2_decryptor_t *decryptor = sum2_decryptor_create(
        manifest, 0, raw_kek, sizeof(raw_kek));
    ASSERT_NE(decryptor, nullptr);

    sum2_decompressor_t *decompressor = sum2_decompressor_create();
    ASSERT_NE(decompressor, nullptr);

    EVP_MD_CTX *hash_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(hash_ctx, EVP_sha256(), nullptr);

    const size_t CHUNK = 4096;
    uint8_t dec_buf[CHUNK + 64];   /* decrypted (still compressed) */
    uint8_t decomp_buf[CHUNK * 4]; /* decompressed output */
    size_t total_decompressed = 0;

    auto drain_decompressor = [&](const uint8_t *data, size_t len) {
        size_t pos = 0;
        while (pos < len) {
            size_t remaining = len - pos;
            size_t out_len = sizeof(decomp_buf);
            ASSERT_EQ(sum2_decompressor_update(decompressor,
                data + pos, &remaining,
                decomp_buf, &out_len), 0);
            pos += remaining;

            if (out_len > 0) {
                ASSERT_LE(total_decompressed + out_len, FW_SIZE);
                EXPECT_EQ(memcmp(decomp_buf,
                    big_fw.data() + total_decompressed, out_len), 0);
                EVP_DigestUpdate(hash_ctx, decomp_buf, out_len);
                total_decompressed += out_len;
            }
            if (remaining == 0 && out_len == 0) break;
        }
    };

    for (size_t off = 0; off < encrypted.ciphertext.size(); off += CHUNK) {
        size_t n = std::min(CHUNK, encrypted.ciphertext.size() - off);

        /* Decrypt chunk */
        size_t dec_len = sizeof(dec_buf);
        ASSERT_EQ(sum2_decryptor_update(decryptor,
            encrypted.ciphertext.data() + off, n,
            dec_buf, &dec_len), 0);

        /* Decompress decrypted output */
        if (dec_len > 0)
            drain_decompressor(dec_buf, dec_len);
    }

    /* Finalize decryption (verify GCM tag) */
    size_t final_dec_len = sizeof(dec_buf);
    ASSERT_EQ(sum2_decryptor_finalize(decryptor, dec_buf, &final_dec_len), 0);

    if (final_dec_len > 0)
        drain_decompressor(dec_buf, final_dec_len);

    /* Drain any remaining buffered decompression output */
    while (true) {
        size_t zero_in = 0;
        size_t out_len = sizeof(decomp_buf);
        ASSERT_EQ(sum2_decompressor_update(decompressor,
            nullptr, &zero_in, decomp_buf, &out_len), 0);
        if (out_len == 0) break;
        EVP_DigestUpdate(hash_ctx, decomp_buf, out_len);
        total_decompressed += out_len;
    }

    ASSERT_EQ(sum2_decompressor_finalize(decompressor), 0);
    EXPECT_EQ(total_decompressed, FW_SIZE);

    /* Verify plaintext digest */
    uint8_t computed_digest[32];
    EVP_DigestFinal_ex(hash_ctx, computed_digest, nullptr);
    EVP_MD_CTX_free(hash_ctx);

    EXPECT_EQ(memcmp(computed_digest, expected_digest, 32), 0)
        << "Decompressed firmware digest mismatch";

    sum2_decompressor_free(decompressor);
    sum2_decryptor_free(decryptor);
    sum2_manifest_free(manifest);
    sum2_validator_free(validator);
}

/**
 * ECDH-ES+A128KW: per-device asymmetric key wrapping.
 *
 * Offboard: encrypt with sender's P-256 key + device's P-256 public key
 * Onboard:  decrypt with device's P-256 private key
 *
 * This matches the per-device security model where:
 * - Each device has a unique P-256 key pair
 * - Compromising one device's key doesn't expose other devices' firmware
 * - Server only needs device's public key
 */
TEST_F(E2ETest, EcdhEsA128kwPerDeviceEncryption) {
    /* --- OFFBOARD: Encrypt with ECDH-ES+A128KW --- */
    sum2::CoseKey sender_key = sum2::CoseKey::FromCoseKeyBytes(
        {ecdh_sender_key, sizeof(ecdh_sender_key)});

    /* Use the device's private key as receiver (libcsuit extracts public part) */
    sum2::CoseKey recv_key = sum2::CoseKey::FromCoseKeyBytes(
        {ecdh_device_key_private, sizeof(ecdh_device_key_private)});

    std::vector<uint8_t> kid = {0x6B, 0x69, 0x64, 0x2D, 0x32}; /* "kid-2" */
    std::vector<sum2::Recipient> recipients;
    recipients.push_back({std::move(recv_key), kid});

    auto encrypted = sum2::EncryptFirmwareEcdh(firmware_, sender_key, recipients);

    ASSERT_FALSE(encrypted.ciphertext.empty());
    ASSERT_FALSE(encrypted.encryption_info.empty());
    EXPECT_EQ(encrypted.ciphertext.size(), firmware_.size() + 16);

    /* --- OFFBOARD: Build manifest --- */
    auto digest = sum2::Sha256(firmware_);

    sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
        {hmac256_cose_key, sizeof(hmac256_cose_key)});

    auto envelope = sum2::ImageManifestBuilder()
        .SetComponentId({"ecu-a", "firmware"})
        .SetSequenceNumber(100)
        .SetVendorId(test_vendor)
        .SetClassId(test_class)
        .SetPayloadDigest(digest.data(), digest.size(), firmware_.size())
        .SetPayloadUri("https://fw.example.com/ecu-a-ecdh.enc")
        .SetEncryptionInfo(encrypted.encryption_info)
        .Build(signing_key);

    ASSERT_FALSE(envelope.empty());

    /* --- ONBOARD: Validate manifest --- */
    sum2_device_id_t device_id = {};
    memcpy(device_id.vendor_id, test_vendor.bytes, 16);
    memcpy(device_id.class_id, test_class.bytes, 16);

    sum2_validator_t *validator = sum2_validator_create(
        hmac256_cose_key, sizeof(hmac256_cose_key), &device_id);
    ASSERT_NE(validator, nullptr);

    sum2_manifest_t *manifest = nullptr;
    int rc = sum2_validate_envelope(
        validator, envelope.data(), envelope.size(), 0, &manifest);
    ASSERT_EQ(rc, SUM2_OK) << "Validation failed with rc=" << rc;

    /* --- ONBOARD: Decrypt with device's private COSE_Key --- */
    sum2_decryptor_t *decryptor = sum2_decryptor_create(
        manifest, 0,
        ecdh_device_key_private, sizeof(ecdh_device_key_private));
    ASSERT_NE(decryptor, nullptr) << "ECDH decryptor creation failed";

    /* One-shot decrypt */
    std::vector<uint8_t> plaintext(encrypted.ciphertext.size());
    size_t pt_len = plaintext.size();
    rc = sum2_decryptor_update(
        decryptor,
        encrypted.ciphertext.data(), encrypted.ciphertext.size(),
        plaintext.data(), &pt_len);
    ASSERT_EQ(rc, 0) << "ECDH decryptor update failed";

    uint8_t final_buf[64];
    size_t final_len = sizeof(final_buf);
    rc = sum2_decryptor_finalize(decryptor, final_buf, &final_len);
    ASSERT_EQ(rc, 0) << "ECDH decryptor finalize failed (GCM tag mismatch?)";

    size_t total = pt_len + final_len;
    EXPECT_EQ(total, firmware_.size());
    EXPECT_EQ(memcmp(plaintext.data(), firmware_.data(), pt_len), 0);

    sum2_decryptor_free(decryptor);
    sum2_manifest_free(manifest);
    sum2_validator_free(validator);
}

/**
 * ECDH-ES+A128KW with streaming 4KB chunks on 1MB firmware.
 */
TEST_F(E2ETest, EcdhEsA128kwStreaming1MB) {
    const size_t FW_SIZE = 1024 * 1024;
    std::vector<uint8_t> big_fw(FW_SIZE);
    for (size_t i = 0; i < FW_SIZE; i++)
        big_fw[i] = static_cast<uint8_t>(i ^ (i >> 8) ^ (i >> 16));

    /* --- OFFBOARD --- */
    sum2::CoseKey sender_key = sum2::CoseKey::FromCoseKeyBytes(
        {ecdh_sender_key, sizeof(ecdh_sender_key)});

    sum2::CoseKey recv_key = sum2::CoseKey::FromCoseKeyBytes(
        {ecdh_device_key_private, sizeof(ecdh_device_key_private)});

    std::vector<uint8_t> kid = {0x6B, 0x69, 0x64, 0x2D, 0x32};
    std::vector<sum2::Recipient> recipients;
    recipients.push_back({std::move(recv_key), kid});

    auto encrypted = sum2::EncryptFirmwareEcdh(big_fw, sender_key, recipients);
    auto digest_vec = sum2::Sha256(big_fw);

    sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
        {hmac256_cose_key, sizeof(hmac256_cose_key)});

    auto envelope = sum2::ImageManifestBuilder()
        .SetComponentId({"ecu-a", "firmware"})
        .SetSequenceNumber(200)
        .SetVendorId(test_vendor)
        .SetClassId(test_class)
        .SetPayloadDigest(digest_vec.data(), digest_vec.size(), FW_SIZE)
        .SetPayloadUri("https://fw.example.com/ecu-a-ecdh-v200.enc")
        .SetEncryptionInfo(encrypted.encryption_info)
        .Build(signing_key);

    /* --- ONBOARD --- */
    sum2_device_id_t device_id = {};
    memcpy(device_id.vendor_id, test_vendor.bytes, 16);
    memcpy(device_id.class_id, test_class.bytes, 16);

    sum2_validator_t *validator = sum2_validator_create(
        hmac256_cose_key, sizeof(hmac256_cose_key), &device_id);
    ASSERT_NE(validator, nullptr);

    sum2_manifest_t *manifest = nullptr;
    ASSERT_EQ(sum2_validate_envelope(
        validator, envelope.data(), envelope.size(), 0, &manifest), SUM2_OK);

    sum2_decryptor_t *decryptor = sum2_decryptor_create(
        manifest, 0,
        ecdh_device_key_private, sizeof(ecdh_device_key_private));
    ASSERT_NE(decryptor, nullptr);

    /* Stream with 4KB chunks + incremental SHA-256 */
    EVP_MD_CTX *hash_ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(hash_ctx, EVP_sha256(), nullptr);

    const size_t CHUNK = 4096;
    uint8_t pt_buf[CHUNK + 64];
    size_t total_decrypted = 0;

    for (size_t off = 0; off < encrypted.ciphertext.size(); off += CHUNK) {
        size_t n = std::min(CHUNK, encrypted.ciphertext.size() - off);
        size_t pt_len = sizeof(pt_buf);
        ASSERT_EQ(sum2_decryptor_update(decryptor,
            encrypted.ciphertext.data() + off, n,
            pt_buf, &pt_len), 0);

        if (pt_len > 0) {
            EVP_DigestUpdate(hash_ctx, pt_buf, pt_len);
            total_decrypted += pt_len;
        }
    }

    size_t final_len = sizeof(pt_buf);
    ASSERT_EQ(sum2_decryptor_finalize(decryptor, pt_buf, &final_len), 0);
    if (final_len > 0) {
        EVP_DigestUpdate(hash_ctx, pt_buf, final_len);
        total_decrypted += final_len;
    }

    EXPECT_EQ(total_decrypted, FW_SIZE);

    uint8_t computed_digest[32];
    EVP_DigestFinal_ex(hash_ctx, computed_digest, nullptr);
    EVP_MD_CTX_free(hash_ctx);

    const uint8_t *expected_digest = nullptr;
    size_t expected_digest_len = 0;
    ASSERT_EQ(sum2_manifest_image_digest(manifest, 0,
        &expected_digest, &expected_digest_len, nullptr), SUM2_OK);
    EXPECT_EQ(memcmp(computed_digest, expected_digest, 32), 0)
        << "ECDH-ES+A128KW streaming decrypt digest mismatch";

    sum2_decryptor_free(decryptor);
    sum2_manifest_free(manifest);
    sum2_validator_free(validator);
}
