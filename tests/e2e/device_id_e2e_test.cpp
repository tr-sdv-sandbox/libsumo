/**
 * @file device_id_test.cpp
 * @brief T1.1 — exercise device-ID condition checking in sumo_validate_envelope.
 *
 * Builds an envelope with vendor + class UUID conditions via the offboard
 * builder, then runs it through validators configured with matching,
 * mismatched, and absent device identities.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

#include "sumo/image_builder.h"

extern "C" {
#include "sumo/validator.h"
}

/* HMAC256 COSE_Key — same fixture used by e2e_test.cpp. Kept local so this
 * test file does not depend on e2e linkage. */
static const uint8_t kHmac256CoseKey[] = {
    0xA4,
    0x01, 0x04,
    0x02, 0x58, 0x20,
        0x16, 0x60, 0x96, 0xC9, 0x21, 0x14, 0x91, 0x5B,
        0xE3, 0xC2, 0xFA, 0x50, 0x47, 0x9C, 0x43, 0x00,
        0x1E, 0x31, 0xA6, 0x75, 0xD0, 0x73, 0x22, 0x7F,
        0x44, 0xA2, 0x81, 0xD6, 0x0F, 0xF8, 0xFD, 0x79,
    0x03, 0x05,
    0x20, 0x58, 0x20,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
};

static const sumo::Uuid kVendorA = {{
    0xFA, 0x6B, 0x4A, 0x53, 0xD5, 0xAD, 0x5F, 0xDF,
    0xBE, 0x9D, 0xE6, 0x63, 0xE4, 0xD4, 0x1F, 0xFE,
}};

static const sumo::Uuid kClassA = {{
    0x14, 0x92, 0xAF, 0x14, 0x25, 0x69, 0x5E, 0x48,
    0xBF, 0x42, 0x9B, 0x2D, 0x51, 0xF2, 0xAB, 0x45,
}};

/* Different UUIDs for mismatch cases */
static const sumo::Uuid kVendorB = {{
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
}};

static const sumo::Uuid kClassB = {{
    0xAB, 0xCD, 0xEF, 0x00, 0x11, 0x22, 0x33, 0x44,
    0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
}};

/* --- Fixture envelope built by sumo-tool, signed ES256, with the
 * suit-parameter-device-identifier set in the override-parameters map.
 * Used by the DeviceIdMismatch tests below — exercises the validator's
 * SUMO_ERR_DEVICE_MISMATCH branch that the offboard ImageManifestBuilder
 * cannot produce (no SetDeviceId knob). Build command:
 *   sumo-tool build --signing-key sign.key --component "ecu-a,firmware" \
 *     --seq 1 --vendor fa6b4a53d5ad5fdfbe9de663e4d41ffe \
 *     --class 1492af1425695e48bf429b2d51f2ab45 \
 *     --device 0123456789abcdef0011223344556677 \
 *     --uri file:///tmp/fw.bin --payload-digest 00..00 --payload-size 100
 */
static const uint8_t kSignPub[] = {
    0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20, 0x2e, 0x72,
    0xf7, 0x48, 0xe7, 0x4f, 0x9a, 0x17, 0xee, 0x0b, 0x1d, 0xd7, 0x8c, 0x0e,
    0x89, 0xcf, 0x9f, 0x1b, 0x6b, 0x97, 0x89, 0xa3, 0xad, 0x81, 0x66, 0x7e,
    0x12, 0xe1, 0x9f, 0xfd, 0x22, 0x7a, 0x22, 0x58, 0x20, 0xd0, 0x93, 0xa3,
    0xd3, 0xe8, 0x3d, 0xcb, 0xd1, 0x07, 0x07, 0x0d, 0x05, 0x01, 0x77, 0x92,
    0x07, 0x17, 0x13, 0x76, 0x6e, 0xda, 0xcc, 0x2b, 0xf3, 0xa6, 0xa7, 0xb2,
    0x95, 0x5d, 0x51, 0x7b, 0x82,
};

static const uint8_t kEnvelopeWithDeviceId[] = {
    0xa2, 0x02, 0x58, 0x73, 0x82, 0x58, 0x24, 0x82, 0x2f, 0x58, 0x20, 0xa9,
    0x85, 0x79, 0x7c, 0x14, 0x35, 0xad, 0x7f, 0xae, 0xe2, 0x69, 0x89, 0xc5,
    0x4e, 0xc8, 0x72, 0x5a, 0xe5, 0x1f, 0x57, 0x03, 0x20, 0xc5, 0xae, 0xbe,
    0x2e, 0x49, 0x87, 0xc8, 0xb8, 0x7e, 0x93, 0x58, 0x4a, 0xd2, 0x84, 0x43,
    0xa1, 0x01, 0x26, 0xa0, 0xf6, 0x58, 0x40, 0x4b, 0x70, 0x1f, 0x5e, 0xa3,
    0x5f, 0x82, 0x00, 0x30, 0x93, 0x55, 0x24, 0xfb, 0xd9, 0x4e, 0x6b, 0xf3,
    0x91, 0x28, 0x68, 0x57, 0x5e, 0x79, 0xad, 0x94, 0x5c, 0xd4, 0xfa, 0x62,
    0x81, 0xe3, 0xb9, 0x0e, 0x7d, 0xfc, 0x35, 0x0b, 0x3c, 0x18, 0x81, 0xfa,
    0xb4, 0xff, 0x4c, 0xd2, 0xa8, 0xf6, 0xec, 0xf0, 0xaf, 0x7e, 0x99, 0x6d,
    0xab, 0x8b, 0xd3, 0xc0, 0xb7, 0xd8, 0x6f, 0x08, 0xfb, 0x97, 0xb3, 0x03,
    0x58, 0x9c, 0xa6, 0x01, 0x01, 0x02, 0x01, 0x03, 0x58, 0x85, 0xa2, 0x02,
    0x81, 0x82, 0x45, 0x65, 0x63, 0x75, 0x2d, 0x61, 0x48, 0x66, 0x69, 0x72,
    0x6d, 0x77, 0x61, 0x72, 0x65, 0x04, 0x58, 0x6f, 0x82, 0x14, 0xa6, 0x01,
    0x50, 0xfa, 0x6b, 0x4a, 0x53, 0xd5, 0xad, 0x5f, 0xdf, 0xbe, 0x9d, 0xe6,
    0x63, 0xe4, 0xd4, 0x1f, 0xfe, 0x02, 0x50, 0x14, 0x92, 0xaf, 0x14, 0x25,
    0x69, 0x5e, 0x48, 0xbf, 0x42, 0x9b, 0x2d, 0x51, 0xf2, 0xab, 0x45, 0x03,
    0x58, 0x24, 0x82, 0x2f, 0x58, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x0e, 0x18, 0x64, 0x15, 0x69, 0x23, 0x66, 0x69, 0x72, 0x6d,
    0x77, 0x61, 0x72, 0x65, 0x18, 0x18, 0x50, 0x01, 0x23, 0x45, 0x67, 0x89,
    0xab, 0xcd, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x07,
    0x43, 0x82, 0x03, 0x00, 0x09, 0x43, 0x82, 0x17, 0x00, 0x14, 0x43, 0x82,
    0x16, 0x00,
};

/* The vendor/class/device UUIDs encoded in kEnvelopeWithDeviceId. */
static const uint8_t kEmbeddedVendor[16] = {
    0xfa, 0x6b, 0x4a, 0x53, 0xd5, 0xad, 0x5f, 0xdf,
    0xbe, 0x9d, 0xe6, 0x63, 0xe4, 0xd4, 0x1f, 0xfe,
};
static const uint8_t kEmbeddedClass[16] = {
    0x14, 0x92, 0xaf, 0x14, 0x25, 0x69, 0x5e, 0x48,
    0xbf, 0x42, 0x9b, 0x2d, 0x51, 0xf2, 0xab, 0x45,
};
static const uint8_t kEmbeddedDevice[16] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
};

class DeviceIdTest : public ::testing::Test {
protected:
    std::vector<uint8_t> envelope_;

    void SetUp() override {
        /* The validator only inspects the manifest; an unencrypted reference
         * envelope with vendor+class conditions is enough. */
        const uint8_t plaintext[] = "device-id-conditions test fixture";
        size_t pt_len = sizeof(plaintext) - 1;

        /* Pre-computed SHA-256 of `plaintext` is required; the builder
         * embeds it as image-digest. We let the builder skip verifying it
         * by handing it any 32 bytes — validator does not recompute. */
        uint8_t fake_digest[32];
        for (size_t i = 0; i < sizeof(fake_digest); i++)
            fake_digest[i] = static_cast<uint8_t>(i);

        sumo::CoseKey signing_key = sumo::CoseKey::FromCoseKeyBytes(
            {kHmac256CoseKey, sizeof(kHmac256CoseKey)});

        envelope_ = sumo::ImageManifestBuilder()
            .SetComponentId({"ecu-a", "firmware"})
            .SetSequenceNumber(1)
            .SetVendorId(kVendorA)
            .SetClassId(kClassA)
            .SetPayloadDigest(fake_digest, sizeof(fake_digest), pt_len)
            .SetPayloadUri("file:///tmp/fixture.bin")
            .Build(signing_key);

        ASSERT_FALSE(envelope_.empty());
    }
};

TEST_F(DeviceIdTest, MatchingVendorAndClassPasses) {
    sumo_device_id_t dev = {};
    memcpy(dev.vendor_id, kVendorA.bytes, 16);
    memcpy(dev.class_id, kClassA.bytes, 16);

    auto *v = sumo_validator_create(
        kHmac256CoseKey, sizeof(kHmac256CoseKey), &dev);
    ASSERT_NE(v, nullptr);

    sumo_manifest_t *m = nullptr;
    int rc = sumo_validate_envelope(
        v, envelope_.data(), envelope_.size(), 0, &m);
    EXPECT_EQ(rc, SUMO_OK);
    EXPECT_NE(m, nullptr);

    sumo_manifest_free(m);
    sumo_validator_free(v);
}

TEST_F(DeviceIdTest, WrongVendorRejected) {
    sumo_device_id_t dev = {};
    memcpy(dev.vendor_id, kVendorB.bytes, 16);   /* mismatch */
    memcpy(dev.class_id,  kClassA.bytes,  16);

    auto *v = sumo_validator_create(
        kHmac256CoseKey, sizeof(kHmac256CoseKey), &dev);
    ASSERT_NE(v, nullptr);

    sumo_manifest_t *m = nullptr;
    int rc = sumo_validate_envelope(
        v, envelope_.data(), envelope_.size(), 0, &m);
    EXPECT_EQ(rc, SUMO_ERR_VENDOR_MISMATCH);
    EXPECT_EQ(m, nullptr);

    sumo_validator_free(v);
}

TEST_F(DeviceIdTest, WrongClassRejected) {
    sumo_device_id_t dev = {};
    memcpy(dev.vendor_id, kVendorA.bytes, 16);
    memcpy(dev.class_id,  kClassB.bytes,  16);   /* mismatch */

    auto *v = sumo_validator_create(
        kHmac256CoseKey, sizeof(kHmac256CoseKey), &dev);
    ASSERT_NE(v, nullptr);

    sumo_manifest_t *m = nullptr;
    int rc = sumo_validate_envelope(
        v, envelope_.data(), envelope_.size(), 0, &m);
    EXPECT_EQ(rc, SUMO_ERR_CLASS_MISMATCH);
    EXPECT_EQ(m, nullptr);

    sumo_validator_free(v);
}

TEST(DeviceIdMismatch, MatchingDeviceIdPasses) {
    sumo_device_id_t dev = {};
    memcpy(dev.vendor_id, kEmbeddedVendor, 16);
    memcpy(dev.class_id,  kEmbeddedClass,  16);
    memcpy(dev.device_id, kEmbeddedDevice, 16);

    auto *v = sumo_validator_create(kSignPub, sizeof(kSignPub), &dev);
    ASSERT_NE(v, nullptr);

    sumo_manifest_t *m = nullptr;
    int rc = sumo_validate_envelope(v, kEnvelopeWithDeviceId,
                                    sizeof(kEnvelopeWithDeviceId), 0, &m);
    EXPECT_EQ(rc, SUMO_OK);
    EXPECT_NE(m, nullptr);

    sumo_manifest_free(m);
    sumo_validator_free(v);
}

TEST(DeviceIdMismatch, WrongDeviceUuidRejected) {
    sumo_device_id_t dev = {};
    memcpy(dev.vendor_id, kEmbeddedVendor, 16);
    memcpy(dev.class_id,  kEmbeddedClass,  16);
    /* Right vendor + class, but a totally different device id. */
    for (size_t i = 0; i < 16; i++) dev.device_id[i] = 0xFF;

    auto *v = sumo_validator_create(kSignPub, sizeof(kSignPub), &dev);
    ASSERT_NE(v, nullptr);

    sumo_manifest_t *m = nullptr;
    int rc = sumo_validate_envelope(v, kEnvelopeWithDeviceId,
                                    sizeof(kEnvelopeWithDeviceId), 0, &m);
    EXPECT_EQ(rc, SUMO_ERR_DEVICE_MISMATCH);
    EXPECT_EQ(m, nullptr);

    sumo_validator_free(v);
}

TEST(DeviceIdMismatch, NilDeviceIdFieldOptsOutOfDeviceCheck) {
    /* Vendor + class set, device_id field left as nil → device check is
     * skipped per the per-field opt-in convention, even though the
     * manifest declares a device-id condition. */
    sumo_device_id_t dev = {};
    memcpy(dev.vendor_id, kEmbeddedVendor, 16);
    memcpy(dev.class_id,  kEmbeddedClass,  16);
    /* dev.device_id stays all-zero (nil UUID). */

    auto *v = sumo_validator_create(kSignPub, sizeof(kSignPub), &dev);
    ASSERT_NE(v, nullptr);

    sumo_manifest_t *m = nullptr;
    int rc = sumo_validate_envelope(v, kEnvelopeWithDeviceId,
                                    sizeof(kEnvelopeWithDeviceId), 0, &m);
    EXPECT_EQ(rc, SUMO_OK);
    EXPECT_NE(m, nullptr);

    sumo_manifest_free(m);
    sumo_validator_free(v);
}

TEST_F(DeviceIdTest, NullDeviceIdSkipsCheck) {
    /* Back-compat: validator created with NULL device_id never enforces
     * UUID conditions, even when the manifest declares them. */
    auto *v = sumo_validator_create(
        kHmac256CoseKey, sizeof(kHmac256CoseKey), nullptr);
    ASSERT_NE(v, nullptr);

    sumo_manifest_t *m = nullptr;
    int rc = sumo_validate_envelope(
        v, envelope_.data(), envelope_.size(), 0, &m);
    EXPECT_EQ(rc, SUMO_OK);
    EXPECT_NE(m, nullptr);

    sumo_manifest_free(m);
    sumo_validator_free(v);
}
