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
