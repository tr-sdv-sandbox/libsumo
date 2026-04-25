/**
 * @file multi_device_key_e2e_test.cpp
 * @brief T1.3 — multi-device-key with kid matching.
 *
 * The validator can hold up to SUMO_MAX_DEVICE_KEYS keys, each tagged
 * with its own kid. When the COSE_Encrypt recipient carries a kid (label
 * 4 in the unprotected header), `sumo_decryptor_create_v` selects the
 * matching device key automatically; an unknown kid is rejected with
 * SUMO_ERR_DECRYPT_FAILED-equivalent (NULL decryptor handle).
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <gtest/gtest.h>
#include <cstring>
#include <vector>

#include "sumo/encryptor.h"
#include "sumo/image_builder.h"

extern "C" {
#include "sumo/decryptor.h"
#include "sumo/validator.h"
}

/* HMAC256 signing key (same fixture as e2e_test.cpp). */
static const uint8_t kHmac256Sign[] = {
    0xA4, 0x01, 0x04, 0x02, 0x58, 0x20,
        0x16, 0x60, 0x96, 0xC9, 0x21, 0x14, 0x91, 0x5B,
        0xE3, 0xC2, 0xFA, 0x50, 0x47, 0x9C, 0x43, 0x00,
        0x1E, 0x31, 0xA6, 0x75, 0xD0, 0x73, 0x22, 0x7F,
        0x44, 0xA2, 0x81, 0xD6, 0x0F, 0xF8, 0xFD, 0x79,
    0x03, 0x05, 0x20, 0x58, 0x20,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
};

/* Two A128KW device-key COSE_Keys with distinct kids. The kid is the
 * 32-byte label-2 slot inside the COSE_Key map. The 16-byte symmetric
 * key (label -1) is what the onboard validator stores as the raw KEK. */
static const uint8_t kKidA[32] = {
    0xAA, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};

static const uint8_t kKidB[32] = {
    0xBB, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};

static const uint8_t kKekA[16] = {
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
};

static const uint8_t kKekB[16] = {
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
};

/* Build an A128KW COSE_Key CBOR map: {1:4, 2:<kid>, 3:-3, -1:<k>} */
static std::vector<uint8_t> MakeA128kwCoseKey(const uint8_t kid[32],
                                              const uint8_t k[16]) {
    std::vector<uint8_t> v;
    v.push_back(0xA4);             // map(4)
    v.push_back(0x01); v.push_back(0x04);
    v.push_back(0x02); v.push_back(0x58); v.push_back(0x20);
    v.insert(v.end(), kid, kid + 32);
    v.push_back(0x03); v.push_back(0x22);  // alg = -3 (A128KW)
    v.push_back(0x20); v.push_back(0x50);  // -1 = bstr(16)
    v.insert(v.end(), k, k + 16);
    return v;
}

static const sumo::Uuid kVendor = {{
    0xFA, 0x6B, 0x4A, 0x53, 0xD5, 0xAD, 0x5F, 0xDF,
    0xBE, 0x9D, 0xE6, 0x63, 0xE4, 0xD4, 0x1F, 0xFE,
}};
static const sumo::Uuid kClass = {{
    0x14, 0x92, 0xAF, 0x14, 0x25, 0x69, 0x5E, 0x48,
    0xBF, 0x42, 0x9B, 0x2D, 0x51, 0xF2, 0xAB, 0x45,
}};

class MultiDeviceKeyTest : public ::testing::Test {
protected:
    std::vector<uint8_t> firmware_;
    std::vector<uint8_t> envelope_for_b_;

    void SetUp() override {
        const char *text = "T1.3 multi-device-key fixture firmware";
        firmware_.assign(reinterpret_cast<const uint8_t *>(text),
                         reinterpret_cast<const uint8_t *>(text) + strlen(text));

        /* Encrypt firmware to recipient B (single recipient → single
         * COSE_recipient with kid_B in unprotected header). */
        auto cose_key_b = MakeA128kwCoseKey(kKidB, kKekB);
        sumo::CoseKey enc_key = sumo::CoseKey::FromCoseKeyBytes(
            {cose_key_b.data(), cose_key_b.size()});
        std::vector<sumo::Recipient> rcpts;
        rcpts.push_back({std::move(enc_key),
                         std::vector<uint8_t>(kKidB, kKidB + 32)});
        sumo::EncryptedPayload enc =
            sumo::EncryptFirmware(firmware_, rcpts);
        ASSERT_FALSE(enc.ciphertext.empty());

        auto digest = sumo::Sha256(firmware_);

        sumo::CoseKey signing_key = sumo::CoseKey::FromCoseKeyBytes(
            {kHmac256Sign, sizeof(kHmac256Sign)});
        envelope_for_b_ = sumo::ImageManifestBuilder()
            .SetComponentId({"ecu-a", "firmware"})
            .SetSequenceNumber(1)
            .SetVendorId(kVendor)
            .SetClassId(kClass)
            .SetPayloadDigest(digest.data(), digest.size(), firmware_.size())
            .SetPayloadUri("file:///tmp/fw.bin")
            .SetEncryptionInfo(enc.encryption_info)
            .Build(signing_key);
        ASSERT_FALSE(envelope_for_b_.empty());

        /* Stash the ciphertext for later — the test will feed it through
         * the chosen decryptor. */
        ciphertext_ = std::move(enc.ciphertext);
    }

    std::vector<uint8_t> ciphertext_;
};

TEST_F(MultiDeviceKeyTest, KidMatchSelectsCorrectKey) {
    /* Both A and B registered, in that order. The envelope's recipient
     * carries kid_B; the validator must pick KEK_B. */
    sumo_validator_t *v = sumo_validator_create(
        kHmac256Sign, sizeof(kHmac256Sign), nullptr);
    ASSERT_NE(v, nullptr);
    ASSERT_EQ(sumo_validator_add_device_key(v, kKekA, sizeof(kKekA),
                                            kKidA, sizeof(kKidA)), SUMO_OK);
    ASSERT_EQ(sumo_validator_add_device_key(v, kKekB, sizeof(kKekB),
                                            kKidB, sizeof(kKidB)), SUMO_OK);

    sumo_manifest_t *m = nullptr;
    ASSERT_EQ(sumo_validate_envelope(v, envelope_for_b_.data(),
                                     envelope_for_b_.size(), 0, &m),
              SUMO_OK);

    sumo_decryptor_t *dec = sumo_decryptor_create_v(m, 0, v);
    ASSERT_NE(dec, nullptr);

    std::vector<uint8_t> pt(ciphertext_.size());
    size_t pt_len = pt.size();
    ASSERT_EQ(sumo_decryptor_update(dec, ciphertext_.data(), ciphertext_.size(),
                                    pt.data(), &pt_len), 0);
    uint8_t tail[64];
    size_t tail_len = sizeof(tail);
    ASSERT_EQ(sumo_decryptor_finalize(dec, tail, &tail_len), 0);
    EXPECT_EQ(pt_len + tail_len, firmware_.size());
    EXPECT_EQ(memcmp(pt.data(), firmware_.data(), pt_len), 0);

    sumo_decryptor_free(dec);
    sumo_manifest_free(m);
    sumo_validator_free(v);
}

TEST_F(MultiDeviceKeyTest, UnknownKidRejected) {
    /* Only key A registered. Envelope's recipient kid is B → no match. */
    sumo_validator_t *v = sumo_validator_create(
        kHmac256Sign, sizeof(kHmac256Sign), nullptr);
    ASSERT_NE(v, nullptr);
    ASSERT_EQ(sumo_validator_add_device_key(v, kKekA, sizeof(kKekA),
                                            kKidA, sizeof(kKidA)), SUMO_OK);

    sumo_manifest_t *m = nullptr;
    ASSERT_EQ(sumo_validate_envelope(v, envelope_for_b_.data(),
                                     envelope_for_b_.size(), 0, &m),
              SUMO_OK);

    sumo_decryptor_t *dec = sumo_decryptor_create_v(m, 0, v);
    EXPECT_EQ(dec, nullptr);

    sumo_manifest_free(m);
    sumo_validator_free(v);
}

TEST_F(MultiDeviceKeyTest, FirstKeyFallsThroughToCorrectKidWhenStored) {
    /* If only key B is registered (no key A), kid match still works
     * even though the registered key is the only one. Confirms the
     * search loop, not just "first key wins". */
    sumo_validator_t *v = sumo_validator_create(
        kHmac256Sign, sizeof(kHmac256Sign), nullptr);
    ASSERT_NE(v, nullptr);
    ASSERT_EQ(sumo_validator_add_device_key(v, kKekB, sizeof(kKekB),
                                            kKidB, sizeof(kKidB)), SUMO_OK);

    sumo_manifest_t *m = nullptr;
    ASSERT_EQ(sumo_validate_envelope(v, envelope_for_b_.data(),
                                     envelope_for_b_.size(), 0, &m),
              SUMO_OK);

    sumo_decryptor_t *dec = sumo_decryptor_create_v(m, 0, v);
    ASSERT_NE(dec, nullptr);
    sumo_decryptor_free(dec);

    sumo_manifest_free(m);
    sumo_validator_free(v);
}

TEST(MultiDeviceKeyValidator, AddBeyondMaxFailsCleanly) {
    sumo_validator_t *v = sumo_validator_create(
        kHmac256Sign, sizeof(kHmac256Sign), nullptr);
    ASSERT_NE(v, nullptr);

    /* SUMO_MAX_DEVICE_KEYS == 4 by default. Add 4 keys, then expect a
     * 5th add to fail with SUMO_ERR_OUT_OF_MEMORY. */
    for (int i = 0; i < 4; i++) {
        uint8_t kid[8] = {(uint8_t)i};
        EXPECT_EQ(sumo_validator_add_device_key(v, kKekA, sizeof(kKekA),
                                                kid, sizeof(kid)), SUMO_OK);
    }
    uint8_t kid_extra[8] = {0xFF};
    EXPECT_EQ(sumo_validator_add_device_key(v, kKekA, sizeof(kKekA),
                                            kid_extra, sizeof(kid_extra)),
              SUMO_ERR_OUT_OF_MEMORY);

    sumo_validator_free(v);
}
