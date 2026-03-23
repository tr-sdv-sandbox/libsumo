/**
 * @file e2e_test_helpers.h
 * @brief Shared test helpers: key material, fake platform/storage ops.
 */
#ifndef E2E_TEST_HELPERS_H
#define E2E_TEST_HELPERS_H

#include <cstring>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "sum2/image_builder.h"
#include "sum2/encryptor.h"
#include "sum2/validator.h"
#include "sum2/decryptor.h"
#include "sum2/decompressor.h"
#include "sum2/orchestrator.h"
#include "sum2/policy.h"

/* ===== Shared key material (from libcsuit examples) ===== */

/* HMAC256 COSE_Key: alg=5, k=32 bytes of 0x61 ("aaa...") */
static const uint8_t kHmacCoseKey[] = {
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
static const uint8_t kA128kwCoseKey[] = {
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

/* Raw KEK (16 bytes of 0x61) */
static const uint8_t kRawKek[16] = {
    0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
    0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
};

/* ECDH-ES+A128KW P-256 sender key */
static const uint8_t kEcdhSenderKey[] = {
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

/* ECDH device private key (for decryption) */
static const uint8_t kEcdhDeviceKeyPrivate[] = {
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

/* ECDH device public key (for encryption) */
static const uint8_t kEcdhDeviceKeyPublic[] = {
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
static const sum2::Uuid kTestVendor = {{
    0xFA, 0x6B, 0x4A, 0x53, 0xD5, 0xAD, 0x5F, 0xDF,
    0xBE, 0x9D, 0xE6, 0x63, 0xE4, 0xD4, 0x1F, 0xFE
}};

static const sum2::Uuid kTestClass = {{
    0x14, 0x92, 0xAF, 0x14, 0x25, 0x69, 0x5E, 0x48,
    0xBF, 0x42, 0x9B, 0x2D, 0x51, 0xF2, 0xAB, 0x45
}};

/* ===== Fake Platform Ops ===== */

struct FakePlatformOps {
    /* URI → data store for fetch() */
    std::map<std::string, std::vector<uint8_t>> fetch_store;

    /* Per-component accumulated write data */
    std::map<std::string, std::vector<uint8_t>> written;

    /* Recorded invoke/swap calls */
    std::vector<std::string> invoked;
    std::vector<std::pair<std::string, std::string>> swapped;

    /* Recorded persist_sequence calls: component_key → sequence */
    std::map<std::string, uint64_t> persisted_seqs;

    /* Failure injection: set to N to fail on Nth call (1-based, 0 = never) */
    int fetch_fail_on = 0;
    int write_fail_on = 0;

    int fetch_call_count = 0;
    int write_call_count = 0;

    sum2_platform_ops_t ops() {
        sum2_platform_ops_t o = {};
        o.fetch = &s_fetch;
        o.write = &s_write;
        o.invoke = &s_invoke;
        o.swap = &s_swap;
        o.persist_sequence = &s_persist_sequence;
        o.user_ctx = this;
        return o;
    }

private:
    static std::string key_from_bytes(const uint8_t *data, size_t len) {
        return std::string(reinterpret_cast<const char *>(data), len);
    }

    static int s_fetch(const char *uri, size_t uri_len,
                       uint8_t *buf, size_t buf_size, size_t *fetched,
                       void *ctx) {
        auto *self = static_cast<FakePlatformOps *>(ctx);
        self->fetch_call_count++;
        if (self->fetch_fail_on > 0 &&
            self->fetch_call_count >= self->fetch_fail_on)
            return -1;

        std::string key(uri, uri_len);
        auto it = self->fetch_store.find(key);
        if (it == self->fetch_store.end()) return -1;

        if (it->second.size() > buf_size) return -1;
        memcpy(buf, it->second.data(), it->second.size());
        *fetched = it->second.size();
        return 0;
    }

    static int s_write(const uint8_t *component_id, size_t cid_len,
                       size_t /*offset*/,
                       const uint8_t *data, size_t data_len,
                       void *ctx) {
        auto *self = static_cast<FakePlatformOps *>(ctx);
        self->write_call_count++;
        if (self->write_fail_on > 0 &&
            self->write_call_count >= self->write_fail_on)
            return -1;

        auto key = key_from_bytes(component_id, cid_len);
        self->written[key].insert(
            self->written[key].end(), data, data + data_len);
        return 0;
    }

    static int s_invoke(const uint8_t *component_id, size_t cid_len,
                        void *ctx) {
        auto *self = static_cast<FakePlatformOps *>(ctx);
        self->invoked.push_back(key_from_bytes(component_id, cid_len));
        return 0;
    }

    static int s_swap(const uint8_t *comp_a, size_t a_len,
                      const uint8_t *comp_b, size_t b_len,
                      void *ctx) {
        auto *self = static_cast<FakePlatformOps *>(ctx);
        self->swapped.push_back({
            key_from_bytes(comp_a, a_len),
            key_from_bytes(comp_b, b_len)
        });
        return 0;
    }

    static int s_persist_sequence(const uint8_t *component_id, size_t cid_len,
                                  uint64_t seq, void *ctx) {
        auto *self = static_cast<FakePlatformOps *>(ctx);
        self->persisted_seqs[key_from_bytes(component_id, cid_len)] = seq;
        return 0;
    }
};

/* ===== Fake Storage Ops ===== */

struct FakeStorageOps {
    std::map<std::string, uint64_t> u64_store;
    std::map<std::string, int64_t>  i64_store;

    /* Failure injection */
    bool fail_reads = false;
    bool fail_writes = false;

    sum2_storage_ops_t ops() {
        sum2_storage_ops_t o = {};
        o.read_u64 = &s_read_u64;
        o.write_u64 = &s_write_u64;
        o.read_i64 = &s_read_i64;
        o.write_i64 = &s_write_i64;
        o.ctx = this;
        return o;
    }

private:
    static int s_read_u64(const char *key, uint64_t *value, void *ctx) {
        auto *self = static_cast<FakeStorageOps *>(ctx);
        if (self->fail_reads) return -1;
        auto it = self->u64_store.find(key);
        if (it == self->u64_store.end()) return -1;
        *value = it->second;
        return 0;
    }

    static int s_write_u64(const char *key, uint64_t value, void *ctx) {
        auto *self = static_cast<FakeStorageOps *>(ctx);
        if (self->fail_writes) return -1;
        self->u64_store[key] = value;
        return 0;
    }

    static int s_read_i64(const char *key, int64_t *value, void *ctx) {
        auto *self = static_cast<FakeStorageOps *>(ctx);
        if (self->fail_reads) return -1;
        auto it = self->i64_store.find(key);
        if (it == self->i64_store.end()) return -1;
        *value = it->second;
        return 0;
    }

    static int s_write_i64(const char *key, int64_t value, void *ctx) {
        auto *self = static_cast<FakeStorageOps *>(ctx);
        if (self->fail_writes) return -1;
        self->i64_store[key] = value;
        return 0;
    }
};

/* ===== Helper: Build a test image manifest + encrypted payload ===== */

struct TestImage {
    std::vector<uint8_t> envelope;          /* Signed SUIT_Envelope */
    std::vector<uint8_t> ciphertext;        /* Encrypted firmware */
    std::vector<uint8_t> plaintext;         /* Original firmware */
    std::string payload_uri;
    uint64_t sequence_number;
};

/**
 * Build a complete L2 image: compress (optional) → encrypt → build manifest.
 * Signs with HMAC256 key for simplicity.
 */
inline TestImage BuildTestImage(
    std::vector<uint8_t> firmware,
    std::vector<std::string> component_id,
    uint64_t seq,
    std::string uri,
    bool compress = false)
{
    TestImage result;
    result.plaintext = firmware;
    result.payload_uri = uri;
    result.sequence_number = seq;

    std::vector<uint8_t> to_encrypt = firmware;
    if (compress) {
        to_encrypt = sum2::CompressFirmware(firmware);
    }

    sum2::CoseKey enc_key = sum2::CoseKey::FromCoseKeyBytes(
        {kA128kwCoseKey, sizeof(kA128kwCoseKey)});
    std::vector<sum2::Recipient> recipients;
    recipients.push_back({std::move(enc_key), {}});

    auto encrypted = sum2::EncryptFirmware(to_encrypt, recipients);
    result.ciphertext = encrypted.ciphertext;

    auto digest = sum2::Sha256(firmware);

    sum2::CoseKey signing_key = sum2::CoseKey::FromCoseKeyBytes(
        {kHmacCoseKey, sizeof(kHmacCoseKey)});

    result.envelope = sum2::ImageManifestBuilder()
        .SetComponentId(component_id)
        .SetSequenceNumber(seq)
        .SetVendorId(kTestVendor)
        .SetClassId(kTestClass)
        .SetPayloadDigest(digest.data(), digest.size(), firmware.size())
        .SetPayloadUri(uri)
        .SetEncryptionInfo(encrypted.encryption_info)
        .Build(signing_key);

    return result;
}

/**
 * Create a validator configured with our test keys.
 */
inline sum2_validator_t *CreateTestValidator() {
    sum2_device_id_t device_id = {};
    memcpy(device_id.vendor_id, kTestVendor.bytes, 16);
    memcpy(device_id.class_id, kTestClass.bytes, 16);

    sum2_validator_t *v = sum2_validator_create(
        kHmacCoseKey, sizeof(kHmacCoseKey), &device_id);
    if (v) {
        sum2_validator_add_device_key(v,
            kRawKek, sizeof(kRawKek), nullptr, 0);
    }
    return v;
}

#endif /* E2E_TEST_HELPERS_H */
