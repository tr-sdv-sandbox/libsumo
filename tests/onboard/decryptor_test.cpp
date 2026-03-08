/**
 * @file decryptor_test.cpp
 * @brief Unit tests for streaming AES-GCM decryption (onboard C API).
 *
 * Tests both:
 *   - Low-level AES-128-GCM encrypt/decrypt round-trips (OpenSSL EVP)
 *   - Full COSE_Encrypt → CEK unwrap → streaming decrypt via sum2_decryptor
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <gtest/gtest.h>
#include <cstring>
#include <vector>
#include <numeric>

extern "C" {
#include "sum2/decryptor.h"
#include "sum2/validator.h"

/*
 * Helper defined in decryptor_test_helper.c — decodes a SUIT envelope
 * with Mac0 authentication (for expAW test vector) and returns an
 * opaque sum2_manifest_t* that the decryptor can use.
 */
sum2_manifest_t *test_decode_mac0_envelope(
    const uint8_t *envelope, size_t envelope_len,
    const uint8_t *hmac_key, size_t hmac_key_len);
}

#include <openssl/evp.h>
#include <openssl/rand.h>

static const char *kTestFilesDir = LIBCSUIT_TESTFILES "/";

/* Helper: read binary file into vector */
static std::vector<uint8_t> ReadFile(const std::string &path) {
    FILE *f = fopen(path.c_str(), "rb");
    if (!f) return {};
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> buf(sz);
    if (sz > 0) {
        size_t n = fread(buf.data(), 1, sz, f);
        buf.resize(n);
    }
    fclose(f);
    return buf;
}

/* Helper: encrypt with AES-128-GCM using OpenSSL, return {ciphertext || tag} */
struct GCMResult {
    std::vector<uint8_t> ciphertext;  /* ciphertext + 16-byte tag appended */
    uint8_t iv[12];
    uint8_t key[16];
};

static GCMResult AES128GCM_Encrypt(const std::vector<uint8_t> &plaintext,
                                    const uint8_t key[16],
                                    const uint8_t iv[12]) {
    GCMResult r;
    memcpy(r.key, key, 16);
    memcpy(r.iv, iv, 12);
    r.ciphertext.resize(plaintext.size() + 16); /* ct + tag */

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EXPECT_NE(ctx, nullptr);

    EXPECT_EQ(EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr), 1);
    EXPECT_EQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr), 1);
    EXPECT_EQ(EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv), 1);

    int outl = 0;
    EXPECT_EQ(EVP_EncryptUpdate(ctx, r.ciphertext.data(), &outl,
                                 plaintext.data(), (int)plaintext.size()), 1);
    EXPECT_EQ((size_t)outl, plaintext.size());

    int finl = 0;
    EXPECT_EQ(EVP_EncryptFinal_ex(ctx, r.ciphertext.data() + outl, &finl), 1);

    /* Append GCM tag */
    EXPECT_EQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16,
                                    r.ciphertext.data() + plaintext.size()), 1);

    EVP_CIPHER_CTX_free(ctx);
    return r;
}

// ============================================================================
// Basic OpenSSL AES-GCM Round-Trip (sanity check)
// ============================================================================

TEST(DecryptorTest, BasicRoundTrip) {
    uint8_t key[16] = {0};
    uint8_t iv[12] = {0};
    for (int i = 0; i < 16; i++) key[i] = (uint8_t)i;
    for (int i = 0; i < 12; i++) iv[i] = (uint8_t)(i + 16);

    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};  // "Hello"
    auto enc = AES128GCM_Encrypt(plaintext, key, iv);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    ASSERT_NE(ctx, nullptr);
    ASSERT_EQ(EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr), 1);
    ASSERT_EQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr), 1);
    ASSERT_EQ(EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv), 1);

    /* ciphertext is plaintext_len bytes; tag is the last 16 */
    std::vector<uint8_t> decrypted(plaintext.size() + 16);
    int outl = 0;
    ASSERT_EQ(EVP_DecryptUpdate(ctx, decrypted.data(), &outl,
                                 enc.ciphertext.data(),
                                 (int)plaintext.size()), 1);
    decrypted.resize(outl);

    ASSERT_EQ(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                    (void *)(enc.ciphertext.data() + plaintext.size())), 1);
    int finl = 0;
    ASSERT_EQ(EVP_DecryptFinal_ex(ctx, decrypted.data() + outl, &finl), 1);
    decrypted.resize(outl + finl);

    EVP_CIPHER_CTX_free(ctx);

    EXPECT_EQ(decrypted, plaintext);
}

// ============================================================================
// Tampered Ciphertext Detection
// ============================================================================

TEST(DecryptorTest, TamperedCiphertextDetected) {
    uint8_t key[16], iv[12];
    memset(key, 0xAA, 16);
    memset(iv, 0xBB, 12);

    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    auto enc = AES128GCM_Encrypt(plaintext, key, iv);

    enc.ciphertext[0] ^= 0xFF;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    ASSERT_NE(ctx, nullptr);
    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv);

    std::vector<uint8_t> buf(enc.ciphertext.size() + 16);
    int outl = 0;
    EVP_DecryptUpdate(ctx, buf.data(), &outl,
                       enc.ciphertext.data(), (int)plaintext.size());

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                         (void *)(enc.ciphertext.data() + plaintext.size()));
    int finl = 0;
    int rc = EVP_DecryptFinal_ex(ctx, buf.data() + outl, &finl);
    EXPECT_NE(rc, 1) << "Tampered ciphertext should fail GCM auth";

    EVP_CIPHER_CTX_free(ctx);
}

// ============================================================================
// Tampered Tag Detection
// ============================================================================

TEST(DecryptorTest, TamperedTagDetected) {
    uint8_t key[16], iv[12];
    memset(key, 0xAA, 16);
    memset(iv, 0xBB, 12);

    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    auto enc = AES128GCM_Encrypt(plaintext, key, iv);

    /* Tamper with tag (last 16 bytes) */
    enc.ciphertext[plaintext.size()] ^= 0xFF;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    ASSERT_NE(ctx, nullptr);
    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv);

    std::vector<uint8_t> buf(enc.ciphertext.size() + 16);
    int outl = 0;
    EVP_DecryptUpdate(ctx, buf.data(), &outl,
                       enc.ciphertext.data(), (int)plaintext.size());

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                         (void *)(enc.ciphertext.data() + plaintext.size()));
    int finl = 0;
    int rc = EVP_DecryptFinal_ex(ctx, buf.data() + outl, &finl);
    EXPECT_NE(rc, 1) << "Tampered tag should fail GCM auth";

    EVP_CIPHER_CTX_free(ctx);
}

// ============================================================================
// Ciphertext Size Preservation
// ============================================================================

TEST(DecryptorTest, CiphertextSameSize) {
    uint8_t key[16], iv[12];
    memset(key, 0xAA, 16);
    memset(iv, 0xBB, 12);

    std::vector<uint8_t> plaintext = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
    auto enc = AES128GCM_Encrypt(plaintext, key, iv);

    /* ct + tag = plaintext + 16 */
    EXPECT_EQ(enc.ciphertext.size(), plaintext.size() + 16);
}

// ============================================================================
// Full SUIT Decryptor: A128KW CEK unwrap + AES-GCM streaming decrypt
// using the expAW test vector (COSE_Mac0 auth, A128KW encryption)
// ============================================================================

/* HMAC256 COSE_Key for the expAW test vector Mac0 authentication.
 * From libcsuit examples/inc/trust_anchor_hmac256_cose_key_secret.h */
static const uint8_t kHmacCoseKey[] = {
    0xA4,
       0x01, 0x04,                    /* kty: 4 (Symmetric) */
       0x02, 0x58, 0x20,              /* kid: 32 bytes */
          0x16, 0x60, 0x96, 0xC9, 0x21, 0x14, 0x91, 0x5B,
          0xE3, 0xC2, 0xFA, 0x50, 0x47, 0x9C, 0x43, 0x00,
          0x1E, 0x31, 0xA6, 0x75, 0xD0, 0x73, 0x22, 0x7F,
          0x44, 0xA2, 0x81, 0xD6, 0x0F, 0xF8, 0xFD, 0x79,
       0x03, 0x05,                    /* alg: 5 (HMAC-SHA256) */
       0x20, 0x58, 0x20,              /* k: 32 bytes */
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
          0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
};

class SuitDecryptorTest : public ::testing::Test {
protected:
    void SetUp() override {
        envelope_ = ReadFile(std::string(kTestFilesDir) +
                             "suit_manifest_expAW.suit");
        if (envelope_.empty()) return;

        /* Decode via C helper (avoids C++ keyword conflict in suit_common.h) */
        manifest_ = test_decode_mac0_envelope(
            envelope_.data(), envelope_.size(),
            kHmacCoseKey, sizeof(kHmacCoseKey));
    }

    void TearDown() override {
        if (manifest_) sum2_manifest_free(manifest_);
    }

    sum2_manifest_t *manifest_ = nullptr;
    std::vector<uint8_t> envelope_;
};

TEST_F(SuitDecryptorTest, DecodeExpAW) {
    if (envelope_.empty()) GTEST_SKIP() << "expAW test file not available";
    ASSERT_NE(manifest_, nullptr) << "Failed to decode expAW envelope";
    EXPECT_EQ(sum2_manifest_sequence_number(manifest_), 1u);
}

TEST_F(SuitDecryptorTest, CreateDecryptor) {
    if (envelope_.empty()) GTEST_SKIP() << "expAW test file not available";
    ASSERT_NE(manifest_, nullptr);

    /* KEK for A128KW: "aaaaaaaaaaaaaaaa" */
    const uint8_t kek[] = {
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61
    };

    sum2_decryptor_t *d = sum2_decryptor_create(
        manifest_, 0, kek, sizeof(kek));
    ASSERT_NE(d, nullptr)
        << "Failed to create decryptor — CEK unwrap or COSE_Encrypt parsing failed";

    sum2_decryptor_free(d);
}

TEST_F(SuitDecryptorTest, DecryptContent) {
    if (envelope_.empty()) GTEST_SKIP() << "expAW test file not available";
    ASSERT_NE(manifest_, nullptr);

    const uint8_t kek[] = {
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61
    };

    sum2_decryptor_t *d = sum2_decryptor_create(
        manifest_, 0, kek, sizeof(kek));
    ASSERT_NE(d, nullptr);

    /* The encrypted content from expAW (parameter-content, label 18).
     * This is 46 bytes: 30 bytes ciphertext + 16 bytes GCM tag. */
    const uint8_t encrypted_content[] = {
        0x75, 0x8C, 0x4B, 0x7B, 0xBA, 0xE2, 0xC4, 0xC1,
        0xD4, 0x62, 0x42, 0x3E, 0x0F, 0x0D, 0xC3, 0x16,
        0x4F, 0xFA, 0x7B, 0x85, 0xBB, 0x94, 0xD4, 0xBD,
        0x6D, 0x7E, 0xD2, 0x6A, 0xB3, 0x2F, 0xEB, 0x06,
        0x33, 0x85, 0xD4, 0xD3, 0x46, 0x59, 0x27, 0xEC,
        0x82, 0xCB, 0x5E, 0x19, 0x8A, 0x59
    };

    /* Decrypt in one shot */
    uint8_t pt[64];
    size_t pt_len;
    int rc = sum2_decryptor_update(d, encrypted_content,
                                    sizeof(encrypted_content),
                                    pt, &pt_len);
    ASSERT_EQ(rc, 0) << "decryptor_update failed";

    uint8_t fin_buf[16];
    size_t fin_len;
    rc = sum2_decryptor_finalize(d, fin_buf, &fin_len);
    ASSERT_EQ(rc, 0) << "decryptor_finalize failed — GCM tag mismatch?";

    /* Combine plaintext */
    size_t total = pt_len + fin_len;
    EXPECT_EQ(total, 30u) << "Expected 30 bytes of plaintext";

    /* The plaintext should be meaningful firmware content */
    EXPECT_GT(total, 0u);

    sum2_decryptor_free(d);
}

TEST_F(SuitDecryptorTest, StreamingChunkedDecrypt) {
    if (envelope_.empty()) GTEST_SKIP() << "expAW test file not available";
    ASSERT_NE(manifest_, nullptr);

    const uint8_t kek[] = {
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
        0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61
    };

    sum2_decryptor_t *d = sum2_decryptor_create(
        manifest_, 0, kek, sizeof(kek));
    ASSERT_NE(d, nullptr);

    const uint8_t encrypted_content[] = {
        0x75, 0x8C, 0x4B, 0x7B, 0xBA, 0xE2, 0xC4, 0xC1,
        0xD4, 0x62, 0x42, 0x3E, 0x0F, 0x0D, 0xC3, 0x16,
        0x4F, 0xFA, 0x7B, 0x85, 0xBB, 0x94, 0xD4, 0xBD,
        0x6D, 0x7E, 0xD2, 0x6A, 0xB3, 0x2F, 0xEB, 0x06,
        0x33, 0x85, 0xD4, 0xD3, 0x46, 0x59, 0x27, 0xEC,
        0x82, 0xCB, 0x5E, 0x19, 0x8A, 0x59
    };

    /* Decrypt in small chunks (10 bytes at a time) */
    std::vector<uint8_t> plaintext;
    uint8_t pt_buf[64];
    size_t chunk_size = 10;

    for (size_t off = 0; off < sizeof(encrypted_content); off += chunk_size) {
        size_t sz = std::min(chunk_size, sizeof(encrypted_content) - off);
        size_t pt_len;
        int rc = sum2_decryptor_update(d, encrypted_content + off, sz,
                                        pt_buf, &pt_len);
        ASSERT_EQ(rc, 0) << "decryptor_update failed at offset " << off;
        plaintext.insert(plaintext.end(), pt_buf, pt_buf + pt_len);
    }

    size_t fin_len;
    int rc = sum2_decryptor_finalize(d, pt_buf, &fin_len);
    ASSERT_EQ(rc, 0) << "decryptor_finalize failed";
    plaintext.insert(plaintext.end(), pt_buf, pt_buf + fin_len);

    EXPECT_EQ(plaintext.size(), 30u);

    sum2_decryptor_free(d);
}

TEST_F(SuitDecryptorTest, WrongKeyFails) {
    if (envelope_.empty()) GTEST_SKIP() << "expAW test file not available";
    ASSERT_NE(manifest_, nullptr);

    /* Wrong KEK */
    const uint8_t wrong_kek[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };

    sum2_decryptor_t *d = sum2_decryptor_create(
        manifest_, 0, wrong_kek, sizeof(wrong_kek));
    /* A128KW unwrap with wrong key should fail */
    EXPECT_EQ(d, nullptr) << "Wrong KEK should fail to unwrap CEK";
    if (d) sum2_decryptor_free(d);
}

TEST_F(SuitDecryptorTest, NullManifestFails) {
    const uint8_t kek[16] = {0x61};
    sum2_decryptor_t *d = sum2_decryptor_create(nullptr, 0, kek, 16);
    EXPECT_EQ(d, nullptr);
}

TEST_F(SuitDecryptorTest, FreeNull) {
    sum2_decryptor_free(nullptr);  /* Should not crash */
}
