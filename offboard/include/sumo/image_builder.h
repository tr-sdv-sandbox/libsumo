/**
 * @file image_builder.h
 * @brief Fluent builder for L2 ECU image manifests.
 *
 * Builds a signed SUIT_Envelope containing a single-component manifest
 * for one ECU's firmware image. Handles hash computation, encryption
 * parameter embedding, and COSE_Sign1 signing.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SUMO_IMAGE_BUILDER_H
#define SUMO_IMAGE_BUILDER_H

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace sumo {

struct Uuid {
    uint8_t bytes[16];
};

struct SemVer {
    uint32_t major;
    uint32_t minor;
    uint32_t patch;
    std::string prerelease;   // optional
    std::string build;        // optional
};

/**
 * Opaque COSE_Key wrapper.
 * Holds signing keys (Ed25519/ES256) or device keys (X25519/P-256).
 */
class CoseKey {
public:
    static CoseKey FromDer(std::span<const uint8_t> der);
    static CoseKey FromCoseKeyBytes(std::span<const uint8_t> cose_key);
    static CoseKey FromPem(std::string_view pem);

    std::vector<uint8_t> PublicKeyBytes() const;
    std::vector<uint8_t> KeyId() const;

    // Move-only
    CoseKey(CoseKey&&) noexcept;
    CoseKey& operator=(CoseKey&&) noexcept;
    ~CoseKey();

private:
    CoseKey();
    struct Impl;
    std::unique_ptr<Impl> impl_;
    friend class ImageManifestBuilder;
    friend class CampaignBuilder;
    friend class Encryptor;
    friend CoseKey GenerateSigningKey(int algorithm);
    friend CoseKey GenerateDeviceKey(int algorithm);
    friend std::vector<uint8_t> SerializeKey(const CoseKey& key, bool include_private);
    friend std::string SerializeKeyPem(const CoseKey& key, bool include_private);
};

/**
 * Result of encrypting a firmware payload.
 */
struct EncryptedPayload {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> encryption_info;  // CBOR-encoded COSE_Encrypt
};

/**
 * Build an L2 (ECU image) SUIT manifest.
 *
 * Usage:
 *   auto envelope = ImageManifestBuilder()
 *       .SetComponentId({"ecu-a", "firmware"})
 *       .SetSequenceNumber(42)
 *       .SetVendorId(vendor_uuid)
 *       .SetClassId(class_uuid)
 *       .SetPayloadDigest(hash, sizeof(hash), plaintext_size)
 *       .SetPayloadUri("https://fw.example.com/ecu-a-v2.enc")
 *       .AddFallbackUri("ipfs://Qm...")
 *       .SetEncryptionInfo(encrypted.encryption_info)
 *       .SetSemVer({2, 1, 0})
 *       .Build(signing_key);
 */
class ImageManifestBuilder {
public:
    ImageManifestBuilder();
    ~ImageManifestBuilder();

    // Identity & metadata
    ImageManifestBuilder& SetComponentId(std::vector<std::string> id);
    ImageManifestBuilder& SetSequenceNumber(uint64_t seq);
    ImageManifestBuilder& SetVendorId(Uuid vendor);
    ImageManifestBuilder& SetClassId(Uuid class_id);
    ImageManifestBuilder& SetSemVer(SemVer version);

    // Payload description (hash + size must be set; payload itself is external)
    ImageManifestBuilder& SetPayloadDigest(
        const uint8_t *sha256, size_t digest_len,
        uint64_t plaintext_size);
    ImageManifestBuilder& SetPayloadUri(std::string uri);
    ImageManifestBuilder& AddFallbackUri(std::string uri);

    // Encryption (optional — omit for unencrypted manifests)
    ImageManifestBuilder& SetEncryptionInfo(
        std::span<const uint8_t> cose_encrypt_cbor);

    // Build and sign. Returns the complete SUIT_Envelope as CBOR bytes.
    std::vector<uint8_t> Build(const CoseKey& signing_key);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace sumo

#endif /* SUMO_IMAGE_BUILDER_H */
