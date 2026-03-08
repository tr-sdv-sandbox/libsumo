/**
 * @file image_builder.cpp
 * @brief L2 ECU image manifest builder.
 *
 * Wraps libcsuit's encode API with a fluent C++ interface.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sum2/image_builder.h"

#include <stdexcept>

/* libcsuit headers (C) */
#include "csuit_wrapper.h"

namespace sum2 {

// --- CoseKey ---

struct CoseKey::Impl {
    std::vector<uint8_t> key_bytes;   // Raw key material (COSE_Key CBOR or DER)
    std::vector<uint8_t> kid;         // Key identifier
    int algorithm = 0;                // COSE algorithm ID
};

CoseKey::CoseKey() : impl_(std::make_unique<Impl>()) {}
CoseKey::~CoseKey() = default;
CoseKey::CoseKey(CoseKey&&) noexcept = default;
CoseKey& CoseKey::operator=(CoseKey&&) noexcept = default;

CoseKey CoseKey::FromDer(std::span<const uint8_t> der) {
    CoseKey k;
    k.impl_->key_bytes.assign(der.begin(), der.end());
    /* TODO: parse DER into suit_key_t via libcsuit or backend */
    return k;
}

CoseKey CoseKey::FromCoseKeyBytes(std::span<const uint8_t> cose_key) {
    CoseKey k;
    k.impl_->key_bytes.assign(cose_key.begin(), cose_key.end());
    /* TODO: parse COSE_Key CBOR into suit_key_t */
    return k;
}

CoseKey CoseKey::FromPem(std::string_view pem) {
    CoseKey k;
    /* TODO: parse PEM into suit_key_t via backend */
    (void)pem;
    return k;
}

std::vector<uint8_t> CoseKey::PublicKeyBytes() const {
    /* TODO: extract public key bytes */
    return {};
}

std::vector<uint8_t> CoseKey::KeyId() const {
    return impl_->kid;
}

// --- ImageManifestBuilder ---

struct ImageManifestBuilder::Impl {
    std::vector<std::string> component_id;
    uint64_t sequence_number = 0;
    Uuid vendor_id{};
    Uuid class_id{};
    SemVer semver{};
    bool has_semver = false;

    std::vector<uint8_t> payload_digest;
    uint64_t payload_size = 0;
    std::string payload_uri;
    std::vector<std::string> fallback_uris;

    std::vector<uint8_t> encryption_info;
};

ImageManifestBuilder::ImageManifestBuilder()
    : impl_(std::make_unique<Impl>()) {}

ImageManifestBuilder::~ImageManifestBuilder() = default;

ImageManifestBuilder& ImageManifestBuilder::SetComponentId(
    std::vector<std::string> id) {
    impl_->component_id = std::move(id);
    return *this;
}

ImageManifestBuilder& ImageManifestBuilder::SetSequenceNumber(uint64_t seq) {
    impl_->sequence_number = seq;
    return *this;
}

ImageManifestBuilder& ImageManifestBuilder::SetVendorId(Uuid vendor) {
    impl_->vendor_id = vendor;
    return *this;
}

ImageManifestBuilder& ImageManifestBuilder::SetClassId(Uuid class_id) {
    impl_->class_id = class_id;
    return *this;
}

ImageManifestBuilder& ImageManifestBuilder::SetSemVer(SemVer version) {
    impl_->semver = std::move(version);
    impl_->has_semver = true;
    return *this;
}

ImageManifestBuilder& ImageManifestBuilder::SetPayloadDigest(
    const uint8_t *sha256, size_t digest_len, uint64_t plaintext_size) {
    impl_->payload_digest.assign(sha256, sha256 + digest_len);
    impl_->payload_size = plaintext_size;
    return *this;
}

ImageManifestBuilder& ImageManifestBuilder::SetPayloadUri(std::string uri) {
    impl_->payload_uri = std::move(uri);
    return *this;
}

ImageManifestBuilder& ImageManifestBuilder::AddFallbackUri(std::string uri) {
    impl_->fallback_uris.push_back(std::move(uri));
    return *this;
}

ImageManifestBuilder& ImageManifestBuilder::SetEncryptionInfo(
    std::span<const uint8_t> cose_encrypt_cbor) {
    impl_->encryption_info.assign(
        cose_encrypt_cbor.begin(), cose_encrypt_cbor.end());
    return *this;
}

std::vector<uint8_t> ImageManifestBuilder::Build(const CoseKey& signing_key) {
    /*
     * TODO: implementation outline:
     *
     * 1. Allocate suit_envelope_t and populate:
     *    - manifest.version = 1
     *    - manifest.sequence_number = impl_->sequence_number
     *    - manifest.common.components = [impl_->component_id]
     *    - manifest.common.shared_seq:
     *        override-parameters { vendor-id, class-id, image-digest, image-size }
     *        condition-vendor-identifier
     *        condition-class-identifier
     *
     * 2. Build payload-fetch sequence:
     *    - set-component-index(0)
     *    - override-parameters { uri: impl_->payload_uri }
     *    - If fallback URIs: try-each with alternatives
     *    - If encryption: override-parameters { encryption-info }
     *    - directive-fetch
     *
     * 3. Build install sequence:
     *    - set-component-index(0)
     *    - If encrypted: directive-copy (decrypt + write)
     *    - condition-image-match
     *
     * 4. Build validate sequence:
     *    - set-component-index(0)
     *    - condition-image-match
     *
     * 5. Call suit_encode_envelope() to serialize to CBOR
     * 6. Call suit_sign_cose_sign1() to wrap in COSE_Sign1
     * 7. Build final SUIT_Envelope with auth wrapper
     *
     * Return the complete envelope as CBOR bytes.
     */

    (void)signing_key;
    throw std::runtime_error("ImageManifestBuilder::Build not yet implemented");
}

} // namespace sum2
