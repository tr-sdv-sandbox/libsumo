/**
 * @file image_builder.cpp
 * @brief L2 ECU image manifest builder.
 *
 * Wraps the C envelope builder with a fluent C++ interface.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sum2/image_builder.h"

#include <stdexcept>
#include <cstring>

#include "csuit_wrapper.h"

namespace sum2 {

// --- CoseKey ---

struct CoseKey::Impl {
    std::vector<uint8_t> key_bytes;   // COSE_Key CBOR
    std::vector<uint8_t> kid;
    int algorithm = 0;
};

CoseKey::CoseKey() : impl_(std::make_unique<Impl>()) {}
CoseKey::~CoseKey() = default;
CoseKey::CoseKey(CoseKey&&) noexcept = default;
CoseKey& CoseKey::operator=(CoseKey&&) noexcept = default;

CoseKey CoseKey::FromDer(std::span<const uint8_t> der) {
    CoseKey k;
    k.impl_->key_bytes.assign(der.begin(), der.end());
    return k;
}

CoseKey CoseKey::FromCoseKeyBytes(std::span<const uint8_t> cose_key) {
    CoseKey k;
    k.impl_->key_bytes.assign(cose_key.begin(), cose_key.end());
    return k;
}

CoseKey CoseKey::FromPem(std::string_view pem) {
    CoseKey k;
    (void)pem;
    throw std::runtime_error("CoseKey::FromPem not yet implemented");
}

std::vector<uint8_t> CoseKey::PublicKeyBytes() const {
    return impl_->key_bytes;
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
    bool has_vendor_id = false;
    bool has_class_id = false;

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
    impl_->has_vendor_id = true;
    return *this;
}

ImageManifestBuilder& ImageManifestBuilder::SetClassId(Uuid class_id) {
    impl_->class_id = class_id;
    impl_->has_class_id = true;
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
    sum2_envelope_builder_t *eb = sum2_eb_create();
    if (!eb)
        throw std::runtime_error("Failed to create envelope builder");

    sum2_eb_set_sequence_number(eb, impl_->sequence_number);

    if (!impl_->component_id.empty()) {
        std::vector<const char *> segs;
        for (auto &s : impl_->component_id)
            segs.push_back(s.c_str());
        if (sum2_eb_add_component(eb, segs.data(), segs.size()) != 0) {
            sum2_eb_free(eb);
            throw std::runtime_error("Failed to set component ID");
        }
    }

    if (impl_->has_vendor_id)
        sum2_eb_set_vendor_id(eb, impl_->vendor_id.bytes);
    if (impl_->has_class_id)
        sum2_eb_set_class_id(eb, impl_->class_id.bytes);

    if (!impl_->payload_digest.empty()) {
        sum2_eb_set_image_digest_sha256(
            eb, impl_->payload_digest.data(), impl_->payload_size);
    }

    if (!impl_->payload_uri.empty())
        sum2_eb_set_payload_uri(eb, impl_->payload_uri.c_str());

    if (!impl_->encryption_info.empty()) {
        sum2_eb_set_encryption_info(
            eb, impl_->encryption_info.data(), impl_->encryption_info.size());
    }

    /* Determine signing mode from key.
     * For now: if the key has COSE_Key bytes, pass them through.
     * The caller specifies the algorithm via the key's algorithm field,
     * but for simplicity we default to HMAC256/MAC0 if key.algorithm==5,
     * otherwise ES256/Sign1. */
    const auto &kb = signing_key.impl_->key_bytes;
    int cose_tag = 17;  /* COSE_Mac0 default */
    int algorithm = 5;  /* HMAC256 default */
    if (signing_key.impl_->algorithm != 0) {
        algorithm = signing_key.impl_->algorithm;
        if (algorithm == -7 || algorithm == -8 || algorithm == -9) {
            cose_tag = 18; /* COSE_Sign1 for asymmetric */
        }
    }

    std::vector<uint8_t> out(8192);
    size_t out_len = 0;
    int rc = sum2_eb_encode(eb,
                            kb.data(), kb.size(),
                            cose_tag, algorithm,
                            out.data(), out.size(), &out_len);
    sum2_eb_free(eb);
    if (rc != 0)
        throw std::runtime_error("Failed to encode envelope (rc=" + std::to_string(rc) + ")");

    out.resize(out_len);
    return out;
}

} // namespace sum2
