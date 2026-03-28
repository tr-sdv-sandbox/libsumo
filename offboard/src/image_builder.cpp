/**
 * @file image_builder.cpp
 * @brief L2 ECU image manifest builder.
 *
 * Wraps the C envelope builder with a fluent C++ interface.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sumo/image_builder.h"

#include <stdexcept>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include "cose_key_impl.h"
#include "csuit_wrapper.h"

namespace sumo {

// --- CoseKey ---

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

    /* Try to extract algorithm (label 3) from the COSE_Key CBOR map.
     * Scan for byte 0x03 (uint 3) followed by the algorithm value. */
    for (size_t i = 1; i + 1 < cose_key.size(); i++) {
        if (cose_key[i] == 0x03) {
            uint8_t next = cose_key[i + 1];
            if (next < 0x18) {
                /* Tiny positive int (0-23) — e.g., HMAC256 = 5 */
                k.impl_->algorithm = next;
                break;
            } else if (next >= 0x20 && next < 0x38) {
                /* Tiny negative int: -1 - (next - 0x20) */
                k.impl_->algorithm = -1 - (next - 0x20);
                break;
            } else if (next == 0x38 && i + 2 < cose_key.size()) {
                /* 1-byte negative int: -1 - cose_key[i+2] */
                k.impl_->algorithm = -1 - static_cast<int>(cose_key[i + 2]);
                break;
            }
        }
    }

    return k;
}

CoseKey CoseKey::FromPem(std::string_view pem) {
    BIO *bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) throw std::runtime_error("BIO_new_mem_buf failed");

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    if (!pkey) {
        BIO_reset(bio);
        pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    }
    BIO_free(bio);
    if (!pkey) throw std::runtime_error("Failed to parse PEM key");

    CoseKey k;
    k.impl_->evp_pkey = pkey;

    int id = EVP_PKEY_id(pkey);
    if (id == EVP_PKEY_EC) {
        uint8_t x[32], y[32], d[32];
        int has_private = 0;

        BIGNUM *bn_x = nullptr, *bn_y = nullptr, *bn_d = nullptr;
        EVP_PKEY_get_bn_param(pkey, "qx", &bn_x);
        EVP_PKEY_get_bn_param(pkey, "qy", &bn_y);
        has_private = (EVP_PKEY_get_bn_param(pkey, "priv", &bn_d) == 1);

        if (bn_x) { BN_bn2binpad(bn_x, x, 32); BN_free(bn_x); }
        if (bn_y) { BN_bn2binpad(bn_y, y, 32); BN_free(bn_y); }
        if (bn_d && has_private) { BN_bn2binpad(bn_d, d, 32); BN_free(bn_d); }

        k.impl_->algorithm = -7; /* ES256 */

        /* Compute kid = SHA-256(x || y) */
        uint8_t combined[64];
        memcpy(combined, x, 32);
        memcpy(combined + 32, y, 32);
        k.impl_->kid.resize(32);
        sumo_sha256(combined, 64, k.impl_->kid.data());

        /* Build COSE_Key CBOR using the same helper approach as keygen.cpp */
        auto build_ec2 = [&](const uint8_t *priv) -> std::vector<uint8_t> {
            std::vector<uint8_t> buf;
            size_t n = 5 + 1 + (priv ? 1 : 0); /* kty, kid, alg, crv, x, y [, d] */
            /* map header */
            buf.push_back(static_cast<uint8_t>(0xA0 | (n & 0x1F)));
            /* 1: kty = EC2 (2) */
            buf.push_back(0x01); buf.push_back(0x02);
            /* 2: kid */
            buf.push_back(0x02); buf.push_back(0x58); buf.push_back(0x20);
            buf.insert(buf.end(), k.impl_->kid.begin(), k.impl_->kid.end());
            /* 3: alg = ES256 (-7) */
            buf.push_back(0x03); buf.push_back(0x26); /* -7 */
            /* -1: crv = P-256 (1) */
            buf.push_back(0x20); buf.push_back(0x01);
            /* -2: x */
            buf.push_back(0x21); buf.push_back(0x58); buf.push_back(0x20);
            buf.insert(buf.end(), x, x + 32);
            /* -3: y */
            buf.push_back(0x22); buf.push_back(0x58); buf.push_back(0x20);
            buf.insert(buf.end(), y, y + 32);
            /* -4: d (optional) */
            if (priv) {
                buf.push_back(0x23); buf.push_back(0x58); buf.push_back(0x20);
                buf.insert(buf.end(), priv, priv + 32);
            }
            return buf;
        };

        k.impl_->key_bytes = build_ec2(has_private ? d : nullptr);
        k.impl_->public_key_bytes = build_ec2(nullptr);
    }

    return k;
}

std::vector<uint8_t> CoseKey::PublicKeyBytes() const {
    if (!impl_->public_key_bytes.empty())
        return impl_->public_key_bytes;
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
    sumo_envelope_builder_t *eb = sumo_eb_create();
    if (!eb)
        throw std::runtime_error("Failed to create envelope builder");

    sumo_eb_set_sequence_number(eb, impl_->sequence_number);

    if (!impl_->component_id.empty()) {
        std::vector<const char *> segs;
        for (auto &s : impl_->component_id)
            segs.push_back(s.c_str());
        if (sumo_eb_add_component(eb, segs.data(), segs.size()) != 0) {
            sumo_eb_free(eb);
            throw std::runtime_error("Failed to set component ID");
        }
    }

    if (impl_->has_vendor_id)
        sumo_eb_set_vendor_id(eb, impl_->vendor_id.bytes);
    if (impl_->has_class_id)
        sumo_eb_set_class_id(eb, impl_->class_id.bytes);

    if (!impl_->payload_digest.empty()) {
        sumo_eb_set_image_digest_sha256(
            eb, impl_->payload_digest.data(), impl_->payload_size);
    }

    if (!impl_->payload_uri.empty())
        sumo_eb_set_payload_uri(eb, impl_->payload_uri.c_str());

    if (!impl_->encryption_info.empty()) {
        sumo_eb_set_encryption_info(
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
    int rc = sumo_eb_encode(eb,
                            kb.data(), kb.size(),
                            cose_tag, algorithm,
                            out.data(), out.size(), &out_len);
    sumo_eb_free(eb);
    if (rc != 0)
        throw std::runtime_error("Failed to encode envelope (rc=" + std::to_string(rc) + ")");

    out.resize(out_len);
    return out;
}

} // namespace sumo
