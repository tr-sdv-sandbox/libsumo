/**
 * @file campaign_builder.cpp
 * @brief L1 campaign manifest builder.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sum2/campaign_builder.h"

#include <stdexcept>

#include "cose_key_impl.h"
#include "csuit_wrapper.h"

namespace sum2 {

struct CampaignBuilder::Impl {
    uint64_t sequence_number = 0;
    Uuid vendor_id{};
    Uuid class_id{};

    struct Dependency {
        std::string fetch_uri;
        std::vector<uint8_t> l2_envelope;
        std::string integrated_key;  // empty = external, non-empty = integrated
    };

    std::vector<Dependency> dependencies;
};

CampaignBuilder::CampaignBuilder()
    : impl_(std::make_unique<Impl>()) {}

CampaignBuilder::~CampaignBuilder() = default;

CampaignBuilder& CampaignBuilder::SetSequenceNumber(uint64_t seq) {
    impl_->sequence_number = seq;
    return *this;
}

CampaignBuilder& CampaignBuilder::SetVendorId(Uuid vendor) {
    impl_->vendor_id = vendor;
    return *this;
}

CampaignBuilder& CampaignBuilder::SetClassId(Uuid class_id) {
    impl_->class_id = class_id;
    return *this;
}

CampaignBuilder& CampaignBuilder::AddImage(
    std::string fetch_uri,
    std::span<const uint8_t> l2_envelope) {
    Impl::Dependency dep;
    dep.fetch_uri = std::move(fetch_uri);
    dep.l2_envelope.assign(l2_envelope.begin(), l2_envelope.end());
    impl_->dependencies.push_back(std::move(dep));
    return *this;
}

CampaignBuilder& CampaignBuilder::AddIntegratedImage(
    std::string key,
    std::span<const uint8_t> l2_envelope) {
    Impl::Dependency dep;
    dep.fetch_uri = key;
    dep.l2_envelope.assign(l2_envelope.begin(), l2_envelope.end());
    dep.integrated_key = std::move(key);
    impl_->dependencies.push_back(std::move(dep));
    return *this;
}

std::vector<uint8_t> CampaignBuilder::Build(const CoseKey& signing_key) {
    if (impl_->dependencies.empty())
        throw std::runtime_error("CampaignBuilder: no dependencies added");

    /* Compute SHA-256 digest of each L2 envelope and build dep descriptors */
    std::vector<sum2_campaign_dep_t> deps;
    for (auto &d : impl_->dependencies) {
        sum2_campaign_dep_t cd{};
        cd.fetch_uri = d.fetch_uri.c_str();
        cd.fetch_uri_len = d.fetch_uri.size();
        cd.is_integrated = !d.integrated_key.empty();
        cd.payload = d.l2_envelope.data();
        cd.payload_len = d.l2_envelope.size();

        sum2_sha256(d.l2_envelope.data(), d.l2_envelope.size(), cd.digest);
        deps.push_back(cd);
    }

    /* Determine signing mode */
    const auto &kb = signing_key.impl_->key_bytes;
    int cose_tag = 17;  /* COSE_Mac0 default */
    int algorithm = 5;  /* HMAC256 default */
    if (signing_key.impl_->algorithm != 0) {
        algorithm = signing_key.impl_->algorithm;
        if (algorithm == -7 || algorithm == -8 || algorithm == -9) {
            cose_tag = 18; /* COSE_Sign1 for asymmetric */
        }
    }

    std::vector<uint8_t> out(16384);
    size_t out_len = 0;
    int rc = sum2_eb_encode_campaign(
        impl_->sequence_number,
        impl_->vendor_id.bytes,
        impl_->class_id.bytes,
        deps.data(), deps.size(),
        kb.data(), kb.size(),
        cose_tag, algorithm,
        out.data(), out.size(), &out_len);

    if (rc != 0)
        throw std::runtime_error("Failed to encode campaign (rc=" + std::to_string(rc) + ")");

    out.resize(out_len);
    return out;
}

} // namespace sum2
