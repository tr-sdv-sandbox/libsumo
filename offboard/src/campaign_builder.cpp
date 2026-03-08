/**
 * @file campaign_builder.cpp
 * @brief L1 campaign manifest builder.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sum2/campaign_builder.h"

#include <stdexcept>

extern "C" {
#include "csuit/csuit.h"
}

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
    impl_->dependencies.push_back({
        std::move(fetch_uri),
        {l2_envelope.begin(), l2_envelope.end()},
        {}
    });
    return *this;
}

CampaignBuilder& CampaignBuilder::AddIntegratedImage(
    std::string key,
    std::span<const uint8_t> l2_envelope) {
    impl_->dependencies.push_back({
        key,
        {l2_envelope.begin(), l2_envelope.end()},
        std::move(key)
    });
    return *this;
}

std::vector<uint8_t> CampaignBuilder::Build(const CoseKey& signing_key) {
    /*
     * TODO: implementation outline:
     *
     * 1. Compute SHA-256 digest of each L2 envelope
     *
     * 2. Allocate suit_envelope_t and populate:
     *    - manifest.version = 1
     *    - manifest.sequence_number = impl_->sequence_number
     *    - manifest.common.dependencies = [one per L2 manifest]
     *    - manifest.common.shared_seq:
     *        override-parameters { vendor-id, class-id }
     *        condition-vendor-identifier
     *        condition-class-identifier
     *
     * 3. Build dependency-resolution sequence:
     *    For each dependency i:
     *      set-component-index(i)
     *      override-parameters { uri, image-digest of L2 envelope }
     *      directive-fetch
     *      condition-dependency-integrity
     *
     * 4. Build install sequence:
     *    For each dependency i (in order):
     *      set-component-index(i)
     *      directive-process-dependency
     *
     * 5. Build validate sequence:
     *    For each dependency i:
     *      set-component-index(i)
     *      condition-dependency-integrity
     *
     * 6. For integrated dependencies:
     *    Add L2 envelope bytes to SUIT_Envelope as integrated payloads
     *
     * 7. Encode + sign
     */

    (void)signing_key;
    throw std::runtime_error("CampaignBuilder::Build not yet implemented");
}

} // namespace sum2
