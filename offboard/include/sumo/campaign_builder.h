/**
 * @file campaign_builder.h
 * @brief Fluent builder for L1 campaign manifests.
 *
 * Builds a signed SUIT_Envelope that references L2 image manifests as
 * dependencies. The campaign manifest orchestrates multi-ECU updates:
 * it specifies which image manifests to fetch, in what order, and
 * generates the dependency-resolution + install command sequences.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SUMO_CAMPAIGN_BUILDER_H
#define SUMO_CAMPAIGN_BUILDER_H

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "sumo/image_builder.h"  // CoseKey, Uuid

namespace sumo {

/**
 * A dependency entry: an L2 image manifest to include in the campaign.
 */
struct ImageDependency {
    std::string fetch_uri;                // Where the device fetches the L2 envelope
    std::vector<uint8_t> l2_envelope;     // Signed L2 envelope (digest computed automatically)
};

/**
 * Build an L1 (campaign) SUIT manifest.
 *
 * Usage:
 *   // First, build L2 image manifests
 *   auto ecu_a_envelope = ImageManifestBuilder().SetComponentId({"ecu-a", "fw"})...Build(fw_key);
 *   auto ecu_b_envelope = ImageManifestBuilder().SetComponentId({"ecu-b", "fw"})...Build(fw_key);
 *
 *   // Then, build L1 campaign referencing them
 *   auto campaign = CampaignBuilder()
 *       .SetSequenceNumber(100)
 *       .SetVendorId(vendor_uuid)
 *       .SetClassId(class_uuid)
 *       .AddImage("https://updates.example.com/ecu-a.suit", ecu_a_envelope)
 *       .AddImage("https://updates.example.com/ecu-b.suit", ecu_b_envelope)
 *       .Build(operator_key);
 */
class CampaignBuilder {
public:
    CampaignBuilder();
    ~CampaignBuilder();

    // Campaign-level metadata
    CampaignBuilder& SetSequenceNumber(uint64_t seq);
    CampaignBuilder& SetVendorId(Uuid vendor);
    CampaignBuilder& SetClassId(Uuid class_id);

    /**
     * Add an L2 image manifest as a dependency (fetched by URI).
     *
     * The device will fetch the L2 envelope from fetch_uri during the
     * payload-fetch phase. The digest of l2_envelope is computed and
     * embedded in the campaign manifest for integrity verification.
     *
     * Dependencies are processed in the order they are added.
     */
    CampaignBuilder& AddImage(
        std::string fetch_uri,
        std::span<const uint8_t> l2_envelope);

    /**
     * Add an L2 image manifest as an integrated dependency.
     *
     * The L2 envelope is embedded directly in the campaign envelope
     * (no separate fetch required). Useful for small manifests or
     * offline/USB delivery.
     *
     * @param key  Integrated payload key (e.g., "#ecu-a")
     */
    CampaignBuilder& AddIntegratedImage(
        std::string key,
        std::span<const uint8_t> l2_envelope);

    // Build and sign. Returns the complete L1 SUIT_Envelope as CBOR bytes.
    std::vector<uint8_t> Build(const CoseKey& signing_key);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace sumo

#endif /* SUMO_CAMPAIGN_BUILDER_H */
