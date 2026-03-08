/**
 * @file orchestrator.h
 * @brief Two-level manifest orchestration (campaign + image processing).
 *
 * Processes L1 campaign manifests by resolving dependencies, fetching L2
 * image manifests, and driving the update sequence. Delegates actual I/O
 * to platform callbacks.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SUM2_ORCHESTRATOR_H
#define SUM2_ORCHESTRATOR_H

#include <stddef.h>
#include <stdint.h>
#include "sum2/validator.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Platform callbacks — the device provides these to handle I/O.
 *
 * The orchestrator calls these during manifest processing. All callbacks
 * receive the user_ctx pointer for device-specific state.
 */
typedef struct {
    /**
     * Fetch data from a URI into a buffer.
     * Used to download L2 manifests and firmware payloads.
     *
     * @param uri       URI string (not null-terminated, use uri_len)
     * @param uri_len   URI length
     * @param buf       Output buffer
     * @param buf_size  Buffer capacity
     * @param fetched   On output: bytes written to buf
     * @return 0 on success, negative on error
     */
    int (*fetch)(const char *uri, size_t uri_len,
                 uint8_t *buf, size_t buf_size, size_t *fetched,
                 void *user_ctx);

    /**
     * Stream-write decrypted firmware to a component's storage.
     * Called repeatedly with chunks during decryption.
     *
     * @param component_id   CBOR-encoded SUIT_Component_Identifier
     * @param cid_len        Component ID length
     * @param offset         Byte offset within the component
     * @param data           Decrypted plaintext chunk
     * @param data_len       Chunk length
     * @return 0 on success, negative on error
     */
    int (*write)(const uint8_t *component_id, size_t cid_len,
                 size_t offset,
                 const uint8_t *data, size_t data_len,
                 void *user_ctx);

    /**
     * Invoke (boot) a component after successful update.
     * Return 0 to continue, negative to abort.
     */
    int (*invoke)(const uint8_t *component_id, size_t cid_len,
                  void *user_ctx);

    /**
     * Swap two components atomically (A/B partition switch).
     */
    int (*swap)(const uint8_t *comp_a, size_t a_len,
                const uint8_t *comp_b, size_t b_len,
                void *user_ctx);

    /**
     * Persist the accepted sequence number for a component.
     * Called after successful validation so rollback policy survives reboot.
     */
    int (*persist_sequence)(const uint8_t *component_id, size_t cid_len,
                            uint64_t sequence_number,
                            void *user_ctx);

    void *user_ctx;
} sum2_platform_ops_t;

/**
 * Process a campaign manifest (L1).
 *
 * Resolves dependencies, fetches and validates L2 image manifests,
 * and drives the update sequence in install_order.
 *
 * For each dependency:
 *   1. fetch() the L2 envelope from the URI in the campaign manifest
 *   2. sum2_validate_envelope() the L2 envelope
 *   3. sum2_process_image() for the L2 manifest
 *
 * @param v          Validator (carries trust anchor + device identity)
 * @param campaign   Validated L1 campaign manifest
 * @param ops        Platform callbacks
 * @return SUM2_OK on success, first error encountered on failure
 */
int sum2_process_campaign(
    sum2_validator_t *v,
    const sum2_manifest_t *campaign,
    const sum2_platform_ops_t *ops
);

/**
 * Process a single image manifest (L2).
 *
 * Fetches the encrypted firmware, decrypts in chunks via streaming
 * decryptor, writes to component storage, and verifies the plaintext
 * digest.
 *
 * Can be called standalone (without a campaign) for single-ECU devices.
 *
 * @param v          Validator
 * @param image      Validated L2 image manifest
 * @param ops        Platform callbacks
 * @return SUM2_OK on success, negative error code on failure
 */
int sum2_process_image(
    sum2_validator_t *v,
    const sum2_manifest_t *image,
    const sum2_platform_ops_t *ops
);

#ifdef __cplusplus
}
#endif
#endif /* SUM2_ORCHESTRATOR_H */
