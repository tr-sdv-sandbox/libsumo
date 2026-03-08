/**
 * @file orchestrator.c
 * @brief Two-level manifest orchestration.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sum2/orchestrator.h"
#include "sum2/decryptor.h"

#include <stdlib.h>
#include <string.h>

/* Default streaming chunk size (4KB) */
#define SUM2_CHUNK_SIZE 4096

int sum2_process_campaign(
    sum2_validator_t *v,
    const sum2_manifest_t *campaign,
    const sum2_platform_ops_t *ops)
{
    if (!v || !campaign || !ops) return SUM2_ERR_INVALID_ENVELOPE;
    if (!sum2_manifest_is_campaign(campaign)) return SUM2_ERR_INVALID_ENVELOPE;

    /*
     * TODO: implementation outline:
     *
     * For each dependency in campaign (in order):
     *   1. Extract fetch URI from campaign's payload-fetch sequence
     *   2. ops->fetch() the L2 envelope
     *   3. sum2_validate_envelope() the L2 envelope
     *   4. sum2_process_image() for the validated L2 manifest
     *   5. On success: ops->persist_sequence() for the L2 component
     *
     * On any failure: abort and return error (no partial updates).
     *
     * Alternative: use libcsuit's suit_process_envelope() with custom
     * callbacks that delegate to our ops. This reuses libcsuit's command
     * sequence interpreter instead of reimplementing dependency walking.
     */

    size_t dep_count = sum2_manifest_dependency_count(campaign);

    for (size_t i = 0; i < dep_count; i++) {
        /* TODO: extract dependency URI + expected digest */
        /* TODO: fetch, validate, process */
        (void)i;
    }

    return SUM2_ERR_UNSUPPORTED; /* not yet implemented */
}

int sum2_process_image(
    sum2_validator_t *v,
    const sum2_manifest_t *image,
    const sum2_platform_ops_t *ops)
{
    if (!v || !image || !ops) return SUM2_ERR_INVALID_ENVELOPE;

    /*
     * TODO: implementation outline:
     *
     * 1. Extract payload URI from image manifest
     * 2. Create streaming decryptor: sum2_decryptor_create()
     * 3. Fetch firmware in chunks:
     *    a. ops->fetch() a chunk of ciphertext
     *    b. sum2_decryptor_update() to decrypt
     *    c. ops->write() the plaintext chunk to component storage
     *    d. Feed plaintext into running SHA-256 hash
     * 4. sum2_decryptor_finalize() — verify GCM auth tag
     * 5. Compare computed SHA-256 against image-digest in manifest
     * 6. On success: ops->persist_sequence() for this component
     *
     * For unencrypted manifests: skip steps 2/4, just hash + verify.
     */

    return SUM2_ERR_UNSUPPORTED; /* not yet implemented */
}
