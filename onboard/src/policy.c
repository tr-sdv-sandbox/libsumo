/**
 * @file policy.c
 * @brief Persistent rollback and revocation policy.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sum2/policy.h"
#include "sum2/validator.h"

#include <string.h>

#define REVOCATION_KEY "sum2_reject_before"

int sum2_policy_load(
    sum2_validator_t *v,
    const sum2_storage_ops_t *storage)
{
    if (!v || !storage) return -1;

    /* Load revocation timestamp */
    int64_t reject_before = 0;
    if (storage->read_i64(REVOCATION_KEY, &reject_before, storage->ctx) == 0) {
        sum2_validator_set_reject_before(v, reject_before);
    }

    /*
     * TODO: Load per-component sequence numbers.
     *
     * Convention: key = "sum2_seq_<component_id_hex>"
     * For each stored key, call sum2_validator_set_min_sequence().
     *
     * This requires either:
     *   a) A known list of component IDs (configured at init), or
     *   b) An enumerate/iterate API on the storage backend
     */

    return 0;
}

int sum2_policy_save(
    const sum2_manifest_t *manifest,
    const sum2_storage_ops_t *storage)
{
    if (!manifest || !storage) return -1;

    /*
     * TODO: Persist sequence number for each component in the manifest.
     *
     * For campaign manifests: persist the campaign sequence number.
     * For image manifests: persist the per-ECU sequence number.
     */

    return 0;
}
