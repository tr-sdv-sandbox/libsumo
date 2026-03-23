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
#define SEQUENCE_KEY   "sum2_seq"

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

    /* Load global sequence number */
    uint64_t seq = 0;
    if (storage->read_u64(SEQUENCE_KEY, &seq, storage->ctx) == 0) {
        sum2_validator_set_min_sequence(v, NULL, 0, seq);
    }

    return 0;
}

int sum2_policy_save(
    const sum2_manifest_t *manifest,
    const sum2_storage_ops_t *storage)
{
    if (!manifest || !storage) return -1;

    uint64_t seq = sum2_manifest_sequence_number(manifest);
    if (storage->write_u64(SEQUENCE_KEY, seq, storage->ctx) != 0) {
        return -1;
    }

    return 0;
}
