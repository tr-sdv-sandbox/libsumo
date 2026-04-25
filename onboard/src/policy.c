/**
 * @file policy.c
 * @brief Persistent rollback and revocation policy.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sumo/policy.h"
#include "sumo/validator.h"

#include <string.h>

#define REVOCATION_KEY      "sumo_reject_before"
#define SEQUENCE_KEY        "sumo_seq"
#define SECURITY_VERSION_KEY "sumo_sec_ver"

int sumo_policy_load(
    sumo_validator_t *v,
    const sumo_storage_ops_t *storage)
{
    if (!v || !storage) return -1;

    /* Load revocation timestamp */
    int64_t reject_before = 0;
    if (storage->read_i64(REVOCATION_KEY, &reject_before, storage->ctx) == 0) {
        sumo_validator_set_reject_before(v, reject_before);
    }

    /* Load global sequence number */
    uint64_t seq = 0;
    if (storage->read_u64(SEQUENCE_KEY, &seq, storage->ctx) == 0) {
        sumo_validator_set_min_sequence(v, NULL, 0, seq);
    }

    /* Load security_version floor (independent rollback counter) */
    uint64_t sec_ver = 0;
    if (storage->read_u64(SECURITY_VERSION_KEY, &sec_ver, storage->ctx) == 0) {
        sumo_validator_set_min_security_version(v, sec_ver);
    }

    return 0;
}

int sumo_policy_save(
    const sumo_manifest_t *manifest,
    const sumo_storage_ops_t *storage)
{
    if (!manifest || !storage) return -1;

    uint64_t seq = sumo_manifest_sequence_number(manifest);
    if (storage->write_u64(SEQUENCE_KEY, seq, storage->ctx) != 0) {
        return -1;
    }

    /* Persist security_version only when the manifest declared one. The
     * validator has already enforced strict-greater against the existing
     * floor, so unconditional write is safe. */
    uint64_t sec_ver = 0;
    if (sumo_manifest_security_version(manifest, 0, &sec_ver) == SUMO_OK) {
        if (storage->write_u64(SECURITY_VERSION_KEY, sec_ver, storage->ctx) != 0) {
            return -1;
        }
    }

    return 0;
}
