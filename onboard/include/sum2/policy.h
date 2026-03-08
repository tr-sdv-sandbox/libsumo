/**
 * @file policy.h
 * @brief Device-side update policy (rollback, revocation, version tracking).
 *
 * Application-layer policy that sits above the SUIT manifest format.
 * Manages persistent state (sequence numbers, revocation timestamps)
 * across reboots.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SUM2_POLICY_H
#define SUM2_POLICY_H

#include <stddef.h>
#include <stdint.h>
#include "sum2/validator.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Persistent storage interface — device provides this.
 *
 * The policy module needs to persist sequence numbers and revocation
 * timestamps across reboots. On ESP32 this maps to NVS, on Linux to
 * a file, on Zephyr to settings subsystem.
 */
typedef struct {
    /** Read a uint64 value by key. Return 0 on success, negative if not found. */
    int (*read_u64)(const char *key, uint64_t *value, void *ctx);

    /** Write a uint64 value by key. Return 0 on success. */
    int (*write_u64)(const char *key, uint64_t value, void *ctx);

    /** Read a int64 value by key. */
    int (*read_i64)(const char *key, int64_t *value, void *ctx);

    /** Write a int64 value by key. */
    int (*write_i64)(const char *key, int64_t value, void *ctx);

    void *ctx;
} sum2_storage_ops_t;

/**
 * Load rollback policy from persistent storage into a validator.
 * Reads all stored sequence numbers and revocation timestamps,
 * applies them via sum2_validator_set_min_sequence / set_reject_before.
 */
int sum2_policy_load(
    sum2_validator_t *v,
    const sum2_storage_ops_t *storage
);

/**
 * Persist updated policy after a successful update.
 * Stores the new sequence number for the updated component(s).
 */
int sum2_policy_save(
    const sum2_manifest_t *manifest,
    const sum2_storage_ops_t *storage
);

#ifdef __cplusplus
}
#endif
#endif /* SUM2_POLICY_H */
