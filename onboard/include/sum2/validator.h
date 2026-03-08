/**
 * @file validator.h
 * @brief SUIT envelope validation for device-side update processing.
 *
 * Validates SUIT_Envelope authentication (COSE_Sign1), checks device
 * conditions (vendor/class/device ID), and enforces anti-rollback policy.
 * Works with both L1 (campaign) and L2 (image) manifests.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SUM2_VALIDATOR_H
#define SUM2_VALIDATOR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque types */
typedef struct sum2_validator sum2_validator_t;
typedef struct sum2_manifest sum2_manifest_t;

/* Error codes */
typedef enum {
    SUM2_OK                       =  0,
    SUM2_ERR_INVALID_ENVELOPE     = -1,
    SUM2_ERR_AUTH_FAILED          = -2,  /* COSE_Sign1 verification failed */
    SUM2_ERR_VENDOR_MISMATCH      = -3,
    SUM2_ERR_CLASS_MISMATCH       = -4,
    SUM2_ERR_DEVICE_MISMATCH      = -5,
    SUM2_ERR_ROLLBACK_REJECTED    = -6,  /* sequence number too low */
    SUM2_ERR_REVOKED              = -7,  /* timestamp-based revocation */
    SUM2_ERR_EXPIRED              = -8,
    SUM2_ERR_DEPENDENCY_FAILED    = -9,
    SUM2_ERR_DIGEST_MISMATCH     = -10,
    SUM2_ERR_DECRYPT_FAILED      = -11,
    SUM2_ERR_OUT_OF_MEMORY       = -12,
    SUM2_ERR_UNSUPPORTED         = -13,
    SUM2_ERR_CALLBACK_FAILED     = -14,
} sum2_err_t;

/**
 * Device identity — UUIDs for vendor, class, and device matching.
 */
typedef struct {
    uint8_t vendor_id[16];  /* RFC 4122 UUID */
    uint8_t class_id[16];
    uint8_t device_id[16];
} sum2_device_id_t;

/**
 * Create a validator with trust anchor and device identity.
 *
 * @param trust_anchor_key  COSE_Key bytes (public key of trust anchor)
 * @param ta_len            Length of trust anchor key
 * @param device_id         Device identity for condition matching
 * @return Validator handle, or NULL on failure
 */
sum2_validator_t *sum2_validator_create(
    const uint8_t *trust_anchor_key, size_t ta_len,
    const sum2_device_id_t *device_id
);

/**
 * Add a device key for decryption (X25519 or P-256 ECDH).
 * Multiple keys can be registered (matched by kid).
 */
int sum2_validator_add_device_key(
    sum2_validator_t *v,
    const uint8_t *key, size_t key_len,
    const uint8_t *kid, size_t kid_len
);

/**
 * Set minimum accepted sequence number for a component.
 * Manifests with sequence_number < min_seq are rejected.
 *
 * @param component_id  CBOR-encoded SUIT_Component_Identifier, or NULL for
 *                      global (campaign-level) policy
 * @param cid_len       Length, or 0 for global
 * @param min_seq       Minimum accepted sequence number (exclusive)
 */
int sum2_validator_set_min_sequence(
    sum2_validator_t *v,
    const uint8_t *component_id, size_t cid_len,
    uint64_t min_seq
);

/**
 * Set timestamp-based revocation policy.
 * Reject manifests signed before this timestamp.
 */
int sum2_validator_set_reject_before(
    sum2_validator_t *v,
    int64_t unix_timestamp
);

/**
 * Validate a SUIT_Envelope.
 *
 * Verifies COSE_Sign1 signature against trust anchor, checks conditions
 * (vendor/class/device ID), and enforces rollback policy.
 *
 * On success, returns a parsed manifest handle. The caller must free it
 * with sum2_manifest_free().
 *
 * @param envelope      Raw SUIT_Envelope bytes
 * @param envelope_len  Length
 * @param trusted_time  Current trusted time (unix seconds), or 0 to skip
 *                      time-based checks
 * @param manifest_out  On success, receives parsed manifest handle
 * @return SUM2_OK on success, negative error code on failure
 */
int sum2_validate_envelope(
    sum2_validator_t *v,
    const uint8_t *envelope, size_t envelope_len,
    int64_t trusted_time,
    sum2_manifest_t **manifest_out
);

void sum2_validator_free(sum2_validator_t *v);

/* --- Manifest accessors --- */

uint64_t    sum2_manifest_sequence_number(const sum2_manifest_t *m);
size_t      sum2_manifest_component_count(const sum2_manifest_t *m);
size_t      sum2_manifest_dependency_count(const sum2_manifest_t *m);
int         sum2_manifest_is_campaign(const sum2_manifest_t *m);

int sum2_manifest_component_id(
    const sum2_manifest_t *m, size_t index,
    const uint8_t **out, size_t *out_len
);

int sum2_manifest_image_size(
    const sum2_manifest_t *m, size_t component_index,
    uint64_t *size_out
);

int sum2_manifest_image_digest(
    const sum2_manifest_t *m, size_t component_index,
    const uint8_t **digest_out, size_t *digest_len_out,
    int *algorithm_out
);

void sum2_manifest_free(sum2_manifest_t *m);

#ifdef __cplusplus
}
#endif
#endif /* SUM2_VALIDATOR_H */
