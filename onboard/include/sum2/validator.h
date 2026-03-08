/**
 * @file validator.h
 * @brief SUIT envelope validation for device-side update processing.
 *
 * Validates SUIT_Envelope authentication (COSE_Sign1), including
 * delegation chains (SUIT equivalent of X.509 certificate chains),
 * checks device conditions (vendor/class/device ID), and enforces
 * anti-rollback and key revocation policy.
 *
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
    SUM2_ERR_REVOKED              = -7,  /* key or timestamp revocation */
    SUM2_ERR_EXPIRED              = -8,
    SUM2_ERR_DEPENDENCY_FAILED    = -9,
    SUM2_ERR_DIGEST_MISMATCH     = -10,
    SUM2_ERR_DECRYPT_FAILED      = -11,
    SUM2_ERR_OUT_OF_MEMORY       = -12,
    SUM2_ERR_UNSUPPORTED         = -13,
    SUM2_ERR_CALLBACK_FAILED     = -14,
    SUM2_ERR_DELEGATION_FAILED   = -15,  /* delegation chain verification failed */
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
 * Create a validator with a root trust anchor and device identity.
 *
 * The trust anchor is the root of trust — it can directly sign manifests,
 * or sign delegation chains (CWTs) that delegate signing authority to
 * intermediate keys (SUIT equivalent of X.509 certificate chains).
 *
 * @param trust_anchor_key  COSE_Key CBOR bytes, or raw 65-byte P-256 point
 * @param ta_len            Length of trust anchor key
 * @param device_id         Device identity for condition matching (may be NULL)
 * @return Validator handle, or NULL on failure
 */
sum2_validator_t *sum2_validator_create(
    const uint8_t *trust_anchor_key, size_t ta_len,
    const sum2_device_id_t *device_id
);

/**
 * Add an additional trust anchor.
 *
 * Supports multiple trust domains — e.g., one trust anchor for the
 * bootloader vendor and another for the application vendor.  Up to
 * SUIT_MAX_KEY_NUM total trust anchors can be registered.
 *
 * @return SUM2_OK, or SUM2_ERR_OUT_OF_MEMORY if the trust anchor store is full
 */
int sum2_validator_add_trust_anchor(
    sum2_validator_t *v,
    const uint8_t *key, size_t key_len
);

/**
 * Revoke a signing key by its Key ID (kid).
 *
 * Any manifest signed by this key — whether directly or via a delegation
 * chain that includes this kid — will be rejected.  This is the SUIT
 * equivalent of X.509 certificate revocation.
 *
 * @param kid      Key identifier to revoke (from COSE_Key kid field)
 * @param kid_len  Length of kid
 */
int sum2_validator_revoke_kid(
    sum2_validator_t *v,
    const uint8_t *kid, size_t kid_len
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
 * Manifests with sequence_number <= min_seq are rejected (strictly greater).
 *
 * @param component_id  CBOR-encoded SUIT_Component_Identifier, or NULL for
 *                      global (campaign-level) policy
 * @param cid_len       Length, or 0 for global
 * @param min_seq       Last accepted sequence number; next must be > min_seq
 */
int sum2_validator_set_min_sequence(
    sum2_validator_t *v,
    const uint8_t *component_id, size_t cid_len,
    uint64_t min_seq
);

/**
 * Set timestamp-based revocation policy.
 * Reject envelopes when trusted_time < reject_before.
 */
int sum2_validator_set_reject_before(
    sum2_validator_t *v,
    int64_t unix_timestamp
);

/**
 * Validate a SUIT_Envelope.
 *
 * Full verification pipeline:
 *   1. Parse CBOR envelope structure
 *   2. Verify delegation chain (if present) — each CWT signed by
 *      previous key, starting from a registered trust anchor
 *   3. Verify COSE_Sign1 authentication wrapper — signed by trust
 *      anchor or delegated key
 *   4. Verify manifest digest matches signed digest
 *   5. Check signing key against revocation list (kid-based)
 *   6. Check sequence number against anti-rollback policy (strict >)
 *   7. Check timestamp against revocation policy
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

/**
 * Extract vendor/class/device UUID from shared sequence parameters.
 * Returns SUM2_OK and writes 16 bytes to out, or SUM2_ERR_UNSUPPORTED
 * if not present in the manifest.
 */
int sum2_manifest_vendor_id(
    const sum2_manifest_t *m, size_t component_index,
    uint8_t out[16]
);

int sum2_manifest_class_id(
    const sum2_manifest_t *m, size_t component_index,
    uint8_t out[16]
);

int sum2_manifest_device_id(
    const sum2_manifest_t *m, size_t component_index,
    uint8_t out[16]
);

/**
 * Version comparison types (from draft-ietf-suit-update-management).
 */
typedef enum {
    SUM2_VERSION_CMP_GREATER       = 1,
    SUM2_VERSION_CMP_GREATER_EQUAL = 2,
    SUM2_VERSION_CMP_EQUAL         = 3,
    SUM2_VERSION_CMP_LESSER_EQUAL  = 4,
    SUM2_VERSION_CMP_LESSER        = 5,
} sum2_version_cmp_t;

#define SUM2_MAX_VERSION_PARTS 5

/**
 * Extract semantic version from suit-parameter-version.
 *
 * @param component_index  Component to query
 * @param cmp_out          Comparison type (e.g. GREATER_EQUAL)
 * @param parts_out        Version integers [major, minor, patch, ...]
 * @param parts_len        In: capacity of parts_out; Out: actual count
 * @return SUM2_OK, or SUM2_ERR_UNSUPPORTED if no version parameter
 */
int sum2_manifest_version(
    const sum2_manifest_t *m, size_t component_index,
    sum2_version_cmp_t *cmp_out,
    int64_t *parts_out, size_t *parts_len
);

/**
 * Text section accessors — human-readable strings from suit-text.
 * Returns SUM2_OK and sets out/out_len to point into the parsed envelope,
 * or SUM2_ERR_UNSUPPORTED if the text field is not present.
 * The returned pointer is valid for the lifetime of the manifest handle.
 */
int sum2_manifest_text_vendor_name(
    const sum2_manifest_t *m, size_t component_index,
    const char **out, size_t *out_len
);

int sum2_manifest_text_model_name(
    const sum2_manifest_t *m, size_t component_index,
    const char **out, size_t *out_len
);

int sum2_manifest_text_model_info(
    const sum2_manifest_t *m, size_t component_index,
    const char **out, size_t *out_len
);

int sum2_manifest_text_version(
    const sum2_manifest_t *m, size_t component_index,
    const char **out, size_t *out_len
);

int sum2_manifest_text_description(
    const sum2_manifest_t *m,
    const char **out, size_t *out_len
);

void sum2_manifest_free(sum2_manifest_t *m);

#ifdef __cplusplus
}
#endif
#endif /* SUM2_VALIDATOR_H */
