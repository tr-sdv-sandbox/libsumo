/**
 * @file validator.c
 * @brief SUIT envelope validation — wraps libcsuit's decode + auth.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sum2/validator.h"

#include <stdlib.h>
#include <string.h>

/* libcsuit headers */
#include "csuit/csuit.h"

struct sum2_validator {
    sum2_device_id_t device_id;
    /* TODO: trust anchor COSE_Key */
    /* TODO: device keys for decryption */
    /* TODO: rollback policy (component_id -> min_seq) */
    /* TODO: revocation timestamp */
};

struct sum2_manifest {
    suit_envelope_t envelope;
    /* TODO: parsed metadata cache */
};

sum2_validator_t *sum2_validator_create(
    const uint8_t *trust_anchor_key, size_t ta_len,
    const sum2_device_id_t *device_id)
{
    sum2_validator_t *v = calloc(1, sizeof(*v));
    if (!v) return NULL;

    if (device_id) {
        v->device_id = *device_id;
    }

    /* TODO: parse trust anchor COSE_Key */
    /* TODO: init libcsuit mechanism with trust anchor */

    return v;
}

int sum2_validator_add_device_key(
    sum2_validator_t *v,
    const uint8_t *key, size_t key_len,
    const uint8_t *kid, size_t kid_len)
{
    /* TODO: store device key for COSE_Encrypt recipient matching */
    (void)v; (void)key; (void)key_len; (void)kid; (void)kid_len;
    return SUM2_ERR_UNSUPPORTED;
}

int sum2_validator_set_min_sequence(
    sum2_validator_t *v,
    const uint8_t *component_id, size_t cid_len,
    uint64_t min_seq)
{
    /* TODO: store rollback policy */
    (void)v; (void)component_id; (void)cid_len; (void)min_seq;
    return SUM2_OK;
}

int sum2_validator_set_reject_before(
    sum2_validator_t *v,
    int64_t unix_timestamp)
{
    /* TODO: store revocation timestamp */
    (void)v; (void)unix_timestamp;
    return SUM2_OK;
}

int sum2_validate_envelope(
    sum2_validator_t *v,
    const uint8_t *envelope, size_t envelope_len,
    int64_t trusted_time,
    sum2_manifest_t **manifest_out)
{
    if (!v || !envelope || !manifest_out) return SUM2_ERR_INVALID_ENVELOPE;

    sum2_manifest_t *m = calloc(1, sizeof(*m));
    if (!m) return SUM2_ERR_OUT_OF_MEMORY;

    /*
     * TODO: implementation outline:
     *
     * 1. Call suit_decode_envelope() to parse CBOR
     * 2. Verify COSE_Sign1 against trust anchor via suit_verify_cose_sign1()
     * 3. Check vendor/class/device conditions against v->device_id
     * 4. Check sequence_number against rollback policy
     * 5. Check trusted_time against revocation policy
     * 6. On success: populate *manifest_out
     */

    (void)trusted_time;

    *manifest_out = m;
    return SUM2_ERR_UNSUPPORTED; /* not yet implemented */
}

void sum2_validator_free(sum2_validator_t *v)
{
    free(v);
}

/* --- Manifest accessors --- */

uint64_t sum2_manifest_sequence_number(const sum2_manifest_t *m)
{
    if (!m) return 0;
    return m->envelope.manifest.sequence_number;
}

size_t sum2_manifest_component_count(const sum2_manifest_t *m)
{
    if (!m) return 0;
    return m->envelope.manifest.common.components_len;
}

size_t sum2_manifest_dependency_count(const sum2_manifest_t *m)
{
    if (!m) return 0;
    return m->envelope.manifest.common.dependencies.len;
}

int sum2_manifest_is_campaign(const sum2_manifest_t *m)
{
    return sum2_manifest_dependency_count(m) > 0;
}

int sum2_manifest_component_id(
    const sum2_manifest_t *m, size_t index,
    const uint8_t **out, size_t *out_len)
{
    /* TODO: extract component identifier at index */
    (void)m; (void)index; (void)out; (void)out_len;
    return SUM2_ERR_UNSUPPORTED;
}

int sum2_manifest_image_size(
    const sum2_manifest_t *m, size_t component_index,
    uint64_t *size_out)
{
    /* TODO: extract image-size parameter */
    (void)m; (void)component_index; (void)size_out;
    return SUM2_ERR_UNSUPPORTED;
}

int sum2_manifest_image_digest(
    const sum2_manifest_t *m, size_t component_index,
    const uint8_t **digest_out, size_t *digest_len_out,
    int *algorithm_out)
{
    /* TODO: extract image-digest parameter */
    (void)m; (void)component_index;
    (void)digest_out; (void)digest_len_out; (void)algorithm_out;
    return SUM2_ERR_UNSUPPORTED;
}

void sum2_manifest_free(sum2_manifest_t *m)
{
    free(m);
}
