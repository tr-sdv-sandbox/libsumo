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
    suit_key_t trust_anchor;
    bool has_trust_anchor;
    uint64_t min_seq;           /* per-component rollback (simplified: single global) */
    int64_t reject_before;      /* revocation timestamp */
};

struct sum2_manifest {
    suit_envelope_t envelope;
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

    /* Initialize trust anchor as ES256 public key via libcsuit */
    if (trust_anchor_key && ta_len > 0) {
        suit_err_t err;
        if (ta_len == PRIME256V1_PUBLIC_KEY_LENGTH) {
            err = suit_key_init_es256_public_key(trust_anchor_key, &v->trust_anchor);
        } else {
            /* Try to parse as COSE_Key */
            UsefulBufC cose_key = {trust_anchor_key, ta_len};
            err = suit_set_suit_key_from_cose_key(cose_key, &v->trust_anchor);
        }
        if (err == SUIT_SUCCESS) {
            v->has_trust_anchor = true;
        }
    }

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
    if (!v) return SUM2_ERR_INVALID_ENVELOPE;
    (void)component_id; (void)cid_len;
    v->min_seq = min_seq;
    return SUM2_OK;
}

int sum2_validator_set_reject_before(
    sum2_validator_t *v,
    int64_t unix_timestamp)
{
    if (!v) return SUM2_ERR_INVALID_ENVELOPE;
    v->reject_before = unix_timestamp;
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

    /* 1. Decode envelope CBOR via libcsuit */
    UsefulBufC buf = {envelope, envelope_len};
    suit_mechanism_t mechanism = {0};
    if (v->has_trust_anchor) {
        mechanism.key = v->trust_anchor;
        mechanism.cose_tag = COSE_SIGN1_TAG;
        mechanism.use = true;
    }

    suit_err_t err = suit_decode_envelope(buf, &m->envelope, &mechanism);
    if (err != SUIT_SUCCESS) {
        free(m);
        return SUM2_ERR_INVALID_ENVELOPE;
    }

    /* 2. Verify COSE_Sign1 signature on authentication wrapper */
    if (v->has_trust_anchor && m->envelope.wrapper.signatures_len > 0) {
        UsefulBufC sig_payload = m->envelope.wrapper.signatures[0];
        UsefulBufC verified_payload = NULLUsefulBufC;
        err = suit_verify_cose_sign1(sig_payload, &v->trust_anchor, &verified_payload);
        if (err != SUIT_SUCCESS) {
            free(m);
            return SUM2_ERR_AUTH_FAILED;
        }

        /* 3. Verify manifest digest matches signed digest */
        err = suit_verify_digest(verified_payload, &m->envelope.wrapper.digest);
        if (err != SUIT_SUCCESS) {
            free(m);
            return SUM2_ERR_AUTH_FAILED;
        }
    }

    /* 4. Check sequence number against rollback policy */
    if (m->envelope.manifest.sequence_number < v->min_seq) {
        free(m);
        return SUM2_ERR_ROLLBACK_REJECTED;
    }

    /* 5. Check revocation timestamp */
    if (v->reject_before > 0 && trusted_time > 0 && trusted_time < v->reject_before) {
        free(m);
        return SUM2_ERR_REVOKED;
    }

    *manifest_out = m;
    return SUM2_OK;
}

void sum2_validator_free(sum2_validator_t *v)
{
    if (!v) return;
    if (v->has_trust_anchor) {
        suit_free_key(&v->trust_anchor);
    }
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
    if (!m || !out || !out_len) return SUM2_ERR_INVALID_ENVELOPE;
    if (index >= m->envelope.manifest.common.components_len)
        return SUM2_ERR_INVALID_ENVELOPE;

    *out = m->envelope.manifest.common.components[index].encoded_component.ptr;
    *out_len = m->envelope.manifest.common.components[index].encoded_component.len;
    return SUM2_OK;
}

int sum2_manifest_image_size(
    const sum2_manifest_t *m, size_t component_index,
    uint64_t *size_out)
{
    /* TODO: extract image-size parameter from shared sequence */
    (void)m; (void)component_index; (void)size_out;
    return SUM2_ERR_UNSUPPORTED;
}

int sum2_manifest_image_digest(
    const sum2_manifest_t *m, size_t component_index,
    const uint8_t **digest_out, size_t *digest_len_out,
    int *algorithm_out)
{
    /* TODO: extract image-digest parameter from shared sequence */
    (void)m; (void)component_index;
    (void)digest_out; (void)digest_len_out; (void)algorithm_out;
    return SUM2_ERR_UNSUPPORTED;
}

void sum2_manifest_free(sum2_manifest_t *m)
{
    free(m);
}
