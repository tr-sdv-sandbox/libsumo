/**
 * @file validator.c
 * @brief SUIT envelope validation — wraps libcsuit's decode + auth.
 *
 * Supports:
 *  - Direct COSE_Sign1 verification against trust anchor(s)
 *  - Delegation chains (SUIT equivalent of X.509 cert chains)
 *  - Key revocation by kid
 *  - Anti-rollback via sequence number (strictly greater than)
 *  - Timestamp-based revocation
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sum2/validator.h"

#include <stdlib.h>
#include <string.h>

/* libcsuit headers */
#include "csuit/csuit.h"

#define SUM2_MAX_REVOKED_KIDS 8
#define SUM2_MAX_KID_LEN 32

struct sum2_validator {
    sum2_device_id_t device_id;

    /* Trust anchor store — up to SUIT_MAX_KEY_NUM root keys */
    suit_key_t trust_anchors[SUIT_MAX_KEY_NUM];
    size_t num_trust_anchors;

    /* Key revocation list — kids of revoked signing keys */
    struct {
        uint8_t kid[SUM2_MAX_KID_LEN];
        size_t len;
    } revoked_kids[SUM2_MAX_REVOKED_KIDS];
    size_t num_revoked_kids;

    uint64_t min_seq;       /* anti-rollback: must be strictly > */
    int has_min_seq;        /* true once set_min_sequence called */
    int64_t reject_before;  /* timestamp-based revocation */
};

struct sum2_manifest {
    suit_envelope_t envelope;
    /* Which mechanisms[] slots were used during verification */
    suit_mechanism_t mechanisms[SUIT_MAX_KEY_NUM];
};

/* --- Forward declarations --- */
static const suit_parameters_t *find_shared_param(
    const sum2_manifest_t *m, size_t component_index, int64_t param_label);

/* --- Internal helpers --- */

static suit_err_t init_key(const uint8_t *key_data, size_t key_len,
                            suit_key_t *out)
{
    if (key_len == PRIME256V1_PUBLIC_KEY_LENGTH) {
        return suit_key_init_es256_public_key(key_data, out);
    }
    UsefulBufC cose_key = {key_data, key_len};
    return suit_set_suit_key_from_cose_key(cose_key, out);
}

static int is_kid_revoked(const sum2_validator_t *v,
                           const uint8_t *kid, size_t kid_len)
{
    for (size_t i = 0; i < v->num_revoked_kids; i++) {
        if (v->revoked_kids[i].len == kid_len &&
            memcmp(v->revoked_kids[i].kid, kid, kid_len) == 0) {
            return 1;
        }
    }
    return 0;
}

/* Check if any mechanism used during verification has a revoked kid */
static int any_mechanism_revoked(const sum2_validator_t *v,
                                  const suit_mechanism_t mechanisms[])
{
    if (v->num_revoked_kids == 0) return 0;

    for (size_t i = 0; i < SUIT_MAX_KEY_NUM; i++) {
        if (!mechanisms[i].use) continue;
        if (mechanisms[i].key.kid.ptr && mechanisms[i].key.kid.len > 0) {
            if (is_kid_revoked(v, mechanisms[i].key.kid.ptr,
                               mechanisms[i].key.kid.len)) {
                return 1;
            }
        }
    }
    return 0;
}

/* --- Public API --- */

sum2_validator_t *sum2_validator_create(
    const uint8_t *trust_anchor_key, size_t ta_len,
    const sum2_device_id_t *device_id)
{
    sum2_validator_t *v = calloc(1, sizeof(*v));
    if (!v) return NULL;

    if (device_id) {
        v->device_id = *device_id;
    }

    if (trust_anchor_key && ta_len > 0) {
        if (init_key(trust_anchor_key, ta_len,
                     &v->trust_anchors[0]) == SUIT_SUCCESS) {
            v->num_trust_anchors = 1;
        }
    }

    return v;
}

int sum2_validator_add_trust_anchor(
    sum2_validator_t *v,
    const uint8_t *key, size_t key_len)
{
    if (!v || !key) return SUM2_ERR_INVALID_ENVELOPE;
    if (v->num_trust_anchors >= SUIT_MAX_KEY_NUM)
        return SUM2_ERR_OUT_OF_MEMORY;

    suit_err_t err = init_key(key, key_len,
                              &v->trust_anchors[v->num_trust_anchors]);
    if (err != SUIT_SUCCESS) return SUM2_ERR_AUTH_FAILED;
    v->num_trust_anchors++;
    return SUM2_OK;
}

int sum2_validator_revoke_kid(
    sum2_validator_t *v,
    const uint8_t *kid, size_t kid_len)
{
    if (!v || !kid || kid_len == 0) return SUM2_ERR_INVALID_ENVELOPE;
    if (kid_len > SUM2_MAX_KID_LEN) return SUM2_ERR_INVALID_ENVELOPE;
    if (v->num_revoked_kids >= SUM2_MAX_REVOKED_KIDS)
        return SUM2_ERR_OUT_OF_MEMORY;

    memcpy(v->revoked_kids[v->num_revoked_kids].kid, kid, kid_len);
    v->revoked_kids[v->num_revoked_kids].len = kid_len;
    v->num_revoked_kids++;
    return SUM2_OK;
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
    v->has_min_seq = 1;
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

    /*
     * Populate mechanisms array from all registered trust anchors.
     * suit_decode_envelope will:
     *  1. Process suit-delegation (if present) — verify each CWT in the
     *     chain against current mechanisms, add delegated keys
     *  2. Process suit-authentication-wrapper — verify COSE_Sign1 against
     *     trust anchors or delegated keys
     *  3. Verify manifest digest matches signed digest
     */
    UsefulBufC buf = {envelope, envelope_len};
    memset(m->mechanisms, 0, sizeof(m->mechanisms));

    for (size_t i = 0; i < v->num_trust_anchors && i < SUIT_MAX_KEY_NUM; i++) {
        m->mechanisms[i].key = v->trust_anchors[i];
        m->mechanisms[i].cose_tag = COSE_SIGN1_TAG;
        m->mechanisms[i].use = true;
    }

    suit_err_t err = suit_decode_envelope(buf, &m->envelope, m->mechanisms);
    if (err != SUIT_SUCCESS) {
        free(m);
        if (err == SUIT_ERR_FAILED_TO_VERIFY)
            return SUM2_ERR_AUTH_FAILED;
        if (err == SUIT_ERR_FAILED_TO_VERIFY_DELEGATION)
            return SUM2_ERR_DELEGATION_FAILED;
        return SUM2_ERR_INVALID_ENVELOPE;
    }

    /* Check if any key in the verification chain is revoked */
    if (any_mechanism_revoked(v, m->mechanisms)) {
        free(m);
        return SUM2_ERR_REVOKED;
    }

    /* Anti-rollback: strictly greater than last accepted */
    if (v->has_min_seq && m->envelope.manifest.sequence_number <= v->min_seq) {
        free(m);
        return SUM2_ERR_ROLLBACK_REJECTED;
    }

    /* Timestamp-based revocation */
    if (v->reject_before > 0 && trusted_time > 0 &&
        trusted_time < v->reject_before) {
        free(m);
        return SUM2_ERR_REVOKED;
    }

    *manifest_out = m;
    return SUM2_OK;
}

void sum2_validator_free(sum2_validator_t *v)
{
    if (!v) return;
    for (size_t i = 0; i < v->num_trust_anchors; i++) {
        suit_free_key(&v->trust_anchors[i]);
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
    if (!m || !size_out) return SUM2_ERR_INVALID_ENVELOPE;
    const suit_parameters_t *p =
        find_shared_param(m, component_index, SUIT_PARAMETER_IMAGE_SIZE);
    if (!p) return SUM2_ERR_UNSUPPORTED;
    *size_out = p->value.uint64;
    return SUM2_OK;
}

int sum2_manifest_image_digest(
    const sum2_manifest_t *m, size_t component_index,
    const uint8_t **digest_out, size_t *digest_len_out,
    int *algorithm_out)
{
    if (!m || !digest_out || !digest_len_out) return SUM2_ERR_INVALID_ENVELOPE;
    const suit_parameters_t *p =
        find_shared_param(m, component_index, SUIT_PARAMETER_IMAGE_DIGEST);
    if (!p) return SUM2_ERR_UNSUPPORTED;
    *digest_out = p->value.digest.bytes.ptr;
    *digest_len_out = p->value.digest.bytes.len;
    if (algorithm_out) *algorithm_out = p->value.digest.algorithm_id;
    return SUM2_OK;
}

/* --- Shared-sequence parameter helpers --- */

/*
 * Search shared_seq commands for a parameter with the given label
 * targeting the given component index. The shared sequence contains
 * SUIT_DIRECTIVE_OVERRIDE_PARAMETERS / SET_PARAMETERS commands,
 * each carrying a params_list with an index and param entries.
 */
static const suit_parameters_t *find_shared_param(
    const sum2_manifest_t *m, size_t component_index, int64_t param_label)
{
    const suit_command_sequence_t *seq = &m->envelope.manifest.common.shared_seq;
    for (size_t i = 0; i < seq->len; i++) {
        const suit_command_sequence_item_t *cmd = &seq->commands[i];
        if (cmd->label != SUIT_DIRECTIVE_OVERRIDE_PARAMETERS &&
            cmd->label != SUIT_DIRECTIVE_SET_PARAMETERS)
            continue;

        const suit_parameters_list_t *pl = &cmd->value.params_list;
        if (pl->index != (uint8_t)component_index)
            continue;

        for (size_t j = 0; j < pl->len; j++) {
            if (pl->params[j].label == param_label)
                return &pl->params[j];
        }
    }
    return NULL;
}

/* Extract a 16-byte UUID parameter (vendor/class/device ID) */
static int extract_uuid_param(
    const sum2_manifest_t *m, size_t component_index,
    int64_t param_label, uint8_t out[16])
{
    if (!m || !out) return SUM2_ERR_INVALID_ENVELOPE;
    const suit_parameters_t *p = find_shared_param(m, component_index, param_label);
    if (!p || !p->value.string.ptr || p->value.string.len != 16)
        return SUM2_ERR_UNSUPPORTED;
    memcpy(out, p->value.string.ptr, 16);
    return SUM2_OK;
}

int sum2_manifest_vendor_id(
    const sum2_manifest_t *m, size_t component_index,
    uint8_t out[16])
{
    return extract_uuid_param(m, component_index,
                              SUIT_PARAMETER_VENDOR_IDENTIFIER, out);
}

int sum2_manifest_class_id(
    const sum2_manifest_t *m, size_t component_index,
    uint8_t out[16])
{
    return extract_uuid_param(m, component_index,
                              SUIT_PARAMETER_CLASS_IDENTIFIER, out);
}

int sum2_manifest_device_id(
    const sum2_manifest_t *m, size_t component_index,
    uint8_t out[16])
{
    return extract_uuid_param(m, component_index,
                              SUIT_PARAMETER_DEVICE_IDENTIFIER, out);
}

int sum2_manifest_version(
    const sum2_manifest_t *m, size_t component_index,
    sum2_version_cmp_t *cmp_out,
    int64_t *parts_out, size_t *parts_len)
{
    if (!m || !cmp_out || !parts_out || !parts_len)
        return SUM2_ERR_INVALID_ENVELOPE;

    const suit_parameters_t *p = find_shared_param(
        m, component_index, SUIT_PARAMETER_VERSION);
    if (!p || !p->value.string.ptr || p->value.string.len == 0)
        return SUM2_ERR_UNSUPPORTED;

    /* The version parameter is CBOR-encoded suit_version_match_t.
     * Decode it using libcsuit. */
    suit_version_match_t vm;
    memset(&vm, 0, sizeof(vm));
    suit_err_t err = suit_decode_version_match(p->value.string, &vm);
    if (err != SUIT_SUCCESS)
        return SUM2_ERR_INVALID_ENVELOPE;

    *cmp_out = (sum2_version_cmp_t)vm.type;
    size_t count = vm.value.len;
    if (count > *parts_len) count = *parts_len;
    for (size_t i = 0; i < count; i++)
        parts_out[i] = vm.value.int64[i];
    *parts_len = count;
    return SUM2_OK;
}

/* --- Text section accessors --- */

static const suit_text_component_t *find_text_component(
    const sum2_manifest_t *m, size_t component_index)
{
    const suit_text_map_t *tm = &m->envelope.manifest.sev_man_mem.text;
    if (tm->text_lmaps_len == 0)
        return NULL;

    /* Text map is indexed by language tag; use first lmap. */
    const suit_text_lmap_t *lmap = &tm->text_lmaps[0];
    if (component_index >= lmap->component_len)
        return NULL;

    return &lmap->component[component_index].text_component;
}

/* Use a macro since C doesn't have member pointers */
#define EXTRACT_TEXT_FIELD(m, ci, field_name, out, out_len) do { \
    if (!(m) || !(out) || !(out_len)) return SUM2_ERR_INVALID_ENVELOPE; \
    const suit_text_component_t *tc = find_text_component((m), (ci)); \
    if (!tc || !tc->field_name.ptr || tc->field_name.len == 0) \
        return SUM2_ERR_UNSUPPORTED; \
    *(out) = (const char *)tc->field_name.ptr; \
    *(out_len) = tc->field_name.len; \
    return SUM2_OK; \
} while (0)

int sum2_manifest_text_vendor_name(
    const sum2_manifest_t *m, size_t component_index,
    const char **out, size_t *out_len)
{
    EXTRACT_TEXT_FIELD(m, component_index, vendor_name, out, out_len);
}

int sum2_manifest_text_model_name(
    const sum2_manifest_t *m, size_t component_index,
    const char **out, size_t *out_len)
{
    EXTRACT_TEXT_FIELD(m, component_index, model_name, out, out_len);
}

int sum2_manifest_text_model_info(
    const sum2_manifest_t *m, size_t component_index,
    const char **out, size_t *out_len)
{
    EXTRACT_TEXT_FIELD(m, component_index, model_info, out, out_len);
}

int sum2_manifest_text_version(
    const sum2_manifest_t *m, size_t component_index,
    const char **out, size_t *out_len)
{
    EXTRACT_TEXT_FIELD(m, component_index, component_version, out, out_len);
}

int sum2_manifest_text_description(
    const sum2_manifest_t *m,
    const char **out, size_t *out_len)
{
    if (!m || !out || !out_len) return SUM2_ERR_INVALID_ENVELOPE;
    const suit_text_map_t *tm = &m->envelope.manifest.sev_man_mem.text;
    if (tm->text_lmaps_len == 0)
        return SUM2_ERR_UNSUPPORTED;
    const suit_text_lmap_t *lmap = &tm->text_lmaps[0];
    if (!lmap->manifest_description.ptr || lmap->manifest_description.len == 0)
        return SUM2_ERR_UNSUPPORTED;
    *out = (const char *)lmap->manifest_description.ptr;
    *out_len = lmap->manifest_description.len;
    return SUM2_OK;
}

void sum2_manifest_free(sum2_manifest_t *m)
{
    free(m);
}
