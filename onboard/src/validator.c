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
#include "sumo/validator.h"
#include "sumo_internal.h"

#include <stdlib.h>
#include <string.h>

/* libcsuit headers */
#include "csuit/csuit.h"

#define SUMO_MAX_REVOKED_KIDS 8
#define SUMO_MAX_KID_LEN 32

/* Up to SUMO_MAX_DEVICE_KEYS device decryption keys can be registered
 * (e.g., across key rotations). The recipient's kid in the envelope
 * COSE_Encrypt selects which key to use. */
#ifndef SUMO_MAX_DEVICE_KEYS
#define SUMO_MAX_DEVICE_KEYS 4
#endif
#define SUMO_MAX_DEVICE_KEY_LEN 256

/* SUIT private-use parameter labels (matching sumo-rs). */
#define SUMO_PARAMETER_SECURITY_VERSION ((int64_t)-257)

struct sumo_validator {
    sumo_device_id_t device_id;
    int has_device_id;      /* set when device_id was supplied at create-time */

    /* Trust anchor store — up to SUIT_MAX_KEY_NUM root keys */
    suit_key_t trust_anchors[SUIT_MAX_KEY_NUM];
    size_t num_trust_anchors;

    /* Key revocation list — kids of revoked signing keys */
    struct {
        uint8_t kid[SUMO_MAX_KID_LEN];
        size_t len;
    } revoked_kids[SUMO_MAX_REVOKED_KIDS];
    size_t num_revoked_kids;

    uint64_t min_seq;       /* anti-rollback: must be strictly > */
    int has_min_seq;        /* true once set_min_sequence called */
    uint64_t min_sec_ver;   /* security_version floor: must be strictly > */
    int has_min_sec_ver;    /* true once set_min_security_version called */
    int64_t reject_before;  /* timestamp-based revocation */

    /* Device decryption keys (COSE_Key CBOR or raw symmetric key), each
     * with an optional kid. The recipient kid in the envelope picks the
     * key; if no kid is supplied we fall back to the first registered
     * key for legacy single-key compatibility. */
    struct {
        uint8_t key[SUMO_MAX_DEVICE_KEY_LEN];
        size_t  key_len;
        uint8_t kid[SUMO_MAX_KID_LEN];
        size_t  kid_len;
    } device_keys[SUMO_MAX_DEVICE_KEYS];
    size_t num_device_keys;
};

/* sumo_manifest is defined in sumo_internal.h */

/* --- Forward declarations --- */
static const suit_parameters_t *find_shared_param(
    const sumo_manifest_t *m, size_t component_index, int64_t param_label);

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

static int is_kid_revoked(const sumo_validator_t *v,
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
static int any_mechanism_revoked(const sumo_validator_t *v,
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

sumo_validator_t *sumo_validator_create(
    const uint8_t *trust_anchor_key, size_t ta_len,
    const sumo_device_id_t *device_id)
{
    sumo_validator_t *v = calloc(1, sizeof(*v));
    if (!v) return NULL;

    if (device_id) {
        v->device_id = *device_id;
        v->has_device_id = 1;
    }

    if (trust_anchor_key && ta_len > 0) {
        if (init_key(trust_anchor_key, ta_len,
                     &v->trust_anchors[0]) == SUIT_SUCCESS) {
            v->num_trust_anchors = 1;
        }
    }

    return v;
}

int sumo_validator_add_trust_anchor(
    sumo_validator_t *v,
    const uint8_t *key, size_t key_len)
{
    if (!v || !key) return SUMO_ERR_INVALID_ENVELOPE;
    if (v->num_trust_anchors >= SUIT_MAX_KEY_NUM)
        return SUMO_ERR_OUT_OF_MEMORY;

    suit_err_t err = init_key(key, key_len,
                              &v->trust_anchors[v->num_trust_anchors]);
    if (err != SUIT_SUCCESS) return SUMO_ERR_AUTH_FAILED;
    v->num_trust_anchors++;
    return SUMO_OK;
}

int sumo_validator_revoke_kid(
    sumo_validator_t *v,
    const uint8_t *kid, size_t kid_len)
{
    if (!v || !kid || kid_len == 0) return SUMO_ERR_INVALID_ENVELOPE;
    if (kid_len > SUMO_MAX_KID_LEN) return SUMO_ERR_INVALID_ENVELOPE;
    if (v->num_revoked_kids >= SUMO_MAX_REVOKED_KIDS)
        return SUMO_ERR_OUT_OF_MEMORY;

    memcpy(v->revoked_kids[v->num_revoked_kids].kid, kid, kid_len);
    v->revoked_kids[v->num_revoked_kids].len = kid_len;
    v->num_revoked_kids++;
    return SUMO_OK;
}

int sumo_validator_add_device_key(
    sumo_validator_t *v,
    const uint8_t *key, size_t key_len,
    const uint8_t *kid, size_t kid_len)
{
    if (!v || !key || key_len == 0) return SUMO_ERR_INVALID_ENVELOPE;
    if (key_len > SUMO_MAX_DEVICE_KEY_LEN) return SUMO_ERR_INVALID_ENVELOPE;
    if (kid_len > SUMO_MAX_KID_LEN) return SUMO_ERR_INVALID_ENVELOPE;
    if (v->num_device_keys >= SUMO_MAX_DEVICE_KEYS)
        return SUMO_ERR_OUT_OF_MEMORY;

    size_t i = v->num_device_keys;
    memcpy(v->device_keys[i].key, key, key_len);
    v->device_keys[i].key_len = key_len;
    if (kid && kid_len > 0) {
        memcpy(v->device_keys[i].kid, kid, kid_len);
        v->device_keys[i].kid_len = kid_len;
    } else {
        v->device_keys[i].kid_len = 0;
    }
    v->num_device_keys++;
    return SUMO_OK;
}

int sumo_validator_get_device_key(
    const sumo_validator_t *v,
    const uint8_t **key_out, size_t *key_len_out)
{
    if (!v || !key_out || !key_len_out) return SUMO_ERR_INVALID_ENVELOPE;
    if (v->num_device_keys == 0) return SUMO_ERR_UNSUPPORTED;
    *key_out = v->device_keys[0].key;
    *key_len_out = v->device_keys[0].key_len;
    return SUMO_OK;
}

int sumo_validator_select_device_key(
    const sumo_validator_t *v,
    const uint8_t *kid, size_t kid_len,
    const uint8_t **key_out, size_t *key_len_out)
{
    if (!v || !key_out || !key_len_out) return SUMO_ERR_INVALID_ENVELOPE;
    if (v->num_device_keys == 0) return SUMO_ERR_UNSUPPORTED;

    /* Three cases when an envelope carries a kid:
     *   (a) any registered key has a matching kid → return it.
     *   (b) at least one registered key carries a kid but none match →
     *       reject (operator deliberately tagged keys; a kid mismatch is
     *       a real "wrong device" signal).
     *   (c) no registered key carries any kid → fall back to the first
     *       key (single-device legacy: the operator hasn't opted in to
     *       kid-based selection, so trust the unwrap step to fail-safe).
     */
    if (kid && kid_len > 0) {
        int any_kidded = 0;
        for (size_t i = 0; i < v->num_device_keys; i++) {
            if (v->device_keys[i].kid_len > 0) any_kidded = 1;
            if (v->device_keys[i].kid_len == kid_len &&
                memcmp(v->device_keys[i].kid, kid, kid_len) == 0) {
                *key_out = v->device_keys[i].key;
                *key_len_out = v->device_keys[i].key_len;
                return SUMO_OK;
            }
        }
        if (any_kidded) return SUMO_ERR_DECRYPT_FAILED;
        /* fall through to first-key */
    }

    *key_out = v->device_keys[0].key;
    *key_len_out = v->device_keys[0].key_len;
    return SUMO_OK;
}

int sumo_validator_set_min_sequence(
    sumo_validator_t *v,
    const uint8_t *component_id, size_t cid_len,
    uint64_t min_seq)
{
    if (!v) return SUMO_ERR_INVALID_ENVELOPE;
    (void)component_id; (void)cid_len;
    v->min_seq = min_seq;
    v->has_min_seq = 1;
    return SUMO_OK;
}

int sumo_validator_set_reject_before(
    sumo_validator_t *v,
    int64_t unix_timestamp)
{
    if (!v) return SUMO_ERR_INVALID_ENVELOPE;
    v->reject_before = unix_timestamp;
    return SUMO_OK;
}

int sumo_validator_set_min_security_version(
    sumo_validator_t *v,
    uint64_t min_security_version)
{
    if (!v) return SUMO_ERR_INVALID_ENVELOPE;
    v->min_sec_ver = min_security_version;
    v->has_min_sec_ver = 1;
    return SUMO_OK;
}

int sumo_validate_envelope(
    sumo_validator_t *v,
    const uint8_t *envelope, size_t envelope_len,
    int64_t trusted_time,
    sumo_manifest_t **manifest_out)
{
    if (!v || !envelope || !manifest_out) return SUMO_ERR_INVALID_ENVELOPE;

    sumo_manifest_t *m = calloc(1, sizeof(*m));
    if (!m) return SUMO_ERR_OUT_OF_MEMORY;

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
            return SUMO_ERR_AUTH_FAILED;
        if (err == SUIT_ERR_FAILED_TO_VERIFY_DELEGATION)
            return SUMO_ERR_DELEGATION_FAILED;
        return SUMO_ERR_INVALID_ENVELOPE;
    }

    /* Check if any key in the verification chain is revoked */
    if (any_mechanism_revoked(v, m->mechanisms)) {
        free(m);
        return SUMO_ERR_REVOKED;
    }

    /* Anti-rollback: strictly greater than last accepted */
    if (v->has_min_seq && m->envelope.manifest.sequence_number <= v->min_seq) {
        free(m);
        return SUMO_ERR_ROLLBACK_REJECTED;
    }

    /* security_version floor (strict >). Only enforced when the manifest
     * actually declares the parameter — manifests without security_version
     * fall back to the plain sequence-number check above. */
    if (v->has_min_sec_ver) {
        uint64_t sec_ver = 0;
        if (sumo_manifest_security_version(m, 0, &sec_ver) == SUMO_OK &&
            sec_ver <= v->min_sec_ver) {
            free(m);
            return SUMO_ERR_ROLLBACK_REJECTED;
        }
    }

    /* Timestamp-based revocation */
    if (v->reject_before > 0 && trusted_time > 0 &&
        trusted_time < v->reject_before) {
        free(m);
        return SUMO_ERR_REVOKED;
    }

    /* Device identity check (component 0). Two opt-out routes:
     *   - device_id pointer was NULL at create-time → has_device_id == 0,
     *     entire block skipped.
     *   - any individual UUID field is the RFC 4122 nil UUID (all zeros)
     *     → that specific field is treated as "don't care".
     * A field is enforced only when both sides have a non-nil UUID and
     * the manifest actually declares the corresponding condition. */
    if (v->has_device_id) {
        static const uint8_t nil_uuid[16] = {0};
        uint8_t uuid[16];
        if (memcmp(v->device_id.vendor_id, nil_uuid, 16) != 0 &&
            sumo_manifest_vendor_id(m, 0, uuid) == SUMO_OK &&
            memcmp(uuid, v->device_id.vendor_id, 16) != 0) {
            free(m);
            return SUMO_ERR_VENDOR_MISMATCH;
        }
        if (memcmp(v->device_id.class_id, nil_uuid, 16) != 0 &&
            sumo_manifest_class_id(m, 0, uuid) == SUMO_OK &&
            memcmp(uuid, v->device_id.class_id, 16) != 0) {
            free(m);
            return SUMO_ERR_CLASS_MISMATCH;
        }
        if (memcmp(v->device_id.device_id, nil_uuid, 16) != 0 &&
            sumo_manifest_device_id(m, 0, uuid) == SUMO_OK &&
            memcmp(uuid, v->device_id.device_id, 16) != 0) {
            free(m);
            return SUMO_ERR_DEVICE_MISMATCH;
        }
    }

    *manifest_out = m;
    return SUMO_OK;
}

void sumo_validator_free(sumo_validator_t *v)
{
    if (!v) return;
    for (size_t i = 0; i < v->num_trust_anchors; i++) {
        suit_free_key(&v->trust_anchors[i]);
    }
    free(v);
}

/* --- Manifest accessors --- */

uint64_t sumo_manifest_sequence_number(const sumo_manifest_t *m)
{
    if (!m) return 0;
    return m->envelope.manifest.sequence_number;
}

size_t sumo_manifest_component_count(const sumo_manifest_t *m)
{
    if (!m) return 0;
    return m->envelope.manifest.common.components_len;
}

size_t sumo_manifest_dependency_count(const sumo_manifest_t *m)
{
    if (!m) return 0;
    return m->envelope.manifest.common.dependencies.len;
}

int sumo_manifest_is_campaign(const sumo_manifest_t *m)
{
    return sumo_manifest_dependency_count(m) > 0;
}

int sumo_manifest_component_id(
    const sumo_manifest_t *m, size_t index,
    const uint8_t **out, size_t *out_len)
{
    if (!m || !out || !out_len) return SUMO_ERR_INVALID_ENVELOPE;
    if (index >= m->envelope.manifest.common.components_len)
        return SUMO_ERR_INVALID_ENVELOPE;

    *out = m->envelope.manifest.common.components[index].encoded_component.ptr;
    *out_len = m->envelope.manifest.common.components[index].encoded_component.len;
    return SUMO_OK;
}

int sumo_manifest_image_size(
    const sumo_manifest_t *m, size_t component_index,
    uint64_t *size_out)
{
    if (!m || !size_out) return SUMO_ERR_INVALID_ENVELOPE;
    const suit_parameters_t *p =
        find_shared_param(m, component_index, SUIT_PARAMETER_IMAGE_SIZE);
    if (!p) return SUMO_ERR_UNSUPPORTED;
    *size_out = p->value.uint64;
    return SUMO_OK;
}

int sumo_manifest_image_digest(
    const sumo_manifest_t *m, size_t component_index,
    const uint8_t **digest_out, size_t *digest_len_out,
    int *algorithm_out)
{
    if (!m || !digest_out || !digest_len_out) return SUMO_ERR_INVALID_ENVELOPE;
    const suit_parameters_t *p =
        find_shared_param(m, component_index, SUIT_PARAMETER_IMAGE_DIGEST);
    if (!p) return SUMO_ERR_UNSUPPORTED;
    *digest_out = p->value.digest.bytes.ptr;
    *digest_len_out = p->value.digest.bytes.len;
    if (algorithm_out) *algorithm_out = p->value.digest.algorithm_id;
    return SUMO_OK;
}

int sumo_manifest_security_version(
    const sumo_manifest_t *m, size_t component_index,
    uint64_t *out)
{
    if (!m || !out) return SUMO_ERR_INVALID_ENVELOPE;
    const suit_parameters_t *p = find_shared_param(
        m, component_index, SUMO_PARAMETER_SECURITY_VERSION);
    if (!p) return SUMO_ERR_UNSUPPORTED;
    *out = p->value.uint64;
    return SUMO_OK;
}

/* --- Shared-sequence parameter helpers --- */

/*
 * Search shared_seq commands for a parameter with the given label
 * targeting the given component index. The shared sequence contains
 * SUIT_DIRECTIVE_OVERRIDE_PARAMETERS / SET_PARAMETERS commands,
 * each carrying a params_list with an index and param entries.
 */
static const suit_parameters_t *find_shared_param(
    const sumo_manifest_t *m, size_t component_index, int64_t param_label)
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
    const sumo_manifest_t *m, size_t component_index,
    int64_t param_label, uint8_t out[16])
{
    if (!m || !out) return SUMO_ERR_INVALID_ENVELOPE;
    const suit_parameters_t *p = find_shared_param(m, component_index, param_label);
    if (!p || !p->value.string.ptr || p->value.string.len != 16)
        return SUMO_ERR_UNSUPPORTED;
    memcpy(out, p->value.string.ptr, 16);
    return SUMO_OK;
}

int sumo_manifest_vendor_id(
    const sumo_manifest_t *m, size_t component_index,
    uint8_t out[16])
{
    return extract_uuid_param(m, component_index,
                              SUIT_PARAMETER_VENDOR_IDENTIFIER, out);
}

int sumo_manifest_class_id(
    const sumo_manifest_t *m, size_t component_index,
    uint8_t out[16])
{
    return extract_uuid_param(m, component_index,
                              SUIT_PARAMETER_CLASS_IDENTIFIER, out);
}

int sumo_manifest_device_id(
    const sumo_manifest_t *m, size_t component_index,
    uint8_t out[16])
{
    return extract_uuid_param(m, component_index,
                              SUIT_PARAMETER_DEVICE_IDENTIFIER, out);
}

int sumo_manifest_version(
    const sumo_manifest_t *m, size_t component_index,
    sumo_version_cmp_t *cmp_out,
    int64_t *parts_out, size_t *parts_len)
{
    if (!m || !cmp_out || !parts_out || !parts_len)
        return SUMO_ERR_INVALID_ENVELOPE;

    const suit_parameters_t *p = find_shared_param(
        m, component_index, SUIT_PARAMETER_VERSION);
    if (!p || !p->value.string.ptr || p->value.string.len == 0)
        return SUMO_ERR_UNSUPPORTED;

    /* The version parameter is CBOR-encoded suit_version_match_t.
     * Decode it using libcsuit. */
    suit_version_match_t vm;
    memset(&vm, 0, sizeof(vm));
    suit_err_t err = suit_decode_version_match(p->value.string, &vm);
    if (err != SUIT_SUCCESS)
        return SUMO_ERR_INVALID_ENVELOPE;

    *cmp_out = (sumo_version_cmp_t)vm.type;
    size_t count = vm.value.len;
    if (count > *parts_len) count = *parts_len;
    for (size_t i = 0; i < count; i++)
        parts_out[i] = vm.value.int64[i];
    *parts_len = count;
    return SUMO_OK;
}

/* --- Text section accessors --- */

static const suit_text_component_t *find_text_component(
    const sumo_manifest_t *m, size_t component_index)
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
    if (!(m) || !(out) || !(out_len)) return SUMO_ERR_INVALID_ENVELOPE; \
    const suit_text_component_t *tc = find_text_component((m), (ci)); \
    if (!tc || !tc->field_name.ptr || tc->field_name.len == 0) \
        return SUMO_ERR_UNSUPPORTED; \
    *(out) = (const char *)tc->field_name.ptr; \
    *(out_len) = tc->field_name.len; \
    return SUMO_OK; \
} while (0)

int sumo_manifest_text_vendor_name(
    const sumo_manifest_t *m, size_t component_index,
    const char **out, size_t *out_len)
{
    EXTRACT_TEXT_FIELD(m, component_index, vendor_name, out, out_len);
}

int sumo_manifest_text_model_name(
    const sumo_manifest_t *m, size_t component_index,
    const char **out, size_t *out_len)
{
    EXTRACT_TEXT_FIELD(m, component_index, model_name, out, out_len);
}

int sumo_manifest_text_model_info(
    const sumo_manifest_t *m, size_t component_index,
    const char **out, size_t *out_len)
{
    EXTRACT_TEXT_FIELD(m, component_index, model_info, out, out_len);
}

int sumo_manifest_text_version(
    const sumo_manifest_t *m, size_t component_index,
    const char **out, size_t *out_len)
{
    EXTRACT_TEXT_FIELD(m, component_index, component_version, out, out_len);
}

int sumo_manifest_text_description(
    const sumo_manifest_t *m,
    const char **out, size_t *out_len)
{
    if (!m || !out || !out_len) return SUMO_ERR_INVALID_ENVELOPE;
    const suit_text_map_t *tm = &m->envelope.manifest.sev_man_mem.text;
    if (tm->text_lmaps_len == 0)
        return SUMO_ERR_UNSUPPORTED;
    const suit_text_lmap_t *lmap = &tm->text_lmaps[0];
    if (!lmap->manifest_description.ptr || lmap->manifest_description.len == 0)
        return SUMO_ERR_UNSUPPORTED;
    *out = (const char *)lmap->manifest_description.ptr;
    *out_len = lmap->manifest_description.len;
    return SUMO_OK;
}

/*
 * Search a single command sequence (shared / install / payload_fetch
 * / etc) for the given parameter label scoped to the given component.
 * Returns the parameter value's UsefulBufC if found; {NULL,0} otherwise.
 */
static UsefulBufC search_seq_for_param_str(
    const suit_command_sequence_t *seq,
    size_t component_index, int64_t param_label)
{
    UsefulBufC empty = {NULL, 0};
    for (size_t i = 0; i < seq->len; i++) {
        const suit_command_sequence_item_t *cmd = &seq->commands[i];
        if (cmd->label != SUIT_DIRECTIVE_OVERRIDE_PARAMETERS &&
            cmd->label != SUIT_DIRECTIVE_SET_PARAMETERS)
            continue;
        const suit_parameters_list_t *pl = &cmd->value.params_list;
        if (pl->index != (uint8_t)component_index) continue;
        for (size_t j = 0; j < pl->len; j++) {
            if (pl->params[j].label == param_label)
                return pl->params[j].value.string;
        }
    }
    return empty;
}

int sumo_manifest_encryption_info(
    const sumo_manifest_t *m, size_t component_index,
    const uint8_t **out_data, size_t *out_len)
{
    if (!m || !out_data || !out_len) return SUMO_ERR_INVALID_ENVELOPE;

    /* The encryption_info parameter (label 19) can appear in any of the
     * three sequences sumo-tool may emit it into: shared (most common
     * for static, single-payload images), install (per-component
     * install-time override), payload_fetch (per-fetch override). Match
     * the search order in libsumo's decryptor.c so a fixture that
     * passes there also passes here. */
    const suit_manifest_t *man = &m->envelope.manifest;
    UsefulBufC v;

    v = search_seq_for_param_str(&man->common.shared_seq,
                                 component_index,
                                 SUIT_PARAMETER_ENCRYPTION_INFO);
    if (v.ptr) goto found;

    v = search_seq_for_param_str(&man->sev_man_mem.install,
                                 component_index,
                                 SUIT_PARAMETER_ENCRYPTION_INFO);
    if (v.ptr) goto found;

    v = search_seq_for_param_str(&man->sev_man_mem.payload_fetch,
                                 component_index,
                                 SUIT_PARAMETER_ENCRYPTION_INFO);
    if (!v.ptr) return SUMO_ERR_UNSUPPORTED;

found:
    *out_data = v.ptr;
    *out_len  = v.len;
    return SUMO_OK;
}

void sumo_manifest_free(sumo_manifest_t *m)
{
    free(m);
}
