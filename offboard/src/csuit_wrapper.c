/**
 * @file csuit_wrapper.c
 * @brief C translation unit that includes libcsuit headers.
 *
 * Compiled as C (not C++), avoiding the `delete` keyword conflict.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "csuit_wrapper.h"

#include "csuit/csuit.h"
#include "csuit/suit_manifest_encode.h"
#include "csuit/suit_cose.h"
#include "qcbor/qcbor_encode.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

#define ENCODE_BUF_SIZE 8192

/* --- Envelope builder --- */

struct sum2_envelope_builder {
    /* Stored values — must outlive the envelope struct */
    uint8_t component_cbor[128];
    size_t component_cbor_len;
    char uri[256];
    uint8_t enc_info[512];
    size_t enc_info_len;
    uint8_t vendor_id[16];
    uint8_t class_id[16];
    uint8_t image_digest[32];
    uint64_t image_size;
    uint64_t sequence_number;

    int has_component;
    int has_vendor_id;
    int has_class_id;
    int has_digest;
    int has_uri;
    int has_enc_info;
};

sum2_envelope_builder_t *sum2_eb_create(void)
{
    return calloc(1, sizeof(sum2_envelope_builder_t));
}

void sum2_eb_free(sum2_envelope_builder_t *b)
{
    free(b);
}

int sum2_eb_set_sequence_number(sum2_envelope_builder_t *b, uint64_t seq)
{
    if (!b) return -1;
    b->sequence_number = seq;
    return 0;
}

int sum2_eb_add_component(sum2_envelope_builder_t *b,
                          const char *const *segments, size_t num_segments)
{
    if (!b || !segments || num_segments == 0) return -1;

    UsefulBuf buf = {b->component_cbor, sizeof(b->component_cbor)};
    QCBOREncodeContext ctx;
    QCBOREncode_Init(&ctx, buf);
    QCBOREncode_OpenArray(&ctx);
    for (size_t i = 0; i < num_segments; i++) {
        UsefulBufC seg = {(const uint8_t *)segments[i], strlen(segments[i])};
        QCBOREncode_AddBytes(&ctx, seg);
    }
    QCBOREncode_CloseArray(&ctx);

    UsefulBufC encoded;
    if (QCBOREncode_Finish(&ctx, &encoded) != QCBOR_SUCCESS)
        return -1;

    b->component_cbor_len = encoded.len;
    b->has_component = 1;
    return 0;
}

int sum2_eb_set_vendor_id(sum2_envelope_builder_t *b, const uint8_t uuid[16])
{
    if (!b || !uuid) return -1;
    memcpy(b->vendor_id, uuid, 16);
    b->has_vendor_id = 1;
    return 0;
}

int sum2_eb_set_class_id(sum2_envelope_builder_t *b, const uint8_t uuid[16])
{
    if (!b || !uuid) return -1;
    memcpy(b->class_id, uuid, 16);
    b->has_class_id = 1;
    return 0;
}

int sum2_eb_set_image_digest_sha256(sum2_envelope_builder_t *b,
                                     const uint8_t digest[32],
                                     uint64_t image_size)
{
    if (!b || !digest) return -1;
    memcpy(b->image_digest, digest, 32);
    b->image_size = image_size;
    b->has_digest = 1;
    return 0;
}

int sum2_eb_set_payload_uri(sum2_envelope_builder_t *b, const char *uri)
{
    if (!b || !uri) return -1;
    size_t len = strlen(uri);
    if (len >= sizeof(b->uri)) return -1;
    memcpy(b->uri, uri, len + 1);
    b->has_uri = 1;
    return 0;
}

int sum2_eb_set_encryption_info(sum2_envelope_builder_t *b,
                                 const uint8_t *info, size_t info_len)
{
    if (!b || !info || info_len > sizeof(b->enc_info)) return -1;
    memcpy(b->enc_info, info, info_len);
    b->enc_info_len = info_len;
    b->has_enc_info = 1;
    return 0;
}

/**
 * Assemble the suit_envelope_t from builder state and encode it.
 */
int sum2_eb_encode(sum2_envelope_builder_t *b,
                   const uint8_t *cose_key_cbor, size_t key_len,
                   int cose_tag, int algorithm,
                   uint8_t *out, size_t out_size, size_t *out_len)
{
    if (!b || !cose_key_cbor || !out || !out_len) return -1;

    suit_envelope_t env = {0};
    suit_manifest_t *man = &env.manifest;
    man->version = 1;
    man->sequence_number = b->sequence_number;

    /* Component */
    if (b->has_component) {
        man->common.components_len = 1;
        man->common.components[0].encoded_component.ptr = b->component_cbor;
        man->common.components[0].encoded_component.len = b->component_cbor_len;
    }

    /* --- Shared sequence: override-parameters + conditions --- */
    suit_command_sequence_t *shared = &man->common.shared_seq;
    size_t cmd_idx = 0;

    /* override-parameters block */
    shared->commands[cmd_idx].label = SUIT_DIRECTIVE_OVERRIDE_PARAMETERS;
    suit_parameters_list_t *pl = &shared->commands[cmd_idx].value.params_list;
    pl->index = 0;
    size_t p_idx = 0;

    if (b->has_vendor_id) {
        pl->params[p_idx].label = SUIT_CONDITION_VENDOR_IDENTIFIER;
        pl->params[p_idx].value.string.ptr = b->vendor_id;
        pl->params[p_idx].value.string.len = 16;
        p_idx++;
    }
    if (b->has_class_id) {
        pl->params[p_idx].label = SUIT_CONDITION_CLASS_IDENTIFIER;
        pl->params[p_idx].value.string.ptr = b->class_id;
        pl->params[p_idx].value.string.len = 16;
        p_idx++;
    }
    if (b->has_digest) {
        pl->params[p_idx].label = SUIT_PARAMETER_IMAGE_DIGEST;
        pl->params[p_idx].value.digest.algorithm_id = SUIT_ALGORITHM_ID_SHA256;
        pl->params[p_idx].value.digest.bytes.ptr = b->image_digest;
        pl->params[p_idx].value.digest.bytes.len = 32;
        p_idx++;

        pl->params[p_idx].label = SUIT_PARAMETER_IMAGE_SIZE;
        pl->params[p_idx].value.uint64 = b->image_size;
        p_idx++;
    }
    pl->len = p_idx;
    cmd_idx++;

    /* condition-vendor-identifier */
    if (b->has_vendor_id) {
        shared->commands[cmd_idx].label = SUIT_CONDITION_VENDOR_IDENTIFIER;
        shared->commands[cmd_idx].value.uint64 = 15;
        cmd_idx++;
    }
    /* condition-class-identifier */
    if (b->has_class_id) {
        shared->commands[cmd_idx].label = SUIT_CONDITION_CLASS_IDENTIFIER;
        shared->commands[cmd_idx].value.uint64 = 15;
        cmd_idx++;
    }
    shared->len = cmd_idx;

    /* --- Install sequence --- */
    man->sev_man_mem.install_status = SUIT_SEVERABLE_IN_MANIFEST;
    suit_command_sequence_t *install = &man->sev_man_mem.install;
    size_t inst_idx = 0;

    /* set-parameters: uri */
    if (b->has_uri) {
        install->commands[inst_idx].label = SUIT_DIRECTIVE_SET_PARAMETERS;
        suit_parameters_list_t *ipl = &install->commands[inst_idx].value.params_list;
        ipl->index = 0;
        ipl->len = 1;
        ipl->params[0].label = SUIT_PARAMETER_URI;
        ipl->params[0].value.string.ptr = (const uint8_t *)b->uri;
        ipl->params[0].value.string.len = strlen(b->uri);
        inst_idx++;
    }

    /* set-parameters: encryption-info */
    if (b->has_enc_info) {
        install->commands[inst_idx].label = SUIT_DIRECTIVE_SET_PARAMETERS;
        suit_parameters_list_t *ipl = &install->commands[inst_idx].value.params_list;
        ipl->index = 0;
        ipl->len = 1;
        ipl->params[0].label = SUIT_PARAMETER_ENCRYPTION_INFO;
        ipl->params[0].value.string.ptr = b->enc_info;
        ipl->params[0].value.string.len = b->enc_info_len;
        inst_idx++;
    }

    /* directive-fetch */
    install->commands[inst_idx].label = SUIT_DIRECTIVE_FETCH;
    install->commands[inst_idx].value.uint64 = 15;
    inst_idx++;

    /* condition-image-match */
    install->commands[inst_idx].label = SUIT_CONDITION_IMAGE_MATCH;
    install->commands[inst_idx].value.uint64 = 15;
    inst_idx++;

    install->len = inst_idx;

    /* --- Validate sequence --- */
    suit_command_sequence_t *validate = &man->unsev_mem.validate;
    validate->len = 1;
    validate->commands[0].label = SUIT_CONDITION_IMAGE_MATCH;
    validate->commands[0].value.uint64 = 15;

    /* --- Initialize encoder --- */
    suit_encoder_context_t *enc_ctx =
        malloc(sizeof(suit_encoder_context_t) + ENCODE_BUF_SIZE);
    if (!enc_ctx) return -1;

    suit_err_t err = suit_encode_init(enc_ctx, ENCODE_BUF_SIZE);
    if (err != SUIT_SUCCESS) { free(enc_ctx); return (int)err; }

    /* Load signing/MAC key */
    suit_key_t sender_key = {0};
    UsefulBufC key_buf = {cose_key_cbor, key_len};
    err = suit_set_suit_key_from_cose_key(key_buf, &sender_key);
    if (err != SUIT_SUCCESS) { free(enc_ctx); return (int)err; }

    err = suit_encode_add_sender_key(enc_ctx, cose_tag, algorithm, &sender_key);
    if (err != SUIT_SUCCESS) { suit_free_key(&sender_key); free(enc_ctx); return (int)err; }

    /* Encode envelope */
    UsefulBufC encoded;
    err = suit_encode_envelope(enc_ctx, &env, &encoded);
    if (err != SUIT_SUCCESS) { suit_free_key(&sender_key); free(enc_ctx); return (int)err; }

    if (encoded.len > out_size) {
        suit_free_key(&sender_key);
        free(enc_ctx);
        return -1;
    }
    memcpy(out, encoded.ptr, encoded.len);
    *out_len = encoded.len;

    suit_free_key(&sender_key);
    free(enc_ctx);
    return 0;
}

/* --- Encryption --- */

int sum2_encrypt_a128kw(
    const uint8_t *plaintext, size_t pt_len,
    const uint8_t *kek_cose_key, size_t kek_len,
    uint8_t *ct_out, size_t ct_out_size, size_t *ct_out_len,
    uint8_t *ei_out, size_t ei_out_size, size_t *ei_out_len)
{
    if (!plaintext || !kek_cose_key || !ct_out || !ei_out) return -1;

    suit_mechanism_t mechanism = {0};
    mechanism.key.cose_algorithm_id = T_COSE_ALGORITHM_A128KW;
    UsefulBufC key_buf = {kek_cose_key, kek_len};
    suit_err_t err = suit_set_suit_key_from_cose_key(key_buf, &mechanism.key);
    if (err != SUIT_SUCCESS) return (int)err;
    mechanism.cose_tag = CBOR_TAG_COSE_ENCRYPT;
    mechanism.use = true;

    UsefulBufC pt = {plaintext, pt_len};
    UsefulBuf ct_buf = {ct_out, ct_out_size};
    UsefulBuf ei_buf = {ei_out, ei_out_size};
    UsefulBufC encrypted_payload;
    UsefulBufC encryption_info;

    err = suit_encrypt_cose_encrypt(pt, &mechanism,
                                     ct_buf, ei_buf,
                                     &encrypted_payload,
                                     &encryption_info);
    if (err != SUIT_SUCCESS) return (int)err;

    *ct_out_len = encrypted_payload.len;
    *ei_out_len = encryption_info.len;
    return 0;
}

/* --- ECDH-ES+A128KW Encryption --- */

int sum2_encrypt_esdh(
    const uint8_t *plaintext, size_t pt_len,
    const uint8_t *sender_cose_key, size_t sender_key_len,
    const uint8_t *recv_cose_key, size_t recv_key_len,
    const uint8_t *recv_kid, size_t recv_kid_len,
    uint8_t *ct_out, size_t ct_out_size, size_t *ct_out_len,
    uint8_t *ei_out, size_t ei_out_size, size_t *ei_out_len)
{
    if (!plaintext || !sender_cose_key || !recv_cose_key || !ct_out || !ei_out)
        return -1;

    suit_mechanism_t mechanism = {0};

    /* Load sender's private key */
    UsefulBufC sender_buf = {sender_cose_key, sender_key_len};
    suit_err_t err = suit_set_suit_key_from_cose_key(sender_buf, &mechanism.key);
    if (err != SUIT_SUCCESS) return (int)err;

    /* Load receiver's public key */
    UsefulBufC recv_buf = {recv_cose_key, recv_key_len};
    err = suit_set_suit_key_from_cose_key(recv_buf, &mechanism.rkey);
    if (err != SUIT_SUCCESS) {
        suit_free_key(&mechanism.key);
        return (int)err;
    }

    /* Set receiver's kid */
    mechanism.rkid.ptr = recv_kid;
    mechanism.rkid.len = recv_kid_len;
    mechanism.cose_tag = CBOR_TAG_COSE_ENCRYPT;
    mechanism.use = true;

    UsefulBufC pt = {plaintext, pt_len};
    UsefulBuf ct_buf = {ct_out, ct_out_size};
    UsefulBuf ei_buf = {ei_out, ei_out_size};
    UsefulBufC encrypted_payload;
    UsefulBufC encryption_info;

    err = suit_encrypt_cose_encrypt(pt, &mechanism,
                                     ct_buf, ei_buf,
                                     &encrypted_payload,
                                     &encryption_info);

    suit_free_key(&mechanism.key);
    suit_free_key(&mechanism.rkey);

    if (err != SUIT_SUCCESS) return (int)err;

    *ct_out_len = encrypted_payload.len;
    *ei_out_len = encryption_info.len;
    return 0;
}

/* --- Campaign builder --- */

int sum2_eb_encode_campaign(
    uint64_t seq,
    const uint8_t *vendor_id,
    const uint8_t *class_id,
    const sum2_campaign_dep_t *deps, size_t num_deps,
    const uint8_t *cose_key_cbor, size_t key_len,
    int cose_tag, int algorithm,
    uint8_t *out, size_t out_size, size_t *out_len)
{
    if (!deps || num_deps == 0 || !cose_key_cbor || !out || !out_len)
        return -1;

    suit_envelope_t env = {0};
    suit_manifest_t *man = &env.manifest;
    man->version = 1;
    man->sequence_number = seq;

    /* Dependencies — each needs a CBOR-encoded component identifier prefix.
     * We build a minimal prefix [h'XX'] (CBOR: 81 41 XX) for each dep. */
    uint8_t dep_prefix_bufs[SUIT_MAX_ARRAY_LENGTH][3];
    man->common.dependencies.len = num_deps;
    for (size_t i = 0; i < num_deps; i++) {
        /* Dependency indices must be > 0 (libcsuit decoder requirement).
         * Index 0 is reserved for the main component. */
        uint8_t dep_idx = (uint8_t)(i + 1);
        man->common.dependencies.dependency[i].index = dep_idx;
        dep_prefix_bufs[i][0] = 0x81; /* array(1) */
        dep_prefix_bufs[i][1] = 0x41; /* bstr(1) */
        dep_prefix_bufs[i][2] = dep_idx;
        man->common.dependencies.dependency[i].dependency_metadata.prefix.ptr = dep_prefix_bufs[i];
        man->common.dependencies.dependency[i].dependency_metadata.prefix.len = 3;
    }

    /* Shared sequence: override-parameters + conditions for campaign */
    suit_command_sequence_t *shared = &man->common.shared_seq;
    size_t cmd_idx = 0;

    if (vendor_id || class_id) {
        shared->commands[cmd_idx].label = SUIT_DIRECTIVE_OVERRIDE_PARAMETERS;
        suit_parameters_list_t *pl = &shared->commands[cmd_idx].value.params_list;
        pl->index = 0;
        size_t p_idx = 0;

        if (vendor_id) {
            pl->params[p_idx].label = SUIT_CONDITION_VENDOR_IDENTIFIER;
            pl->params[p_idx].value.string.ptr = vendor_id;
            pl->params[p_idx].value.string.len = 16;
            p_idx++;
        }
        if (class_id) {
            pl->params[p_idx].label = SUIT_CONDITION_CLASS_IDENTIFIER;
            pl->params[p_idx].value.string.ptr = class_id;
            pl->params[p_idx].value.string.len = 16;
            p_idx++;
        }
        pl->len = p_idx;
        cmd_idx++;
    }

    if (vendor_id) {
        shared->commands[cmd_idx].label = SUIT_CONDITION_VENDOR_IDENTIFIER;
        shared->commands[cmd_idx].value.uint64 = 15;
        cmd_idx++;
    }
    if (class_id) {
        shared->commands[cmd_idx].label = SUIT_CONDITION_CLASS_IDENTIFIER;
        shared->commands[cmd_idx].value.uint64 = 15;
        cmd_idx++;
    }
    shared->len = cmd_idx;

    /* Dependency resolution sequence:
     * For each dependency: set-params(uri, digest) + fetch + check-integrity */
    man->sev_man_mem.dependency_resolution_status = SUIT_SEVERABLE_IN_MANIFEST;
    suit_command_sequence_t *dep_res = &man->sev_man_mem.dependency_resolution;
    size_t dr_idx = 0;

    for (size_t i = 0; i < num_deps; i++) {
        /* set-component-index to target this dependency */
        dep_res->commands[dr_idx].label = SUIT_DIRECTIVE_SET_COMPONENT_INDEX;
        dep_res->commands[dr_idx].value.index_arg.len = 1;
        dep_res->commands[dr_idx].value.index_arg.index[0] = (uint8_t)(i + 1);
        dr_idx++;

        /* set-parameters: uri + image-digest */
        dep_res->commands[dr_idx].label = SUIT_DIRECTIVE_SET_PARAMETERS;
        suit_parameters_list_t *pl = &dep_res->commands[dr_idx].value.params_list;
        pl->index = (uint8_t)(i + 1);
        pl->len = 2;

        /* Parameters must be in ascending label order (canonical CBOR) */
        pl->params[0].label = SUIT_PARAMETER_IMAGE_DIGEST; /* 3 */
        pl->params[0].value.digest.algorithm_id = SUIT_ALGORITHM_ID_SHA256;
        pl->params[0].value.digest.bytes.ptr = deps[i].digest;
        pl->params[0].value.digest.bytes.len = 32;

        pl->params[1].label = SUIT_PARAMETER_URI; /* 21 */
        pl->params[1].value.string.ptr = (const uint8_t *)deps[i].fetch_uri;
        pl->params[1].value.string.len = deps[i].fetch_uri_len;
        dr_idx++;

        /* directive-fetch */
        dep_res->commands[dr_idx].label = SUIT_DIRECTIVE_FETCH;
        dep_res->commands[dr_idx].value.uint64 = 15;
        dr_idx++;

        /* condition-dependency-integrity */
        dep_res->commands[dr_idx].label = SUIT_CONDITION_DEPENDENCY_INTEGRITY;
        dep_res->commands[dr_idx].value.uint64 = 15;
        dr_idx++;
    }
    dep_res->len = dr_idx;

    /* Install sequence: process-dependency for each */
    man->sev_man_mem.install_status = SUIT_SEVERABLE_IN_MANIFEST;
    suit_command_sequence_t *install = &man->sev_man_mem.install;
    size_t inst_idx = 0;

    for (size_t i = 0; i < num_deps; i++) {
        install->commands[inst_idx].label = SUIT_DIRECTIVE_PROCESS_DEPENDENCY;
        install->commands[inst_idx].value.uint64 = (uint8_t)(i + 1);
        inst_idx++;
    }
    install->len = inst_idx;

    /* Validate sequence: dependency-integrity for each */
    suit_command_sequence_t *validate = &man->unsev_mem.validate;
    size_t val_idx = 0;
    for (size_t i = 0; i < num_deps; i++) {
        validate->commands[val_idx].label = SUIT_CONDITION_DEPENDENCY_INTEGRITY;
        validate->commands[val_idx].value.uint64 = 15;
        val_idx++;
    }
    validate->len = val_idx;

    /* Integrated payloads */
    size_t ip_idx = 0;
    for (size_t i = 0; i < num_deps; i++) {
        if (deps[i].is_integrated && deps[i].payload && deps[i].payload_len > 0) {
            env.payloads.payload[ip_idx].key.ptr =
                (const uint8_t *)deps[i].fetch_uri;
            env.payloads.payload[ip_idx].key.len = deps[i].fetch_uri_len;
            env.payloads.payload[ip_idx].bytes.ptr = deps[i].payload;
            env.payloads.payload[ip_idx].bytes.len = deps[i].payload_len;
            ip_idx++;
        }
    }
    env.payloads.len = ip_idx;

    /* Encode + sign */
    suit_encoder_context_t *enc_ctx =
        malloc(sizeof(suit_encoder_context_t) + ENCODE_BUF_SIZE);
    if (!enc_ctx) return -1;

    suit_err_t err = suit_encode_init(enc_ctx, ENCODE_BUF_SIZE);
    if (err != SUIT_SUCCESS) { free(enc_ctx); return (int)err; }

    suit_key_t sender_key = {0};
    UsefulBufC key_buf = {cose_key_cbor, key_len};
    err = suit_set_suit_key_from_cose_key(key_buf, &sender_key);
    if (err != SUIT_SUCCESS) { free(enc_ctx); return (int)err; }

    err = suit_encode_add_sender_key(enc_ctx, cose_tag, algorithm, &sender_key);
    if (err != SUIT_SUCCESS) { suit_free_key(&sender_key); free(enc_ctx); return (int)err; }

    UsefulBufC encoded;
    err = suit_encode_envelope(enc_ctx, &env, &encoded);
    if (err != SUIT_SUCCESS) { suit_free_key(&sender_key); free(enc_ctx); return (int)err; }

    if (encoded.len > out_size) {
        suit_free_key(&sender_key);
        free(enc_ctx);
        return -1;
    }
    memcpy(out, encoded.ptr, encoded.len);
    *out_len = encoded.len;

    suit_free_key(&sender_key);
    free(enc_ctx);
    return 0;
}

/* --- SHA-256 --- */

int sum2_sha256(const uint8_t *data, size_t data_len, uint8_t digest[32])
{
    if (!data || !digest) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1
          && EVP_DigestUpdate(ctx, data, data_len) == 1
          && EVP_DigestFinal_ex(ctx, digest, NULL) == 1;
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}
