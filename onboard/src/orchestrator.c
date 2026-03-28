/**
 * @file orchestrator.c
 * @brief Two-level manifest orchestration.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sumo/orchestrator.h"
#include "sumo/decryptor.h"
#include "sumo/decompressor.h"
#include "sumo_internal.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

/* libcsuit headers (for manifest struct access) */
#include "csuit/csuit.h"

/* Default streaming chunk size (4KB) */
#define SUMO_CHUNK_SIZE 4096

/* zstd magic bytes */
static const uint8_t ZSTD_MAGIC[4] = {0x28, 0xB5, 0x2F, 0xFD};

/* --- Helpers to search command sequences for parameters --- */

static UsefulBufC search_cmd_seq_param(
    const suit_command_sequence_t *seq,
    size_t component_index, int64_t param_label)
{
    UsefulBufC empty = {NULL, 0};
    size_t current_index = 0; /* track via SET_COMPONENT_INDEX directives */
    for (size_t i = 0; i < seq->len; i++) {
        const suit_command_sequence_item_t *cmd = &seq->commands[i];

        /* Track component index changes */
        if (cmd->label == SUIT_DIRECTIVE_SET_COMPONENT_INDEX) {
            if (cmd->value.index_arg.len > 0)
                current_index = cmd->value.index_arg.index[0];
            continue;
        }

        if (cmd->label != SUIT_DIRECTIVE_OVERRIDE_PARAMETERS &&
            cmd->label != SUIT_DIRECTIVE_SET_PARAMETERS)
            continue;

        const suit_parameters_list_t *pl = &cmd->value.params_list;
        if (current_index != component_index)
            continue;

        for (size_t j = 0; j < pl->len; j++) {
            if (pl->params[j].label == param_label)
                return pl->params[j].value.string;
        }
    }
    return empty;
}

static UsefulBufC find_payload_uri(
    const sumo_manifest_t *m, size_t component_index)
{
    const suit_manifest_t *man = &m->envelope.manifest;
    UsefulBufC result;

    /* Check install sequence first */
    result = search_cmd_seq_param(&man->sev_man_mem.install,
                                   component_index, SUIT_PARAMETER_URI);
    if (result.ptr) return result;

    /* Check payload_fetch sequence */
    result = search_cmd_seq_param(&man->sev_man_mem.payload_fetch,
                                   component_index, SUIT_PARAMETER_URI);
    if (result.ptr) return result;

    /* Check shared sequence */
    result = search_cmd_seq_param(&man->common.shared_seq,
                                   component_index, SUIT_PARAMETER_URI);
    return result;
}

/* --- process_image implementation --- */

int sumo_process_image(
    sumo_validator_t *v,
    const sumo_manifest_t *image,
    const sumo_platform_ops_t *ops)
{
    if (!v || !image || !ops) return SUMO_ERR_INVALID_ENVELOPE;

    /* 1. Extract component ID */
    const uint8_t *comp_id = NULL;
    size_t comp_id_len = 0;
    if (sumo_manifest_component_id(image, 0, &comp_id, &comp_id_len) != SUMO_OK)
        return SUMO_ERR_INVALID_ENVELOPE;

    /* 2. Extract payload URI */
    UsefulBufC uri = find_payload_uri(image, 0);
    if (!uri.ptr || uri.len == 0)
        return SUMO_ERR_INVALID_ENVELOPE;

    /* 3. Get expected digest and size */
    const uint8_t *expected_digest = NULL;
    size_t digest_len = 0;
    int digest_alg = 0;
    if (sumo_manifest_image_digest(image, 0, &expected_digest, &digest_len, &digest_alg) != SUMO_OK)
        return SUMO_ERR_INVALID_ENVELOPE;

    uint64_t expected_size = 0;
    sumo_manifest_image_size(image, 0, &expected_size);

    /* 4. Fetch payload */
    size_t fetch_buf_size = expected_size + 256; /* room for GCM tag + overhead */
    if (fetch_buf_size < 4096) fetch_buf_size = 4096;
    /* For very large payloads, allow 2x expected size for encrypted+compressed */
    if (expected_size > 0 && fetch_buf_size < expected_size * 2 + 256)
        fetch_buf_size = expected_size * 2 + 256;

    uint8_t *payload = malloc(fetch_buf_size);
    if (!payload) return SUMO_ERR_OUT_OF_MEMORY;

    size_t fetched = 0;
    int rc = ops->fetch((const char *)uri.ptr, uri.len,
                        payload, fetch_buf_size, &fetched,
                        ops->user_ctx);
    if (rc != 0) {
        free(payload);
        return SUMO_ERR_CALLBACK_FAILED;
    }

    /* 5. Create decryptor (if encryption info exists) */
    const uint8_t *device_key = NULL;
    size_t dk_len = 0;
    sumo_validator_get_device_key(v, &device_key, &dk_len);

    sumo_decryptor_t *dec = NULL;
    if (device_key && dk_len > 0) {
        dec = sumo_decryptor_create(image, 0, device_key, dk_len);
    }

    /* 6. Process payload: decrypt → detect zstd → decompress → write */
    EVP_MD_CTX *hash_ctx = EVP_MD_CTX_new();
    if (!hash_ctx) {
        if (dec) sumo_decryptor_free(dec);
        free(payload);
        return SUMO_ERR_OUT_OF_MEMORY;
    }
    EVP_DigestInit_ex(hash_ctx, EVP_sha256(), NULL);

    size_t write_offset = 0;
    int result = SUMO_OK;

    if (dec) {
        /* Encrypted payload — stream-decrypt */
        uint8_t pt_buf[SUMO_CHUNK_SIZE + 128]; /* decrypted chunk buffer */
        sumo_decompressor_t *decomp = NULL;
        int first_chunk = 1;

        size_t pos = 0;
        while (pos < fetched) {
            size_t chunk = fetched - pos;
            if (chunk > SUMO_CHUNK_SIZE) chunk = SUMO_CHUNK_SIZE;

            size_t pt_len = sizeof(pt_buf);
            rc = sumo_decryptor_update(dec, payload + pos, chunk,
                                       pt_buf, &pt_len);
            if (rc != 0) {
                result = SUMO_ERR_DECRYPT_FAILED;
                break;
            }
            pos += chunk;

            if (pt_len == 0) continue;

            /* On first output chunk, detect zstd */
            if (first_chunk && pt_len >= 4 &&
                memcmp(pt_buf, ZSTD_MAGIC, 4) == 0) {
                decomp = sumo_decompressor_create();
            }
            first_chunk = 0;

            if (decomp) {
                /* Decompress then write */
                size_t in_consumed = pt_len;
                uint8_t decomp_buf[SUMO_CHUNK_SIZE * 4];

                while (in_consumed > 0) {
                    size_t in_left = in_consumed;
                    size_t out_avail = sizeof(decomp_buf);
                    rc = sumo_decompressor_update(decomp,
                        pt_buf + (pt_len - in_consumed), &in_left,
                        decomp_buf, &out_avail);
                    if (rc != 0) {
                        result = SUMO_ERR_DECRYPT_FAILED;
                        break;
                    }
                    in_consumed -= in_left;

                    if (out_avail > 0) {
                        EVP_DigestUpdate(hash_ctx, decomp_buf, out_avail);
                        rc = ops->write(comp_id, comp_id_len, write_offset,
                                       decomp_buf, out_avail, ops->user_ctx);
                        if (rc != 0) {
                            result = SUMO_ERR_CALLBACK_FAILED;
                            break;
                        }
                        write_offset += out_avail;
                    }

                    if (in_consumed == 0) break;
                }

                /* Drain any remaining decompressed data */
                if (result == SUMO_OK) {
                    for (;;) {
                        size_t zero_in = 0;
                        size_t out_avail = sizeof(decomp_buf);
                        rc = sumo_decompressor_update(decomp,
                            NULL, &zero_in, decomp_buf, &out_avail);
                        if (out_avail == 0 || rc != 0) break;

                        EVP_DigestUpdate(hash_ctx, decomp_buf, out_avail);
                        rc = ops->write(comp_id, comp_id_len, write_offset,
                                       decomp_buf, out_avail, ops->user_ctx);
                        if (rc != 0) {
                            result = SUMO_ERR_CALLBACK_FAILED;
                            break;
                        }
                        write_offset += out_avail;
                    }
                }
            } else {
                /* No compression — write decrypted directly */
                EVP_DigestUpdate(hash_ctx, pt_buf, pt_len);
                rc = ops->write(comp_id, comp_id_len, write_offset,
                               pt_buf, pt_len, ops->user_ctx);
                if (rc != 0) {
                    result = SUMO_ERR_CALLBACK_FAILED;
                    break;
                }
                write_offset += pt_len;
            }

            if (result != SUMO_OK) break;
        }

        /* Finalize decryption (verify GCM tag) */
        if (result == SUMO_OK) {
            uint8_t final_buf[128];
            size_t final_len = sizeof(final_buf);
            rc = sumo_decryptor_finalize(dec, final_buf, &final_len);
            if (rc != 0) {
                result = SUMO_ERR_DECRYPT_FAILED;
            } else if (final_len > 0) {
                if (decomp) {
                    /* Decompress final bytes */
                    uint8_t decomp_buf[SUMO_CHUNK_SIZE];
                    size_t in_left = final_len;
                    size_t out_avail = sizeof(decomp_buf);
                    sumo_decompressor_update(decomp,
                        final_buf, &in_left, decomp_buf, &out_avail);
                    if (out_avail > 0) {
                        EVP_DigestUpdate(hash_ctx, decomp_buf, out_avail);
                        ops->write(comp_id, comp_id_len, write_offset,
                                  decomp_buf, out_avail, ops->user_ctx);
                        write_offset += out_avail;
                    }
                } else {
                    EVP_DigestUpdate(hash_ctx, final_buf, final_len);
                    ops->write(comp_id, comp_id_len, write_offset,
                              final_buf, final_len, ops->user_ctx);
                    write_offset += final_len;
                }
            }
        }

        if (decomp) sumo_decompressor_free(decomp);
        sumo_decryptor_free(dec);
    } else {
        /* Unencrypted payload — hash and write directly */
        size_t pos = 0;
        while (pos < fetched && result == SUMO_OK) {
            size_t chunk = fetched - pos;
            if (chunk > SUMO_CHUNK_SIZE) chunk = SUMO_CHUNK_SIZE;

            EVP_DigestUpdate(hash_ctx, payload + pos, chunk);
            rc = ops->write(comp_id, comp_id_len, write_offset,
                           payload + pos, chunk, ops->user_ctx);
            if (rc != 0) {
                result = SUMO_ERR_CALLBACK_FAILED;
                break;
            }
            write_offset += chunk;
            pos += chunk;
        }
    }

    free(payload);

    /* 7. Verify digest */
    if (result == SUMO_OK) {
        uint8_t computed_digest[32];
        EVP_DigestFinal_ex(hash_ctx, computed_digest, NULL);

        if (digest_len != 32 ||
            memcmp(computed_digest, expected_digest, 32) != 0) {
            result = SUMO_ERR_DIGEST_MISMATCH;
        }
    }

    EVP_MD_CTX_free(hash_ctx);

    /* 8. Persist sequence number on success */
    if (result == SUMO_OK && ops->persist_sequence) {
        uint64_t seq = sumo_manifest_sequence_number(image);
        ops->persist_sequence(comp_id, comp_id_len, seq, ops->user_ctx);
    }

    return result;
}

/* --- process_campaign implementation --- */

int sumo_process_campaign(
    sumo_validator_t *v,
    const sumo_manifest_t *campaign,
    const sumo_platform_ops_t *ops)
{
    if (!v || !campaign || !ops) return SUMO_ERR_INVALID_ENVELOPE;
    if (!sumo_manifest_is_campaign(campaign)) return SUMO_ERR_INVALID_ENVELOPE;

    size_t dep_count = sumo_manifest_dependency_count(campaign);
    const suit_manifest_t *man = &campaign->envelope.manifest;

    for (size_t i = 0; i < dep_count; i++) {
        /* Get the actual dependency index from the dependencies array */
        size_t dep_idx = man->common.dependencies.dependency[i].index;

        /* Extract URI for this dependency from dependency-resolution sequence */
        UsefulBufC dep_uri = search_cmd_seq_param(
            &man->sev_man_mem.dependency_resolution,
            dep_idx, SUIT_PARAMETER_URI);

        /* Also check install sequence for the dependency URI */
        if (!dep_uri.ptr) {
            dep_uri = search_cmd_seq_param(
                &man->sev_man_mem.install,
                dep_idx, SUIT_PARAMETER_URI);
        }

        if (!dep_uri.ptr || dep_uri.len == 0)
            return SUMO_ERR_INVALID_ENVELOPE;

        /* Check for integrated payload (URI starts with '#') */
        const uint8_t *l2_data = NULL;
        size_t l2_len = 0;
        uint8_t *fetched_l2 = NULL;

        if (dep_uri.len > 0 && ((const char *)dep_uri.ptr)[0] == '#') {
            /* Look for integrated payload in the envelope */
            const suit_payloads_t *payloads = &campaign->envelope.payloads;
            for (size_t k = 0; k < payloads->len; k++) {
                const suit_payload_t *ip = &payloads->payload[k];
                if (ip->key.len == dep_uri.len &&
                    memcmp(ip->key.ptr, dep_uri.ptr, dep_uri.len) == 0) {
                    l2_data = ip->bytes.ptr;
                    l2_len = ip->bytes.len;
                    break;
                }
            }
            if (!l2_data) return SUMO_ERR_CALLBACK_FAILED;
        } else {
            /* Fetch L2 envelope */
            size_t buf_size = 16384; /* 16KB initial buffer */
            fetched_l2 = malloc(buf_size);
            if (!fetched_l2) return SUMO_ERR_OUT_OF_MEMORY;

            size_t got = 0;
            int rc = ops->fetch((const char *)dep_uri.ptr, dep_uri.len,
                               fetched_l2, buf_size, &got, ops->user_ctx);
            if (rc != 0) {
                free(fetched_l2);
                return SUMO_ERR_CALLBACK_FAILED;
            }
            l2_data = fetched_l2;
            l2_len = got;
        }

        /* Validate L2 envelope */
        sumo_manifest_t *l2_manifest = NULL;
        int rc = sumo_validate_envelope(v, l2_data, l2_len, 0, &l2_manifest);
        if (rc != SUMO_OK) {
            free(fetched_l2);
            return rc;
        }

        /* Process L2 image */
        rc = sumo_process_image(v, l2_manifest, ops);
        sumo_manifest_free(l2_manifest);
        free(fetched_l2);

        if (rc != SUMO_OK) return rc;
    }

    return SUMO_OK;
}
