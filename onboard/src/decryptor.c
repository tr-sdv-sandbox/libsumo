/**
 * @file decryptor.c
 * @brief Streaming AES-GCM decryption.
 *
 * Parses COSE_Encrypt structure from the manifest's encryption-info
 * parameter, unwraps the CEK (A128KW or ECDH-ES+A128KW), then provides
 * a streaming AES-128-GCM decryption interface via OpenSSL EVP.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sum2/decryptor.h"
#include "sum2/validator.h"

#include <stdlib.h>
#include <string.h>

/* libcsuit / QCBOR for CBOR parsing + encoding (Enc_structure AAD) */
#include "csuit/csuit.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_encode.h"

/* OpenSSL for AES-GCM streaming + AES key unwrap */
#include <openssl/evp.h>

#define GCM_TAG_LEN 16
#define GCM_IV_LEN  12
#define CEK_LEN     16  /* AES-128 */

struct sum2_decryptor {
    uint8_t cek[CEK_LEN]; /* unwrapped AES-128 key */
    uint8_t iv[GCM_IV_LEN];
    EVP_CIPHER_CTX *ctx;
    /* GCM tag buffering: caller streams ciphertext which has
     * the 16-byte tag appended. We buffer the trailing 16 bytes
     * and set them as the GCM tag at finalize time. */
    uint8_t tail[GCM_TAG_LEN];
    size_t tail_len;
    int initialized;
};

/* --- COSE_Encrypt CBOR parsing --- */

/**
 * Parse a COSE_Encrypt structure to extract IV and wrapped CEK.
 *
 * COSE_Encrypt = [
 *   protected,    // bstr: serialized map {1: alg}
 *   unprotected,  // map {5: IV}
 *   ciphertext,   // null (detached)
 *   recipients    // array of COSE_recipient
 * ]
 *
 * COSE_recipient = [
 *   protected,    // bstr
 *   unprotected,  // map {1: alg, 4: kid, ...}
 *   ciphertext    // bstr: wrapped CEK
 * ]
 */
static int parse_cose_encrypt(
    const uint8_t *enc_info, size_t enc_info_len,
    uint8_t iv_out[GCM_IV_LEN],
    uint8_t *wrapped_cek_out, size_t *wrapped_cek_len,
    int *recipient_alg_out,
    const uint8_t **prot_hdr_out, size_t *prot_hdr_len_out)
{
    QCBORDecodeContext ctx;
    QCBORItem item;
    UsefulBufC enc_buf = {enc_info, enc_info_len};

    QCBORDecode_Init(&ctx, enc_buf, QCBOR_DECODE_MODE_NORMAL);

    /* Optional CBOR tag 96 (COSE_Encrypt) */
    QCBORDecode_PeekNext(&ctx, &item);
    if (item.uDataType == QCBOR_TYPE_ARRAY && item.val.uCount >= 4) {
        /* Tagged or untagged array — enter it */
    }
    QCBORDecode_EnterArray(&ctx, NULL);

    /* [0] protected header — bstr containing serialized CBOR map */
    QCBORDecode_GetNext(&ctx, &item);
    if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
        *prot_hdr_out = item.val.string.ptr;
        *prot_hdr_len_out = item.val.string.len;
    } else {
        *prot_hdr_out = NULL;
        *prot_hdr_len_out = 0;
    }

    /* [1] unprotected header — map containing IV (label 5) */
    QCBORDecode_EnterMap(&ctx, NULL);
    int got_iv = 0;
    while (1) {
        QCBORError err = QCBORDecode_GetNext(&ctx, &item);
        if (err != QCBOR_SUCCESS) break;
        if (item.label.int64 == 5 && item.uDataType == QCBOR_TYPE_BYTE_STRING) {
            if (item.val.string.len == GCM_IV_LEN) {
                memcpy(iv_out, item.val.string.ptr, GCM_IV_LEN);
                got_iv = 1;
            }
        }
    }
    QCBORDecode_ExitMap(&ctx);
    if (!got_iv) return -1;

    /* [2] ciphertext — should be null (detached) */
    QCBORDecode_GetNext(&ctx, &item);

    /* [3] recipients array */
    QCBORDecode_EnterArray(&ctx, NULL);

    /* First recipient */
    QCBORDecode_EnterArray(&ctx, NULL);

    /* recipient[0] protected header — skip */
    QCBORDecode_GetNext(&ctx, &item);

    /* recipient[1] unprotected header — get alg and kid */
    *recipient_alg_out = 0;
    QCBORDecode_EnterMap(&ctx, NULL);
    while (1) {
        QCBORError err = QCBORDecode_GetNext(&ctx, &item);
        if (err != QCBOR_SUCCESS) break;
        if (item.label.int64 == 1) {
            /* algorithm */
            if (item.uDataType == QCBOR_TYPE_INT64) {
                *recipient_alg_out = (int)item.val.int64;
            } else if (item.uDataType == QCBOR_TYPE_UINT64) {
                *recipient_alg_out = (int)item.val.uint64;
            }
        }
    }
    QCBORDecode_ExitMap(&ctx);

    /* recipient[2] ciphertext — the wrapped CEK */
    QCBORDecode_GetNext(&ctx, &item);
    if (item.uDataType != QCBOR_TYPE_BYTE_STRING || item.val.string.len == 0)
        return -1;
    if (item.val.string.len > *wrapped_cek_len)
        return -1;
    memcpy(wrapped_cek_out, item.val.string.ptr, item.val.string.len);
    *wrapped_cek_len = item.val.string.len;

    /* Don't bother fully closing — we have what we need */
    return 0;
}

/* --- CEK unwrap --- */

static int unwrap_cek_a128kw(
    const uint8_t *kek, size_t kek_len,
    const uint8_t *wrapped_cek, size_t wrapped_len,
    uint8_t cek_out[CEK_LEN])
{
    if (kek_len != CEK_LEN) return -1;
    /* A128KW wrapped output is CEK_LEN + 8 bytes */
    if (wrapped_len != CEK_LEN + 8) return -1;

    int ret = -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_wrap(), NULL, kek, NULL) != 1)
        goto out;

    int outl = 0;
    if (EVP_DecryptUpdate(ctx, cek_out, &outl,
                          wrapped_cek, (int)wrapped_len) != 1)
        goto out;

    int finl = 0;
    if (EVP_DecryptFinal_ex(ctx, cek_out + outl, &finl) != 1)
        goto out;

    ret = ((outl + finl) == CEK_LEN) ? 0 : -1;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* --- Encryption info extraction from manifest --- */

/**
 * Search both shared and install/fetch command sequences for
 * the encryption_info parameter (label 19) for a given component.
 */
static UsefulBufC find_encryption_info(
    const sum2_manifest_t *m, size_t component_index);

/* Implemented via the opaque manifest — we need access to the
 * envelope internals. Declare the struct here (matches validator.c). */
struct sum2_manifest {
    suit_envelope_t envelope;
    suit_mechanism_t mechanisms[SUIT_MAX_KEY_NUM];
};

static UsefulBufC search_cmd_seq_for_param(
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
        if (pl->index != (uint8_t)component_index)
            continue;

        for (size_t j = 0; j < pl->len; j++) {
            if (pl->params[j].label == param_label)
                return pl->params[j].value.string;
        }
    }
    return empty;
}

static UsefulBufC find_encryption_info(
    const sum2_manifest_t *m, size_t component_index)
{
    UsefulBufC result;
    const suit_manifest_t *man = &m->envelope.manifest;

    /* Check shared sequence first */
    result = search_cmd_seq_for_param(&man->common.shared_seq,
                                       component_index,
                                       SUIT_PARAMETER_ENCRYPTION_INFO);
    if (result.ptr) return result;

    /* Check install sequence */
    result = search_cmd_seq_for_param(&man->sev_man_mem.install,
                                       component_index,
                                       SUIT_PARAMETER_ENCRYPTION_INFO);
    if (result.ptr) return result;

    /* Check payload_fetch sequence */
    result = search_cmd_seq_for_param(&man->sev_man_mem.payload_fetch,
                                       component_index,
                                       SUIT_PARAMETER_ENCRYPTION_INFO);
    return result;
}

/* --- Public API --- */

sum2_decryptor_t *sum2_decryptor_create(
    const sum2_manifest_t *manifest,
    size_t component_index,
    const uint8_t *device_key, size_t dk_len)
{
    if (!manifest || !device_key) return NULL;

    /* Extract encryption_info CBOR from the manifest */
    UsefulBufC enc_info = find_encryption_info(manifest, component_index);
    if (!enc_info.ptr || enc_info.len == 0) return NULL;

    /* Parse the COSE_Encrypt structure */
    uint8_t iv[GCM_IV_LEN];
    uint8_t wrapped_cek[CEK_LEN + 8 + 16]; /* room for A128KW or larger */
    size_t wrapped_cek_len = sizeof(wrapped_cek);
    int recipient_alg = 0;
    const uint8_t *prot_hdr = NULL;
    size_t prot_hdr_len = 0;

    if (parse_cose_encrypt(enc_info.ptr, enc_info.len,
                           iv, wrapped_cek, &wrapped_cek_len,
                           &recipient_alg,
                           &prot_hdr, &prot_hdr_len) != 0) {
        return NULL;
    }

    /* Unwrap the CEK based on recipient algorithm */
    uint8_t cek[CEK_LEN];
    if (recipient_alg == -3) {
        /* A128KW: device_key is the 16-byte KEK */
        if (unwrap_cek_a128kw(device_key, dk_len,
                              wrapped_cek, wrapped_cek_len, cek) != 0) {
            return NULL;
        }
    } else {
        /* TODO: ECDH-ES+A128KW (alg=-29) requires ECDH + HKDF + A128KW */
        return NULL;
    }

    /* Allocate and initialize the decryptor */
    sum2_decryptor_t *d = calloc(1, sizeof(*d));
    if (!d) {
        OPENSSL_cleanse(cek, sizeof(cek));
        return NULL;
    }

    memcpy(d->cek, cek, CEK_LEN);
    memcpy(d->iv, iv, GCM_IV_LEN);
    OPENSSL_cleanse(cek, sizeof(cek));

    d->ctx = EVP_CIPHER_CTX_new();
    if (!d->ctx) goto fail;

    if (EVP_DecryptInit_ex(d->ctx, EVP_aes_128_gcm(),
                           NULL, NULL, NULL) != 1)
        goto fail;

    if (EVP_CIPHER_CTX_ctrl(d->ctx, EVP_CTRL_GCM_SET_IVLEN,
                            GCM_IV_LEN, NULL) != 1)
        goto fail;

    if (EVP_DecryptInit_ex(d->ctx, NULL, NULL, d->cek, d->iv) != 1)
        goto fail;

    /* Build COSE Enc_structure AAD per RFC 9052 Section 5.3:
     *   Enc_structure = ["Encrypt", protected_header, external_aad]
     * where external_aad is empty (h''). */
    {
        uint8_t aad_buf[64];
        UsefulBuf aad_usbuf = {aad_buf, sizeof(aad_buf)};
        UsefulBufC aad_encoded;
        QCBOREncodeContext qenc;

        QCBOREncode_Init(&qenc, aad_usbuf);
        QCBOREncode_OpenArray(&qenc);
        QCBOREncode_AddSZString(&qenc, "Encrypt");
        UsefulBufC prot_hdr_buf = {prot_hdr, prot_hdr_len};
        QCBOREncode_AddBytes(&qenc, prot_hdr_buf);
        UsefulBufC empty_aad = {NULL, 0};
        QCBOREncode_AddBytes(&qenc, empty_aad);
        QCBOREncode_CloseArray(&qenc);

        if (QCBOREncode_Finish(&qenc, &aad_encoded) != QCBOR_SUCCESS)
            goto fail;

        int outl = 0;
        if (EVP_DecryptUpdate(d->ctx, NULL, &outl,
                              aad_encoded.ptr, (int)aad_encoded.len) != 1)
            goto fail;
    }

    d->initialized = 1;
    return d;

fail:
    if (d->ctx) EVP_CIPHER_CTX_free(d->ctx);
    OPENSSL_cleanse(d, sizeof(*d));
    free(d);
    return NULL;
}

int sum2_decryptor_update(
    sum2_decryptor_t *d,
    const uint8_t *ct, size_t ct_len,
    uint8_t *pt, size_t *pt_len)
{
    if (!d || !d->ctx || !d->initialized || !ct || !pt || !pt_len)
        return -1;

    /*
     * GCM tag handling: in COSE, the GCM authentication tag (16 bytes)
     * is appended to the ciphertext. We need to hold back the last 16
     * bytes and set them as the GCM tag at finalize time.
     *
     * Strategy: maintain a 16-byte tail buffer. On each update, decrypt
     * the data from the *previous* tail plus new data minus new tail.
     */
    size_t total = d->tail_len + ct_len;
    if (total <= GCM_TAG_LEN) {
        /* Not enough data yet — just buffer */
        memcpy(d->tail + d->tail_len, ct, ct_len);
        d->tail_len = total;
        *pt_len = 0;
        return 0;
    }

    /* We have enough to keep a full tail and decrypt something */
    size_t decrypt_len = total - GCM_TAG_LEN;

    /* Build contiguous input: old_tail + new_data - new_tail */
    /* First, decrypt from old tail if any */
    size_t pt_written = 0;

    if (d->tail_len > 0) {
        /* How much of the old tail can we decrypt? */
        size_t from_tail = (decrypt_len < d->tail_len) ? decrypt_len : d->tail_len;
        if (from_tail > 0) {
            int outl = 0;
            if (EVP_DecryptUpdate(d->ctx, pt, &outl,
                                  d->tail, (int)from_tail) != 1) {
                *pt_len = 0;
                return -1;
            }
            pt_written += (size_t)outl;
            decrypt_len -= from_tail;
        }
    }

    /* Now decrypt from new ciphertext */
    size_t from_new = (decrypt_len < ct_len) ? decrypt_len : ct_len;
    if (from_new > 0) {
        int outl = 0;
        if (EVP_DecryptUpdate(d->ctx, pt + pt_written, &outl,
                              ct, (int)from_new) != 1) {
            *pt_len = 0;
            return -1;
        }
        pt_written += (size_t)outl;
    }

    /* Update tail: last GCM_TAG_LEN bytes of (old_tail + new_data) */
    if (ct_len >= GCM_TAG_LEN) {
        memcpy(d->tail, ct + ct_len - GCM_TAG_LEN, GCM_TAG_LEN);
        d->tail_len = GCM_TAG_LEN;
    } else {
        /* Shift old tail left and append new data */
        size_t keep = GCM_TAG_LEN - ct_len;
        memmove(d->tail, d->tail + d->tail_len - keep, keep);
        memcpy(d->tail + keep, ct, ct_len);
        d->tail_len = GCM_TAG_LEN;
    }

    *pt_len = pt_written;
    return 0;
}

int sum2_decryptor_finalize(
    sum2_decryptor_t *d,
    uint8_t *pt, size_t *pt_len)
{
    if (!d || !d->ctx || !d->initialized || !pt_len) return -1;

    /* The tail buffer should contain exactly the 16-byte GCM tag */
    if (d->tail_len != GCM_TAG_LEN) {
        *pt_len = 0;
        return -1;
    }

    /* Set the GCM authentication tag */
    if (EVP_CIPHER_CTX_ctrl(d->ctx, EVP_CTRL_GCM_SET_TAG,
                            GCM_TAG_LEN, d->tail) != 1) {
        *pt_len = 0;
        return -1;
    }

    int outl = 0;
    if (EVP_DecryptFinal_ex(d->ctx, pt, &outl) != 1) {
        *pt_len = 0;
        return -1;  /* GCM tag mismatch */
    }
    *pt_len = (size_t)outl;
    return 0;
}

void sum2_decryptor_free(sum2_decryptor_t *d)
{
    if (!d) return;
    if (d->ctx) EVP_CIPHER_CTX_free(d->ctx);
    OPENSSL_cleanse(d->cek, sizeof(d->cek));
    OPENSSL_cleanse(d->iv, sizeof(d->iv));
    OPENSSL_cleanse(d->tail, sizeof(d->tail));
    memset(d, 0, sizeof(*d));
    free(d);
}
