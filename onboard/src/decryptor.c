/**
 * @file decryptor.c
 * @brief Streaming AES-GCM decryption.
 *
 * This is new code — libcsuit only provides all-at-once decryption.
 * We use the crypto backend directly (mbedTLS or OpenSSL) for streaming,
 * and libcsuit only for COSE_Encrypt parsing and key unwrapping.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sum2/decryptor.h"
#include "sum2/validator.h"

#include <stdlib.h>
#include <string.h>

/* libcsuit for COSE_Encrypt parsing + key unwrap */
#include "csuit/csuit.h"

struct sum2_decryptor {
    uint8_t cek[16];       /* unwrapped AES-128 key */
    uint8_t iv[12];        /* GCM nonce */
    uint8_t tag[16];       /* expected GCM auth tag */
    void   *cipher_ctx;    /* backend-specific cipher context */
};

sum2_decryptor_t *sum2_decryptor_create(
    const sum2_manifest_t *manifest,
    size_t component_index,
    const uint8_t *device_key, size_t dk_len)
{
    if (!manifest || !device_key) return NULL;

    sum2_decryptor_t *d = calloc(1, sizeof(*d));
    if (!d) return NULL;

    /*
     * TODO: implementation outline:
     *
     * 1. Extract suit-parameter-encryption-info from manifest for component_index
     * 2. Parse COSE_Encrypt structure to get:
     *    - IV (from unprotected header, label 5)
     *    - Algorithm (from protected header, label 1)
     *    - Recipients array
     * 3. Find matching COSE_recipient by kid
     * 4. Unwrap CEK:
     *    - For ECDH-ES+A128KW: extract ephemeral key, compute ECDH shared
     *      secret, derive KEK via HKDF, unwrap CEK via AES-KW
     *    - For AES-KW: unwrap directly with pre-shared KEK
     * 5. Extract GCM auth tag (appended to ciphertext, or from encryption-info)
     * 6. Init streaming AES-128-GCM decryption context with CEK + IV
     *
     * Key unwrap can use libcsuit's suit_decrypt_cose_encrypt() internals,
     * but the streaming cipher context must be our own.
     */

    (void)component_index; (void)dk_len;

    free(d);
    return NULL; /* not yet implemented */
}

int sum2_decryptor_update(
    sum2_decryptor_t *d,
    const uint8_t *ct, size_t ct_len,
    uint8_t *pt, size_t *pt_len)
{
    if (!d || !ct || !pt || !pt_len) return -1;

    /*
     * TODO: feed ciphertext chunk into AES-GCM streaming context.
     *
     * mbedTLS:  mbedtls_gcm_update()
     * OpenSSL:  EVP_DecryptUpdate()
     */

    (void)ct_len;
    *pt_len = 0;
    return -1; /* not yet implemented */
}

int sum2_decryptor_finalize(
    sum2_decryptor_t *d,
    uint8_t *pt, size_t *pt_len)
{
    if (!d || !pt_len) return -1;

    /*
     * TODO: finalize AES-GCM and verify auth tag.
     *
     * mbedTLS:  mbedtls_gcm_finish() — checks tag
     * OpenSSL:  EVP_CIPHER_CTX_ctrl(SET_TAG) + EVP_DecryptFinal_ex()
     */

    *pt_len = 0;
    return -1; /* not yet implemented */
}

void sum2_decryptor_free(sum2_decryptor_t *d)
{
    if (!d) return;

    /* TODO: free cipher_ctx via backend */

    /* Zeroize key material */
    memset(d->cek, 0, sizeof(d->cek));
    memset(d, 0, sizeof(*d));
    free(d);
}
