/**
 * @file decryptor.c
 * @brief Streaming AES-GCM decryption.
 *
 * Uses libcsuit for COSE_Encrypt parsing and key unwrapping,
 * and OpenSSL EVP for the actual streaming AES-128-GCM cipher.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sum2/decryptor.h"
#include "sum2/validator.h"

#include <stdlib.h>
#include <string.h>

/* libcsuit for COSE_Encrypt parsing + key unwrap */
#include "csuit/csuit.h"

/* OpenSSL for streaming AES-GCM */
#include <openssl/evp.h>

struct sum2_decryptor {
    uint8_t cek[16];       /* unwrapped AES-128 key */
    uint8_t iv[12];        /* GCM nonce */
    uint8_t tag[16];       /* expected GCM auth tag */
    int has_tag;
    EVP_CIPHER_CTX *ctx;   /* OpenSSL cipher context */
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
     * Use libcsuit to parse the COSE_Encrypt structure and unwrap the CEK.
     * This pulls in suit_decrypt_cose_encrypt and its dependencies.
     */
    suit_mechanism_t mechanism = {0};
    mechanism.cose_tag = COSE_ENCRYPT_TAG;
    mechanism.use = true;

    /* Set up receiver key for ECDH-ES+A128KW or direct A128KW */
    if (dk_len == A128_KEY_CHAR_LENGTH) {
        suit_key_init_a128kw_secret_key(device_key, &mechanism.key);
    } else if (dk_len == PRIME256V1_PUBLIC_KEY_LENGTH + PRIME256V1_PRIVATE_KEY_LENGTH) {
        suit_key_init_es256_key_pair(
            device_key + PRIME256V1_PUBLIC_KEY_LENGTH,
            device_key, &mechanism.rkey);
    } else {
        /* Try as COSE_Key */
        UsefulBufC cose_key_buf = {device_key, dk_len};
        suit_set_suit_key_from_cose_key(cose_key_buf, &mechanism.rkey);
    }

    /*
     * TODO: Extract encryption_info from manifest's shared sequence
     * parameters for component_index. For now this is a placeholder
     * that will be filled in when we parse the manifest command sequences.
     *
     * The key unwrap path (suit_decrypt_cose_encrypt) is what matters
     * for pulling in the right symbols for size measurement.
     */
    (void)component_index;

    /* Initialize OpenSSL AES-128-GCM streaming context */
    d->ctx = EVP_CIPHER_CTX_new();
    if (!d->ctx) {
        suit_free_key(&mechanism.key);
        suit_free_key(&mechanism.rkey);
        free(d);
        return NULL;
    }

    if (EVP_DecryptInit_ex(d->ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(d->ctx);
        suit_free_key(&mechanism.key);
        suit_free_key(&mechanism.rkey);
        free(d);
        return NULL;
    }

    /* Set IV length */
    if (EVP_CIPHER_CTX_ctrl(d->ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(d->iv), NULL) != 1) {
        EVP_CIPHER_CTX_free(d->ctx);
        suit_free_key(&mechanism.key);
        suit_free_key(&mechanism.rkey);
        free(d);
        return NULL;
    }

    /* Set key and IV */
    if (EVP_DecryptInit_ex(d->ctx, NULL, NULL, d->cek, d->iv) != 1) {
        EVP_CIPHER_CTX_free(d->ctx);
        suit_free_key(&mechanism.key);
        suit_free_key(&mechanism.rkey);
        free(d);
        return NULL;
    }

    suit_free_key(&mechanism.key);
    suit_free_key(&mechanism.rkey);
    return d;
}

int sum2_decryptor_update(
    sum2_decryptor_t *d,
    const uint8_t *ct, size_t ct_len,
    uint8_t *pt, size_t *pt_len)
{
    if (!d || !d->ctx || !ct || !pt || !pt_len) return -1;

    int outl = 0;
    if (EVP_DecryptUpdate(d->ctx, pt, &outl, ct, (int)ct_len) != 1) {
        *pt_len = 0;
        return -1;
    }
    *pt_len = (size_t)outl;
    return 0;
}

int sum2_decryptor_finalize(
    sum2_decryptor_t *d,
    uint8_t *pt, size_t *pt_len)
{
    if (!d || !d->ctx || !pt_len) return -1;

    /* Set the expected GCM authentication tag */
    if (d->has_tag) {
        if (EVP_CIPHER_CTX_ctrl(d->ctx, EVP_CTRL_GCM_SET_TAG,
                                 sizeof(d->tag), d->tag) != 1) {
            *pt_len = 0;
            return -1;
        }
    }

    int outl = 0;
    if (EVP_DecryptFinal_ex(d->ctx, pt, &outl) != 1) {
        /* GCM tag mismatch — authentication failed */
        *pt_len = 0;
        return -1;
    }
    *pt_len = (size_t)outl;
    return 0;
}

void sum2_decryptor_free(sum2_decryptor_t *d)
{
    if (!d) return;

    if (d->ctx) {
        EVP_CIPHER_CTX_free(d->ctx);
    }

    /* Zeroize key material */
    OPENSSL_cleanse(d->cek, sizeof(d->cek));
    OPENSSL_cleanse(d->iv, sizeof(d->iv));
    OPENSSL_cleanse(d->tag, sizeof(d->tag));
    memset(d, 0, sizeof(*d));
    free(d);
}
