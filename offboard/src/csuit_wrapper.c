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

int sum2_csuit_encode_and_sign(
    const uint8_t *manifest_cbor, size_t manifest_len,
    const uint8_t *signing_key, size_t key_len,
    int algorithm,
    uint8_t *out, size_t out_size, size_t *out_len)
{
    /* TODO: implement using libcsuit encode + sign APIs */
    (void)manifest_cbor; (void)manifest_len;
    (void)signing_key; (void)key_len;
    (void)algorithm;
    (void)out; (void)out_size; (void)out_len;
    return -1;
}

int sum2_csuit_sha256(
    const uint8_t *data, size_t data_len,
    uint8_t digest[32])
{
    /* TODO: implement using libcsuit digest or crypto backend */
    (void)data; (void)data_len; (void)digest;
    return -1;
}
