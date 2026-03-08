/**
 * @file csuit_wrapper.h
 * @brief C wrapper to isolate libcsuit headers from C++ compilation.
 *
 * libcsuit's suit_common.h uses `delete` as a bitfield name, which is
 * a reserved keyword in C++. This wrapper provides C-linkage functions
 * that the C++ code calls instead of including csuit.h directly.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SUM2_CSUIT_WRAPPER_H
#define SUM2_CSUIT_WRAPPER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Encode a SUIT_Envelope and sign it with COSE_Sign1.
 * Placeholder — will be expanded as builders are implemented.
 */
int sum2_csuit_encode_and_sign(
    const uint8_t *manifest_cbor, size_t manifest_len,
    const uint8_t *signing_key, size_t key_len,
    int algorithm,
    uint8_t *out, size_t out_size, size_t *out_len
);

/**
 * Compute SHA-256 digest.
 */
int sum2_csuit_sha256(
    const uint8_t *data, size_t data_len,
    uint8_t digest[32]
);

#ifdef __cplusplus
}
#endif
#endif /* SUM2_CSUIT_WRAPPER_H */
