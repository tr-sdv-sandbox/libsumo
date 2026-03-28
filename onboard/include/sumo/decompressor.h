/**
 * @file decompressor.h
 * @brief Streaming zstd decompression for firmware payloads.
 *
 * Designed to chain after sumo_decryptor: decrypt chunk → decompress
 * chunk → write to flash. Fixed memory usage regardless of image size.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SUMO_DECOMPRESSOR_H
#define SUMO_DECOMPRESSOR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sumo_decompressor sumo_decompressor_t;

/**
 * Create a streaming zstd decompressor.
 *
 * @return Decompressor handle, or NULL on failure
 */
sumo_decompressor_t *sumo_decompressor_create(void);

/**
 * Decompress a chunk of data.
 *
 * Feeds compressed data and produces decompressed output. Because
 * compression ratios vary, the output may be larger or smaller than
 * the input. If the output buffer is too small, call again with
 * in_len=0 to drain remaining output.
 *
 * @param d        Decompressor handle
 * @param in       Compressed input chunk (from decryptor output)
 * @param in_len   Input length. On return: bytes consumed from in.
 * @param out      Output buffer for decompressed data
 * @param out_len  In: output buffer capacity. Out: bytes written.
 * @return 0 on success, negative on error
 */
int sumo_decompressor_update(
    sumo_decompressor_t *d,
    const uint8_t *in, size_t *in_len,
    uint8_t *out, size_t *out_len
);

/**
 * Check if the decompression stream has ended cleanly.
 *
 * @return 0 if the stream ended normally, negative if truncated
 */
int sumo_decompressor_finalize(sumo_decompressor_t *d);

void sumo_decompressor_free(sumo_decompressor_t *d);

#ifdef __cplusplus
}
#endif
#endif /* SUMO_DECOMPRESSOR_H */
