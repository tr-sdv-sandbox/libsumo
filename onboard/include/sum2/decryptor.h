/**
 * @file decryptor.h
 * @brief Streaming AES-GCM decryption for firmware payloads.
 *
 * Wraps COSE_Encrypt key unwrapping (ECDH-ES+AES-KW or AES-KW) and
 * provides a streaming interface for decrypting firmware in fixed-size
 * chunks. The entire ciphertext does NOT need to fit in memory.
 *
 * This is the critical gap that libcsuit does not provide — libcsuit's
 * suit_decrypt_cose_encrypt() requires the full ciphertext in memory.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SUM2_DECRYPTOR_H
#define SUM2_DECRYPTOR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sum2_manifest sum2_manifest_t;
typedef struct sum2_decryptor sum2_decryptor_t;

/**
 * Create a streaming decryptor for a component in the manifest.
 *
 * Unwraps the content encryption key (CEK) from the COSE_Encrypt
 * encryption-info parameter using the device's private key.
 *
 * @param manifest          Validated manifest
 * @param component_index   Which component to decrypt
 * @param device_key        Device private key (DER or COSE_Key)
 * @param dk_len            Key length
 * @return Decryptor handle, or NULL on failure (key unwrap failed, etc.)
 */
sum2_decryptor_t *sum2_decryptor_create(
    const sum2_manifest_t *manifest,
    size_t component_index,
    const uint8_t *device_key, size_t dk_len
);

/**
 * Decrypt a chunk of ciphertext.
 *
 * Call repeatedly with chunks of the encrypted payload (e.g., 4KB at a
 * time as data arrives from network/flash).
 *
 * @param d           Decryptor handle
 * @param ct          Ciphertext chunk
 * @param ct_len      Chunk length
 * @param pt          Output buffer (must be at least ct_len bytes)
 * @param pt_len      On input: output buffer size. On output: bytes written.
 * @return 0 on success, negative on error
 */
int sum2_decryptor_update(
    sum2_decryptor_t *d,
    const uint8_t *ct, size_t ct_len,
    uint8_t *pt, size_t *pt_len
);

/**
 * Finalize decryption and verify GCM authentication tag.
 *
 * MUST be called after the last chunk. Verifies the AEAD authentication
 * tag to ensure the ciphertext was not tampered with.
 *
 * @param d           Decryptor handle
 * @param pt          Output buffer for any remaining plaintext
 * @param pt_len      On input: buffer size. On output: bytes written.
 * @return 0 on success, SUM2_ERR_DECRYPT_FAILED if tag verification fails
 */
int sum2_decryptor_finalize(
    sum2_decryptor_t *d,
    uint8_t *pt, size_t *pt_len
);

void sum2_decryptor_free(sum2_decryptor_t *d);

#ifdef __cplusplus
}
#endif
#endif /* SUM2_DECRYPTOR_H */
