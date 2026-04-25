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
#ifndef SUMO_DECRYPTOR_H
#define SUMO_DECRYPTOR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sumo_manifest sumo_manifest_t;
typedef struct sumo_decryptor sumo_decryptor_t;
typedef struct sumo_validator sumo_validator_t;

/**
 * Create a streaming decryptor for a component in the manifest.
 *
 * Unwraps the content encryption key (CEK) from the COSE_Encrypt
 * encryption-info parameter using the supplied raw device key.
 * Most callers should prefer sumo_decryptor_create_v(), which selects
 * the right key automatically by matching the recipient kid against
 * the validator's registered device keys.
 *
 * @param manifest          Validated manifest
 * @param component_index   Which component to decrypt
 * @param device_key        Device private key (DER or COSE_Key)
 * @param dk_len            Key length
 * @return Decryptor handle, or NULL on failure (key unwrap failed, etc.)
 */
sumo_decryptor_t *sumo_decryptor_create(
    const sumo_manifest_t *manifest,
    size_t component_index,
    const uint8_t *device_key, size_t dk_len
);

/**
 * Create a streaming decryptor and pick the device key automatically
 * by matching the recipient kid in the COSE_Encrypt to a key registered
 * via sumo_validator_add_device_key(). Returns NULL when no kid matches
 * (and no kid was supplied to fall back on).
 */
sumo_decryptor_t *sumo_decryptor_create_v(
    const sumo_manifest_t *manifest,
    size_t component_index,
    const sumo_validator_t *validator
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
int sumo_decryptor_update(
    sumo_decryptor_t *d,
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
 * @return 0 on success, SUMO_ERR_DECRYPT_FAILED if tag verification fails
 */
int sumo_decryptor_finalize(
    sumo_decryptor_t *d,
    uint8_t *pt, size_t *pt_len
);

void sumo_decryptor_free(sumo_decryptor_t *d);

#ifdef __cplusplus
}
#endif
#endif /* SUMO_DECRYPTOR_H */
