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

/* --- Envelope builder (opaque, wraps suit_envelope_t + encoder) --- */

typedef struct sum2_envelope_builder sum2_envelope_builder_t;

sum2_envelope_builder_t *sum2_eb_create(void);
void sum2_eb_free(sum2_envelope_builder_t *b);

int sum2_eb_set_sequence_number(sum2_envelope_builder_t *b, uint64_t seq);

/**
 * Add a component identifier from string segments.
 * E.g., segments={"ecu-a","firmware"}, num=2 → CBOR [h'6563752d61', h'6669726d77617265']
 */
int sum2_eb_add_component(sum2_envelope_builder_t *b,
                          const char *const *segments, size_t num_segments);

int sum2_eb_set_vendor_id(sum2_envelope_builder_t *b, const uint8_t uuid[16]);
int sum2_eb_set_class_id(sum2_envelope_builder_t *b, const uint8_t uuid[16]);

int sum2_eb_set_image_digest_sha256(sum2_envelope_builder_t *b,
                                     const uint8_t digest[32],
                                     uint64_t image_size);

int sum2_eb_set_payload_uri(sum2_envelope_builder_t *b, const char *uri);

int sum2_eb_set_encryption_info(sum2_envelope_builder_t *b,
                                 const uint8_t *info, size_t info_len);

/**
 * Encode the manifest and sign/MAC it.
 *
 * @param cose_key_cbor  COSE_Key CBOR bytes (signing or MAC key)
 * @param cose_tag       18 = COSE_Sign1, 17 = COSE_Mac0
 * @param algorithm      COSE algorithm ID (e.g., -7=ES256, 5=HMAC256)
 * @param out            Caller-provided output buffer
 * @param out_size       Size of output buffer
 * @param out_len        Actual bytes written
 */
int sum2_eb_encode(sum2_envelope_builder_t *b,
                   const uint8_t *cose_key_cbor, size_t key_len,
                   int cose_tag, int algorithm,
                   uint8_t *out, size_t out_size, size_t *out_len);

/* --- Encryption --- */

/**
 * Encrypt plaintext with A128KW key wrapping.
 * Uses libcsuit's suit_encrypt_cose_encrypt() internally.
 *
 * @param plaintext       Input firmware bytes
 * @param pt_len          Length of plaintext
 * @param kek_cose_key    COSE_Key CBOR for the A128KW KEK
 * @param kek_len         Length of COSE_Key CBOR
 * @param ct_out          Output buffer for ciphertext (pt_len + 16 for GCM tag)
 * @param ct_out_size     Size of ciphertext buffer
 * @param ct_out_len      Actual ciphertext bytes written
 * @param ei_out          Output buffer for COSE_Encrypt CBOR (encryption_info)
 * @param ei_out_size     Size of encryption_info buffer
 * @param ei_out_len      Actual encryption_info bytes written
 */
int sum2_encrypt_a128kw(
    const uint8_t *plaintext, size_t pt_len,
    const uint8_t *kek_cose_key, size_t kek_len,
    uint8_t *ct_out, size_t ct_out_size, size_t *ct_out_len,
    uint8_t *ei_out, size_t ei_out_size, size_t *ei_out_len);

/**
 * Encrypt plaintext with ECDH-ES+A128KW key wrapping.
 * Uses P-256 ECDH + HKDF-SHA256 + A128KW for per-device key wrapping.
 *
 * @param plaintext        Input firmware bytes
 * @param pt_len           Length of plaintext
 * @param sender_cose_key  COSE_Key CBOR for sender's P-256 private key
 * @param sender_key_len   Length of sender COSE_Key CBOR
 * @param recv_cose_key    COSE_Key CBOR for receiver's P-256 key (public or private)
 * @param recv_key_len     Length of receiver COSE_Key CBOR
 * @param recv_kid         Receiver's key identifier
 * @param recv_kid_len     Length of receiver's kid
 * @param ct_out           Output buffer for ciphertext
 * @param ct_out_size      Size of ciphertext buffer
 * @param ct_out_len       Actual ciphertext bytes written
 * @param ei_out           Output buffer for COSE_Encrypt CBOR (encryption_info)
 * @param ei_out_size      Size of encryption_info buffer
 * @param ei_out_len       Actual encryption_info bytes written
 */
int sum2_encrypt_esdh(
    const uint8_t *plaintext, size_t pt_len,
    const uint8_t *sender_cose_key, size_t sender_key_len,
    const uint8_t *recv_cose_key, size_t recv_key_len,
    const uint8_t *recv_kid, size_t recv_kid_len,
    uint8_t *ct_out, size_t ct_out_size, size_t *ct_out_len,
    uint8_t *ei_out, size_t ei_out_size, size_t *ei_out_len);

/* --- Utilities --- */

int sum2_sha256(const uint8_t *data, size_t data_len, uint8_t digest[32]);

#ifdef __cplusplus
}
#endif
#endif /* SUM2_CSUIT_WRAPPER_H */
