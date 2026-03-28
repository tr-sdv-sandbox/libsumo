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
#ifndef SUMO_CSUIT_WRAPPER_H
#define SUMO_CSUIT_WRAPPER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --- Envelope builder (opaque, wraps suit_envelope_t + encoder) --- */

typedef struct sumo_envelope_builder sumo_envelope_builder_t;

sumo_envelope_builder_t *sumo_eb_create(void);
void sumo_eb_free(sumo_envelope_builder_t *b);

int sumo_eb_set_sequence_number(sumo_envelope_builder_t *b, uint64_t seq);

/**
 * Add a component identifier from string segments.
 * E.g., segments={"ecu-a","firmware"}, num=2 → CBOR [h'6563752d61', h'6669726d77617265']
 */
int sumo_eb_add_component(sumo_envelope_builder_t *b,
                          const char *const *segments, size_t num_segments);

int sumo_eb_set_vendor_id(sumo_envelope_builder_t *b, const uint8_t uuid[16]);
int sumo_eb_set_class_id(sumo_envelope_builder_t *b, const uint8_t uuid[16]);

int sumo_eb_set_image_digest_sha256(sumo_envelope_builder_t *b,
                                     const uint8_t digest[32],
                                     uint64_t image_size);

int sumo_eb_set_payload_uri(sumo_envelope_builder_t *b, const char *uri);

int sumo_eb_set_encryption_info(sumo_envelope_builder_t *b,
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
int sumo_eb_encode(sumo_envelope_builder_t *b,
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
int sumo_encrypt_a128kw(
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
int sumo_encrypt_esdh(
    const uint8_t *plaintext, size_t pt_len,
    const uint8_t *sender_cose_key, size_t sender_key_len,
    const uint8_t *recv_cose_key, size_t recv_key_len,
    const uint8_t *recv_kid, size_t recv_kid_len,
    uint8_t *ct_out, size_t ct_out_size, size_t *ct_out_len,
    uint8_t *ei_out, size_t ei_out_size, size_t *ei_out_len);

/* --- Campaign builder --- */

/**
 * Dependency info for campaign builder.
 */
typedef struct {
    const char *fetch_uri;
    size_t fetch_uri_len;
    uint8_t digest[32];          /* SHA-256 of L2 envelope */
    int is_integrated;           /* true if integrated payload */
    const uint8_t *payload;      /* integrated payload bytes (NULL if external) */
    size_t payload_len;
} sumo_campaign_dep_t;

/**
 * Build and encode a campaign (L1) SUIT_Envelope.
 *
 * @param seq             Campaign sequence number
 * @param vendor_id       16-byte vendor UUID (or NULL)
 * @param class_id        16-byte class UUID (or NULL)
 * @param deps            Array of dependency descriptors
 * @param num_deps        Number of dependencies
 * @param cose_key_cbor   Signing key COSE_Key CBOR
 * @param key_len         Length of signing key
 * @param cose_tag        18=Sign1, 17=Mac0
 * @param algorithm       COSE algorithm ID
 * @param out             Output buffer
 * @param out_size        Buffer size
 * @param out_len         Actual bytes written
 */
int sumo_eb_encode_campaign(
    uint64_t seq,
    const uint8_t *vendor_id,
    const uint8_t *class_id,
    const sumo_campaign_dep_t *deps, size_t num_deps,
    const uint8_t *cose_key_cbor, size_t key_len,
    int cose_tag, int algorithm,
    uint8_t *out, size_t out_size, size_t *out_len);

/* --- Utilities --- */

int sumo_sha256(const uint8_t *data, size_t data_len, uint8_t digest[32]);

#ifdef __cplusplus
}
#endif
#endif /* SUMO_CSUIT_WRAPPER_H */
