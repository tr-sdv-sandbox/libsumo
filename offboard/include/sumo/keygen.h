/**
 * @file keygen.h
 * @brief COSE_Key generation for signing and device key agreement.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SUMO_KEYGEN_H
#define SUMO_KEYGEN_H

#include "sumo/image_builder.h"  // CoseKey

namespace sumo {

/** COSE algorithm identifiers */
enum Algorithm {
    ES256  = -7,   // ECDSA w/ SHA-256 (P-256)
    EdDSA  = -8,   // Ed25519
};

/**
 * Generate a signing keypair.
 * @param algorithm  ES256 or EdDSA
 * @return COSE_Key with both private and public key material
 */
CoseKey GenerateSigningKey(int algorithm = EdDSA);

/**
 * Generate a device key agreement keypair.
 * For ECDH-ES: P-256 (when signing algo is ES256) or X25519 (when EdDSA).
 * @param algorithm  ES256 or EdDSA (determines curve)
 * @return COSE_Key with both private and public key material
 */
CoseKey GenerateDeviceKey(int algorithm = EdDSA);

/**
 * Serialize a COSE_Key to CBOR bytes (for storage/transmission).
 */
std::vector<uint8_t> SerializeKey(const CoseKey& key, bool include_private = false);

/**
 * Serialize a COSE_Key to PEM format (for interop with OpenSSL tools).
 */
std::string SerializeKeyPem(const CoseKey& key, bool include_private = false);

} // namespace sumo

#endif /* SUMO_KEYGEN_H */
