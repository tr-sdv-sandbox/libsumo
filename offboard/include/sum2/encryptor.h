/**
 * @file encryptor.h
 * @brief Firmware payload encryption with per-device key wrapping.
 *
 * Encrypts firmware with AES-128-GCM and wraps the content encryption
 * key (CEK) for each target device using ECDH-ES+AES-KW (COSE_Encrypt).
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SUM2_ENCRYPTOR_H
#define SUM2_ENCRYPTOR_H

#include <cstdint>
#include <span>
#include <vector>

#include "sum2/image_builder.h"  // CoseKey, EncryptedPayload

namespace sum2 {

/**
 * A device recipient for per-device encryption.
 */
struct Recipient {
    CoseKey public_key;                   // Device's public key (X25519 or P-256)
    std::vector<uint8_t> kid;             // Key identifier (device ID)
};

/**
 * Encrypt a firmware payload for one or more device recipients.
 *
 * 1. Generates a random AES-128-GCM content encryption key (CEK)
 * 2. Encrypts the plaintext with the CEK
 * 3. For each recipient: wraps the CEK using ECDH-ES+A128KW
 * 4. Returns ciphertext + COSE_Encrypt structure (as CBOR bytes)
 *
 * The COSE_Encrypt structure is passed to ImageManifestBuilder::SetEncryptionInfo().
 * The ciphertext is stored as a separate file (e.g., firmware.enc).
 *
 * @param plaintext   Firmware binary
 * @param recipients  Target devices (one COSE_recipient per device)
 * @return Encrypted payload + COSE_Encrypt metadata
 */
EncryptedPayload EncryptFirmware(
    std::span<const uint8_t> plaintext,
    std::span<const Recipient> recipients
);

/**
 * Encrypt a firmware payload using ECDH-ES+A128KW (per-device asymmetric).
 *
 * Each recipient's CEK is wrapped using ECDH with the device's P-256 public
 * key, matching the security model of per-device key wrapping.
 *
 * @param plaintext    Firmware binary
 * @param sender_key   Sender's P-256 private key (ephemeral or static)
 * @param recipients   Target devices
 * @return Encrypted payload + COSE_Encrypt metadata
 */
EncryptedPayload EncryptFirmwareEcdh(
    std::span<const uint8_t> plaintext,
    const CoseKey& sender_key,
    std::span<const Recipient> recipients
);

/**
 * Compress firmware with zstd.
 *
 * Designed for the pipeline: compress → encrypt → build manifest.
 * The manifest carries the PLAINTEXT digest and size (not compressed).
 *
 * @param plaintext  Raw firmware binary
 * @param level      Zstd compression level (1-19, default 3)
 * @return Compressed bytes
 */
std::vector<uint8_t> CompressFirmware(
    std::span<const uint8_t> plaintext,
    int level = 3);

/**
 * Compute SHA-256 digest of data. Convenience for setting payload digest.
 */
std::vector<uint8_t> Sha256(std::span<const uint8_t> data);

} // namespace sum2

#endif /* SUM2_ENCRYPTOR_H */
