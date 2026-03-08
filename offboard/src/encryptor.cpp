/**
 * @file encryptor.cpp
 * @brief Firmware encryption with per-device COSE_Encrypt key wrapping.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sum2/encryptor.h"

#include <stdexcept>

#include "csuit_wrapper.h"

namespace sum2 {

EncryptedPayload EncryptFirmware(
    std::span<const uint8_t> plaintext,
    std::span<const Recipient> recipients)
{
    /*
     * TODO: implementation outline:
     *
     * 1. Generate random 16-byte CEK (AES-128)
     * 2. Generate random 12-byte IV (GCM nonce)
     * 3. Encrypt plaintext with AES-128-GCM:
     *    - Use libcsuit's suit_encrypt_cose_encrypt() for COSE structure, OR
     *    - Use crypto backend directly for the bulk encryption
     *    - GCM tag appended to ciphertext (COSE convention)
     *
     * 4. For each recipient:
     *    a. Generate ephemeral ECDH keypair
     *    b. Compute shared secret via ECDH (ephemeral priv + recipient pub)
     *    c. Derive KEK via HKDF-SHA256 with COSE_KDF_Context
     *    d. Wrap CEK with AES-KW using derived KEK
     *    e. Build COSE_recipient structure
     *
     * 5. Build COSE_Encrypt CBOR structure:
     *    - protected: { alg: AES-128-GCM }
     *    - unprotected: { iv: <nonce> }
     *    - ciphertext: nil (detached — ciphertext returned separately)
     *    - recipients: [ ... ]
     *
     * 6. Return { ciphertext, COSE_Encrypt CBOR }
     */

    (void)plaintext;
    (void)recipients;
    throw std::runtime_error("EncryptFirmware not yet implemented");
}

std::vector<uint8_t> Sha256(std::span<const uint8_t> data) {
    /*
     * TODO: compute SHA-256 via crypto backend
     * Can use libcsuit's suit_digest or call backend directly
     */
    (void)data;
    throw std::runtime_error("Sha256 not yet implemented");
}

} // namespace sum2
