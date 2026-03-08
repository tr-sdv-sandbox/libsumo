/**
 * @file keygen.cpp
 * @brief COSE_Key generation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sum2/keygen.h"

#include <stdexcept>

#include "csuit_wrapper.h"

namespace sum2 {

CoseKey GenerateSigningKey(int algorithm) {
    /*
     * TODO:
     * - EdDSA (-8): generate Ed25519 keypair
     * - ES256 (-7): generate P-256 keypair
     * Wrap in COSE_Key structure, return as CoseKey
     */
    (void)algorithm;
    throw std::runtime_error("GenerateSigningKey not yet implemented");
}

CoseKey GenerateDeviceKey(int algorithm) {
    /*
     * TODO:
     * - EdDSA (-8): generate X25519 keypair (OKP, crv=4)
     * - ES256 (-7): generate P-256 keypair (EC2, crv=1)
     * Used for ECDH-ES key agreement
     */
    (void)algorithm;
    throw std::runtime_error("GenerateDeviceKey not yet implemented");
}

std::vector<uint8_t> SerializeKey(const CoseKey& key, bool include_private) {
    /*
     * TODO: encode CoseKey as COSE_Key CBOR map
     * { kty, alg, crv, x, [d] }
     */
    (void)key; (void)include_private;
    throw std::runtime_error("SerializeKey not yet implemented");
}

std::string SerializeKeyPem(const CoseKey& key, bool include_private) {
    /*
     * TODO: convert to PEM via crypto backend
     */
    (void)key; (void)include_private;
    throw std::runtime_error("SerializeKeyPem not yet implemented");
}

} // namespace sum2
