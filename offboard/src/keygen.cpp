/**
 * @file keygen.cpp
 * @brief COSE_Key generation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sum2/keygen.h"

#include <stdexcept>

namespace sum2 {

CoseKey GenerateSigningKey(int algorithm) {
    (void)algorithm;
    throw std::runtime_error("GenerateSigningKey not yet implemented");
}

CoseKey GenerateDeviceKey(int algorithm) {
    (void)algorithm;
    throw std::runtime_error("GenerateDeviceKey not yet implemented");
}

std::vector<uint8_t> SerializeKey(const CoseKey& key, bool include_private) {
    (void)include_private;
    return key.PublicKeyBytes(); /* returns the raw COSE_Key CBOR */
}

std::string SerializeKeyPem(const CoseKey& key, bool include_private) {
    (void)key; (void)include_private;
    throw std::runtime_error("SerializeKeyPem not yet implemented");
}

} // namespace sum2
