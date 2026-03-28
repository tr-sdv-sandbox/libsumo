/**
 * @file cose_key_impl.h
 * @brief Internal definition of CoseKey::Impl shared between translation units.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef SUMO_COSE_KEY_IMPL_H
#define SUMO_COSE_KEY_IMPL_H

#include "sumo/image_builder.h"

#include <openssl/evp.h>

namespace sumo {

struct CoseKey::Impl {
    std::vector<uint8_t> key_bytes;        // COSE_Key CBOR (may include private)
    std::vector<uint8_t> public_key_bytes; // Public-only COSE_Key CBOR
    std::vector<uint8_t> kid;
    int algorithm = 0;
    EVP_PKEY *evp_pkey = nullptr;          // For PEM export (owned, nullable)

    ~Impl() {
        if (evp_pkey) EVP_PKEY_free(evp_pkey);
    }
};

} // namespace sumo

#endif /* SUMO_COSE_KEY_IMPL_H */
