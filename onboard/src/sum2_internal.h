/**
 * @file sum2_internal.h
 * @brief Internal cross-module accessors (not part of public API).
 */
#ifndef SUM2_INTERNAL_H
#define SUM2_INTERNAL_H

#include "sum2/validator.h"
#include "csuit/csuit.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Internal definition of the opaque sum2_manifest type.
 * Shared between validator.c, decryptor.c, and orchestrator.c.
 */
struct sum2_manifest {
    suit_envelope_t envelope;
    suit_mechanism_t mechanisms[SUIT_MAX_KEY_NUM];
};

/**
 * Get the device decryption key from a validator.
 * Used internally by the orchestrator to create decryptors.
 */
int sum2_validator_get_device_key(
    const sum2_validator_t *v,
    const uint8_t **key_out, size_t *key_len_out);

#ifdef __cplusplus
}
#endif
#endif /* SUM2_INTERNAL_H */
