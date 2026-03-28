/**
 * @file sumo_internal.h
 * @brief Internal cross-module accessors (not part of public API).
 */
#ifndef SUMO_INTERNAL_H
#define SUMO_INTERNAL_H

#include "sumo/validator.h"
#include "csuit/csuit.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Internal definition of the opaque sumo_manifest type.
 * Shared between validator.c, decryptor.c, and orchestrator.c.
 */
struct sumo_manifest {
    suit_envelope_t envelope;
    suit_mechanism_t mechanisms[SUIT_MAX_KEY_NUM];
};

/**
 * Get the device decryption key from a validator.
 * Used internally by the orchestrator to create decryptors.
 */
int sumo_validator_get_device_key(
    const sumo_validator_t *v,
    const uint8_t **key_out, size_t *key_len_out);

#ifdef __cplusplus
}
#endif
#endif /* SUMO_INTERNAL_H */
