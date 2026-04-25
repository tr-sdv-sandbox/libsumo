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
 * Get the first registered device decryption key from a validator.
 * Legacy single-key accessor; new callers should prefer
 * sumo_validator_select_device_key() and pass the recipient kid.
 */
int sumo_validator_get_device_key(
    const sumo_validator_t *v,
    const uint8_t **key_out, size_t *key_len_out);

/**
 * Select a device decryption key by recipient kid.
 *
 * If `kid` is non-NULL and non-empty, the validator's registered keys
 * are searched for an exact kid match; on miss, returns
 * SUMO_ERR_DECRYPT_FAILED. If `kid` is NULL or empty, the first
 * registered key is returned (single-device legacy behaviour).
 *
 * Returns SUMO_ERR_UNSUPPORTED when no device keys have been registered.
 */
int sumo_validator_select_device_key(
    const sumo_validator_t *v,
    const uint8_t *kid, size_t kid_len,
    const uint8_t **key_out, size_t *key_len_out);

#ifdef __cplusplus
}
#endif
#endif /* SUMO_INTERNAL_H */
