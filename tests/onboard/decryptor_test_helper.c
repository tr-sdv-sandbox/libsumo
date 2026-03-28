/**
 * @file decryptor_test_helper.c
 * @brief C helper for decryptor tests — decodes Mac0-authenticated envelopes.
 *
 * suit_common.h uses C keywords (like "delete") as bitfield names,
 * which aren't valid in C++. This helper is compiled as C to avoid
 * that issue.
 */
#include "sumo/validator.h"
#include "csuit/csuit.h"

#include <stdlib.h>
#include <string.h>

/* Must match the layout in validator.c and decryptor.c */
struct sumo_manifest {
    suit_envelope_t envelope;
    suit_mechanism_t mechanisms[SUIT_MAX_KEY_NUM];
};

sumo_manifest_t *test_decode_mac0_envelope(
    const uint8_t *envelope, size_t envelope_len,
    const uint8_t *hmac_key, size_t hmac_key_len)
{
    if (!envelope || !hmac_key) return NULL;

    sumo_manifest_t *m = calloc(1, sizeof(*m));
    if (!m) return NULL;

    /* Set up HMAC256 mechanism for Mac0 verification */
    UsefulBufC cose_key_buf = {hmac_key, hmac_key_len};
    suit_set_suit_key_from_cose_key(cose_key_buf, &m->mechanisms[0].key);
    m->mechanisms[0].cose_tag = COSE_MAC0_TAG;
    m->mechanisms[0].use = true;

    UsefulBufC buf = {envelope, envelope_len};
    suit_err_t err = suit_decode_envelope(buf, &m->envelope, m->mechanisms);
    if (err != SUIT_SUCCESS) {
        free(m);
        return NULL;
    }

    return m;
}
