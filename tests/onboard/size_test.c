/**
 * Minimal onboard app that exercises the full validation + decryption path.
 * Used to measure linked binary size.
 */
#include "sum2/validator.h"
#include "sum2/decryptor.h"
#include "sum2/orchestrator.h"
#include "sum2/policy.h"

#include <stdio.h>
#include <stdlib.h>

/* Dummy platform callbacks */
static int dummy_fetch(const char *uri, size_t uri_len,
    uint8_t *buf, size_t buf_size, size_t *fetched, void *ctx) {
    (void)uri; (void)uri_len; (void)buf; (void)buf_size;
    (void)fetched; (void)ctx;
    return -1;
}

static int dummy_write(const uint8_t *cid, size_t cid_len,
    size_t offset, const uint8_t *data, size_t data_len, void *ctx) {
    (void)cid; (void)cid_len; (void)offset;
    (void)data; (void)data_len; (void)ctx;
    return -1;
}

static int dummy_invoke(const uint8_t *cid, size_t cid_len, void *ctx) {
    (void)cid; (void)cid_len; (void)ctx;
    return -1;
}

static int dummy_swap(const uint8_t *a, size_t al,
    const uint8_t *b, size_t bl, void *ctx) {
    (void)a; (void)al; (void)b; (void)bl; (void)ctx;
    return -1;
}

static int dummy_persist(const uint8_t *cid, size_t cid_len,
    uint64_t seq, void *ctx) {
    (void)cid; (void)cid_len; (void)seq; (void)ctx;
    return -1;
}

int main(void) {
    /* Create validator with dummy trust anchor */
    uint8_t dummy_key[32] = {0};
    sum2_device_id_t dev_id = {0};

    sum2_validator_t *v = sum2_validator_create(
        dummy_key, sizeof(dummy_key), &dev_id);
    if (!v) {
        fprintf(stderr, "validator_create failed\n");
        return 1;
    }

    /* Set rollback policy */
    sum2_validator_set_min_sequence(v, NULL, 0, 10);
    sum2_validator_set_reject_before(v, 1700000000);

    /* Validate envelope (will fail — no real data) */
    uint8_t dummy_envelope[] = {0xd8, 0x6b, 0xa2}; /* garbage CBOR */
    sum2_manifest_t *m = NULL;
    int rc = sum2_validate_envelope(v, dummy_envelope, sizeof(dummy_envelope),
        1700000001, &m);
    printf("validate_envelope returned: %d\n", rc);

    /* Exercise manifest accessors */
    if (m) {
        printf("seq=%lu components=%zu deps=%zu campaign=%d\n",
            (unsigned long)sum2_manifest_sequence_number(m),
            sum2_manifest_component_count(m),
            sum2_manifest_dependency_count(m),
            sum2_manifest_is_campaign(m));

        /* Try to create decryptor */
        sum2_decryptor_t *d = sum2_decryptor_create(m, 0, dummy_key, 32);
        if (d) {
            uint8_t pt[64];
            size_t pt_len = sizeof(pt);
            sum2_decryptor_update(d, dummy_key, 32, pt, &pt_len);
            sum2_decryptor_finalize(d, pt, &pt_len);
            sum2_decryptor_free(d);
        }

        /* Try orchestrator */
        sum2_platform_ops_t ops = {
            .fetch = dummy_fetch,
            .write = dummy_write,
            .invoke = dummy_invoke,
            .swap = dummy_swap,
            .persist_sequence = dummy_persist,
            .user_ctx = NULL,
        };

        if (sum2_manifest_is_campaign(m)) {
            sum2_process_campaign(v, m, &ops);
        } else {
            sum2_process_image(v, m, &ops);
        }

        sum2_manifest_free(m);
    }

    sum2_validator_free(v);
    return 0;
}
