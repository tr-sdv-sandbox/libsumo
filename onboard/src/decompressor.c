/**
 * @file decompressor.c
 * @brief Streaming zstd decompression.
 *
 * Wraps ZSTD_decompressStream() with a simple update/finalize interface
 * matching the decryptor pattern.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sumo/decompressor.h"

#include <zstd.h>
#include <stdlib.h>

struct sumo_decompressor {
    ZSTD_DStream *dstream;
    int finished;  /* zstd reported end of frame */
};

sumo_decompressor_t *sumo_decompressor_create(void)
{
    sumo_decompressor_t *d = calloc(1, sizeof(*d));
    if (!d) return NULL;

    d->dstream = ZSTD_createDStream();
    if (!d->dstream) {
        free(d);
        return NULL;
    }

    size_t rc = ZSTD_initDStream(d->dstream);
    if (ZSTD_isError(rc)) {
        ZSTD_freeDStream(d->dstream);
        free(d);
        return NULL;
    }

    return d;
}

int sumo_decompressor_update(
    sumo_decompressor_t *d,
    const uint8_t *in, size_t *in_len,
    uint8_t *out, size_t *out_len)
{
    if (!d || !d->dstream || !out || !out_len)
        return -1;

    ZSTD_inBuffer input = {
        .src  = in,
        .size = in_len ? *in_len : 0,
        .pos  = 0
    };
    ZSTD_outBuffer output = {
        .dst  = out,
        .size = *out_len,
        .pos  = 0
    };

    size_t rc = ZSTD_decompressStream(d->dstream, &output, &input);
    if (ZSTD_isError(rc)) {
        if (in_len) *in_len = 0;
        *out_len = 0;
        return -1;
    }

    if (rc == 0)
        d->finished = 1;

    if (in_len)
        *in_len = input.pos;   /* bytes consumed */
    *out_len = output.pos;     /* bytes produced */
    return 0;
}

int sumo_decompressor_finalize(sumo_decompressor_t *d)
{
    if (!d) return -1;
    return d->finished ? 0 : -1;
}

void sumo_decompressor_free(sumo_decompressor_t *d)
{
    if (!d) return;
    if (d->dstream) ZSTD_freeDStream(d->dstream);
    free(d);
}
