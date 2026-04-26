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

/* Cap the maximum window the decoder is willing to allocate for a
 * frame. zstd's library default is 27 (128 MB) — fine on hosts, lethal
 * on Cortex-M class targets with a few hundred KB of heap. Define this
 * at build time to apply the cap; 0 leaves zstd's default in place. */
#ifndef SUMO_DECOMPRESSOR_WINDOW_LOG_MAX
#  define SUMO_DECOMPRESSOR_WINDOW_LOG_MAX 0
#endif

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

#if SUMO_DECOMPRESSOR_WINDOW_LOG_MAX > 0
    rc = ZSTD_DCtx_setParameter(d->dstream, ZSTD_d_windowLogMax,
                                SUMO_DECOMPRESSOR_WINDOW_LOG_MAX);
    if (ZSTD_isError(rc)) {
        ZSTD_freeDStream(d->dstream);
        free(d);
        return NULL;
    }
#endif

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
