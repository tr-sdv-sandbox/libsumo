/**
 * @file platform_linux.c
 * @brief File-backed Linux platform implementation. See platform_linux.h.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sumo/platform_linux.h"
#include "sumo/orchestrator.h"
#include "sumo/policy.h"
#include "sumo/validator.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <curl/curl.h>

/* --- Context shared by both ops bundles --- */

typedef struct {
    char *root_dir;
} linux_ctx_t;

static linux_ctx_t *ctx_create(const char *root_dir)
{
    if (!root_dir || !*root_dir) return NULL;
    linux_ctx_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->root_dir = strdup(root_dir);
    if (!c->root_dir) { free(c); return NULL; }

    /* Ensure root + staging exist (best-effort: ignore EEXIST). */
    mkdir(c->root_dir, 0700);
    char staging[1024];
    snprintf(staging, sizeof(staging), "%s/staging", c->root_dir);
    mkdir(staging, 0700);
    return c;
}

static void ctx_destroy(linux_ctx_t *c)
{
    if (!c) return;
    free(c->root_dir);
    free(c);
}

/* Build "<root>/<name>" or "<root>/<sub>/<name>" without overflowing buf. */
static int build_path(char *buf, size_t cap,
                      const char *root, const char *sub, const char *name)
{
    int n = sub ? snprintf(buf, cap, "%s/%s/%s", root, sub, name)
                : snprintf(buf, cap, "%s/%s", root, name);
    if (n < 0 || (size_t)n >= cap) return -1;
    return 0;
}

/* Hex-encode `in` into `out` (must hold 2*len + 1 bytes). */
static void hex_encode(const uint8_t *in, size_t len, char *out)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = hex[(in[i] >> 4) & 0x0f];
        out[2 * i + 1] = hex[in[i] & 0x0f];
    }
    out[2 * len] = '\0';
}

/* Atomic write: open <path>.tmp, write, fsync, rename → <path>. */
static int atomic_write(const char *path, const void *data, size_t len)
{
    char tmp[1100];
    int n = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (n < 0 || (size_t)n >= sizeof(tmp)) return -1;

    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    const uint8_t *p = data;
    size_t left = len;
    while (left > 0) {
        ssize_t w = write(fd, p, left);
        if (w < 0) { if (errno == EINTR) continue; close(fd); unlink(tmp); return -1; }
        p += w; left -= w;
    }
    if (fsync(fd) < 0) { close(fd); unlink(tmp); return -1; }
    if (close(fd) < 0) { unlink(tmp); return -1; }
    if (rename(tmp, path) < 0) { unlink(tmp); return -1; }
    return 0;
}

/* --- storage_ops callbacks --- */

static int store_read_bytes(const char *key, void *out, size_t want, void *user_ctx)
{
    linux_ctx_t *c = user_ctx;
    char path[1100];
    if (build_path(path, sizeof(path), c->root_dir, NULL, key) != 0) return -1;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    uint8_t *p = out;
    size_t left = want;
    while (left > 0) {
        ssize_t r = read(fd, p, left);
        if (r < 0) { if (errno == EINTR) continue; close(fd); return -1; }
        if (r == 0) { close(fd); return -1; }  /* short file */
        p += r; left -= r;
    }
    close(fd);
    return 0;
}

static int store_write_bytes(const char *key, const void *data, size_t len, void *user_ctx)
{
    linux_ctx_t *c = user_ctx;
    char path[1100];
    if (build_path(path, sizeof(path), c->root_dir, NULL, key) != 0) return -1;
    return atomic_write(path, data, len);
}

static int store_read_u64(const char *key, uint64_t *value, void *user_ctx)
{
    uint8_t buf[8];
    if (store_read_bytes(key, buf, sizeof(buf), user_ctx) != 0) return -1;
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= ((uint64_t)buf[i]) << (8 * i);
    *value = v;
    return 0;
}

static int store_write_u64(const char *key, uint64_t value, void *user_ctx)
{
    uint8_t buf[8];
    for (int i = 0; i < 8; i++) buf[i] = (uint8_t)(value >> (8 * i));
    return store_write_bytes(key, buf, sizeof(buf), user_ctx);
}

static int store_read_i64(const char *key, int64_t *value, void *user_ctx)
{
    uint64_t u;
    int rc = store_read_u64(key, &u, user_ctx);
    if (rc != 0) return rc;
    *value = (int64_t)u;
    return 0;
}

static int store_write_i64(const char *key, int64_t value, void *user_ctx)
{
    return store_write_u64(key, (uint64_t)value, user_ctx);
}

/* --- platform_ops callbacks --- */

/* Strip a `file://` prefix from `uri` and copy the remainder, NUL-
 * terminated, into `out`. Returns 0 on success, -1 if it does not look
 * like a local-path URI. */
static int extract_file_path(const char *uri, size_t uri_len,
                             char *out, size_t out_cap)
{
    static const char prefix[] = "file://";
    const size_t prefix_len = sizeof(prefix) - 1;
    if (uri_len >= prefix_len && memcmp(uri, prefix, prefix_len) == 0) {
        uri += prefix_len; uri_len -= prefix_len;
    }
    if (uri_len + 1 > out_cap) return -1;
    memcpy(out, uri, uri_len);
    out[uri_len] = '\0';
    return 0;
}

static int fetch_local_path(const char *path,
                            uint8_t *buf, size_t buf_size, size_t *fetched)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    uint8_t *p = buf;
    size_t left = buf_size;
    size_t got = 0;
    while (left > 0) {
        ssize_t r = read(fd, p, left);
        if (r < 0) { if (errno == EINTR) continue; close(fd); return -1; }
        if (r == 0) break;
        p += r; left -= r; got += r;
    }
    close(fd);
    *fetched = got;
    return 0;
}

/* libcurl write-callback target. */
typedef struct {
    uint8_t *buf;
    size_t   cap;
    size_t   len;
    int      overflow;
} http_sink_t;

static size_t http_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    http_sink_t *s = userdata;
    size_t incoming = size * nmemb;
    if (s->len + incoming > s->cap) {
        s->overflow = 1;
        return 0;  /* abort: signals CURLE_WRITE_ERROR */
    }
    memcpy(s->buf + s->len, ptr, incoming);
    s->len += incoming;
    return incoming;
}

static int fetch_http(const char *uri,
                      uint8_t *buf, size_t buf_size, size_t *fetched)
{
    CURL *c = curl_easy_init();
    if (!c) return -1;

    http_sink_t sink = { .buf = buf, .cap = buf_size, .len = 0, .overflow = 0 };
    curl_easy_setopt(c, CURLOPT_URL, uri);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, http_write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &sink);
    curl_easy_setopt(c, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(c, CURLOPT_NOSIGNAL,    1L);
    curl_easy_setopt(c, CURLOPT_TIMEOUT,     30L);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);

    CURLcode rc = curl_easy_perform(c);
    curl_easy_cleanup(c);

    if (rc != CURLE_OK) return -1;
    *fetched = sink.len;
    return 0;
}

static int plat_fetch(const char *uri, size_t uri_len,
                      uint8_t *buf, size_t buf_size, size_t *fetched,
                      void *user_ctx)
{
    (void)user_ctx;
    if (uri_len >= 7 && memcmp(uri, "http://", 7) == 0) {
        char zuri[1024];
        if (uri_len + 1 > sizeof(zuri)) return -1;
        memcpy(zuri, uri, uri_len);
        zuri[uri_len] = '\0';
        return fetch_http(zuri, buf, buf_size, fetched);
    }
    if (uri_len >= 8 && memcmp(uri, "https://", 8) == 0) {
        char zuri[1024];
        if (uri_len + 1 > sizeof(zuri)) return -1;
        memcpy(zuri, uri, uri_len);
        zuri[uri_len] = '\0';
        return fetch_http(zuri, buf, buf_size, fetched);
    }
    char path[1100];
    if (extract_file_path(uri, uri_len, path, sizeof(path)) != 0) return -1;
    return fetch_local_path(path, buf, buf_size, fetched);
}

/* Component-id keyed file under <root>/staging/<hex(cid)>. */
static int build_component_path(linux_ctx_t *c,
                                const uint8_t *cid, size_t cid_len,
                                char *out, size_t cap)
{
    /* Cap at 64 hex chars (32 bytes of cid). Longer ids get truncated
     * deterministically, which is acceptable for a test/dev backend. */
    char hex[129];
    size_t use = cid_len > 64 ? 64 : cid_len;
    hex_encode(cid, use, hex);
    return build_path(out, cap, c->root_dir, "staging", hex);
}

static int plat_write(const uint8_t *cid, size_t cid_len,
                      size_t offset,
                      const uint8_t *data, size_t data_len,
                      void *user_ctx)
{
    linux_ctx_t *c = user_ctx;
    char path[1100];
    if (build_component_path(c, cid, cid_len, path, sizeof(path)) != 0)
        return -1;

    int fd = open(path, O_WRONLY | O_CREAT, 0600);
    if (fd < 0) return -1;
    if (lseek(fd, (off_t)offset, SEEK_SET) == (off_t)-1) {
        close(fd); return -1;
    }
    const uint8_t *p = data;
    size_t left = data_len;
    while (left > 0) {
        ssize_t w = write(fd, p, left);
        if (w < 0) { if (errno == EINTR) continue; close(fd); return -1; }
        p += w; left -= w;
    }
    fsync(fd);
    close(fd);
    return 0;
}

static int plat_invoke(const uint8_t *cid, size_t cid_len, void *user_ctx)
{
    (void)cid; (void)cid_len; (void)user_ctx;
    /* No actual invocation on a dev host. Caller can override. */
    return 0;
}

static int plat_swap(const uint8_t *a, size_t a_len,
                     const uint8_t *b, size_t b_len,
                     void *user_ctx)
{
    linux_ctx_t *c = user_ctx;
    char pa[1100], pb[1100], pt[1100];
    if (build_component_path(c, a, a_len, pa, sizeof(pa)) != 0) return -1;
    if (build_component_path(c, b, b_len, pb, sizeof(pb)) != 0) return -1;
    int n = snprintf(pt, sizeof(pt), "%s.swap.tmp", pa);
    if (n < 0 || (size_t)n >= sizeof(pt)) return -1;

    /* a → tmp, b → a, tmp → b. EEXIST on tmp is fine; we own it. */
    if (rename(pa, pt) < 0) return -1;
    if (rename(pb, pa) < 0) { rename(pt, pa); return -1; }
    if (rename(pt, pb) < 0) {
        /* Best-effort partial roll-back — primary slot is intact. */
        return -1;
    }
    return 0;
}

static int plat_persist_sequence(const uint8_t *cid, size_t cid_len,
                                 uint64_t seq, void *user_ctx)
{
    /* For now use a single global key. Per-component sequence numbers
     * are tracked separately in T3.3. */
    (void)cid; (void)cid_len;
    return store_write_u64("sumo_seq", seq, user_ctx);
}

/* --- Public factories --- */

sumo_platform_ops_t *sumo_linux_platform_ops(const char *root_dir)
{
    linux_ctx_t *c = ctx_create(root_dir);
    if (!c) return NULL;
    sumo_platform_ops_t *ops = calloc(1, sizeof(*ops));
    if (!ops) { ctx_destroy(c); return NULL; }
    ops->fetch            = plat_fetch;
    ops->write            = plat_write;
    ops->invoke           = plat_invoke;
    ops->swap             = plat_swap;
    ops->persist_sequence = plat_persist_sequence;
    ops->user_ctx         = c;
    return ops;
}

void sumo_linux_platform_ops_free(sumo_platform_ops_t *ops)
{
    if (!ops) return;
    ctx_destroy(ops->user_ctx);
    free(ops);
}

sumo_storage_ops_t *sumo_linux_storage_ops(const char *root_dir)
{
    linux_ctx_t *c = ctx_create(root_dir);
    if (!c) return NULL;
    sumo_storage_ops_t *ops = calloc(1, sizeof(*ops));
    if (!ops) { ctx_destroy(c); return NULL; }
    ops->read_u64  = store_read_u64;
    ops->write_u64 = store_write_u64;
    ops->read_i64  = store_read_i64;
    ops->write_i64 = store_write_i64;
    ops->ctx       = c;
    return ops;
}

void sumo_linux_storage_ops_free(sumo_storage_ops_t *ops)
{
    if (!ops) return;
    ctx_destroy(ops->ctx);
    free(ops);
}
