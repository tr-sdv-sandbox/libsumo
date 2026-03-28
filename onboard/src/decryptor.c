/**
 * @file decryptor.c
 * @brief Streaming AES-GCM decryption.
 *
 * Parses COSE_Encrypt structure from the manifest's encryption-info
 * parameter, unwraps the CEK (A128KW or ECDH-ES+A128KW), then provides
 * a streaming AES-128-GCM decryption interface via OpenSSL EVP.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sumo/decryptor.h"
#include "sumo/validator.h"
#include "sumo_internal.h"

#include <stdlib.h>
#include <string.h>

/* libcsuit / QCBOR for CBOR parsing + encoding (Enc_structure AAD) */
#include "csuit/csuit.h"
#include "qcbor/qcbor_decode.h"
#include "qcbor/qcbor_encode.h"

/* OpenSSL for AES-GCM streaming + AES key unwrap + ECDH + HKDF */
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/kdf.h>

/* Suppress OpenSSL 3.0 deprecation warnings for EC_KEY API
 * (same approach as t_cose — EC_KEY works fine, just deprecated) */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#define GCM_TAG_LEN 16
#define GCM_IV_LEN  12
#define CEK_LEN     16  /* AES-128 */

struct sumo_decryptor {
    uint8_t cek[CEK_LEN]; /* unwrapped AES-128 key */
    uint8_t iv[GCM_IV_LEN];
    EVP_CIPHER_CTX *ctx;
    /* GCM tag buffering: caller streams ciphertext which has
     * the 16-byte tag appended. We buffer the trailing 16 bytes
     * and set them as the GCM tag at finalize time. */
    uint8_t tail[GCM_TAG_LEN];
    size_t tail_len;
    int initialized;
};

/* --- COSE_Encrypt CBOR parsing --- */

/**
 * Parse a COSE_Encrypt structure to extract IV and wrapped CEK.
 *
 * COSE_Encrypt = [
 *   protected,    // bstr: serialized map {1: alg}
 *   unprotected,  // map {5: IV}
 *   ciphertext,   // null (detached)
 *   recipients    // array of COSE_recipient
 * ]
 *
 * COSE_recipient = [
 *   protected,    // bstr
 *   unprotected,  // map {1: alg, 4: kid, ...}
 *   ciphertext    // bstr: wrapped CEK
 * ]
 */
static int parse_cose_encrypt(
    const uint8_t *enc_info, size_t enc_info_len,
    uint8_t iv_out[GCM_IV_LEN],
    uint8_t *wrapped_cek_out, size_t *wrapped_cek_len,
    int *recipient_alg_out,
    const uint8_t **prot_hdr_out, size_t *prot_hdr_len_out)
{
    QCBORDecodeContext ctx;
    QCBORItem item;
    UsefulBufC enc_buf = {enc_info, enc_info_len};

    QCBORDecode_Init(&ctx, enc_buf, QCBOR_DECODE_MODE_NORMAL);

    /* Optional CBOR tag 96 (COSE_Encrypt) */
    QCBORDecode_PeekNext(&ctx, &item);
    if (item.uDataType == QCBOR_TYPE_ARRAY && item.val.uCount >= 4) {
        /* Tagged or untagged array — enter it */
    }
    QCBORDecode_EnterArray(&ctx, NULL);

    /* [0] protected header — bstr containing serialized CBOR map */
    QCBORDecode_GetNext(&ctx, &item);
    if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
        *prot_hdr_out = item.val.string.ptr;
        *prot_hdr_len_out = item.val.string.len;
    } else {
        *prot_hdr_out = NULL;
        *prot_hdr_len_out = 0;
    }

    /* [1] unprotected header — map containing IV (label 5) */
    QCBORDecode_EnterMap(&ctx, NULL);
    int got_iv = 0;
    while (1) {
        QCBORError err = QCBORDecode_GetNext(&ctx, &item);
        if (err != QCBOR_SUCCESS) break;
        if (item.label.int64 == 5 && item.uDataType == QCBOR_TYPE_BYTE_STRING) {
            if (item.val.string.len == GCM_IV_LEN) {
                memcpy(iv_out, item.val.string.ptr, GCM_IV_LEN);
                got_iv = 1;
            }
        }
    }
    QCBORDecode_ExitMap(&ctx);
    if (!got_iv) return -1;

    /* [2] ciphertext — should be null (detached) */
    QCBORDecode_GetNext(&ctx, &item);

    /* [3] recipients array */
    QCBORDecode_EnterArray(&ctx, NULL);

    /* First recipient */
    QCBORDecode_EnterArray(&ctx, NULL);

    /* recipient[0] protected header — may contain algorithm (ECDH-ES case) */
    *recipient_alg_out = 0;
    QCBORDecode_GetNext(&ctx, &item);
    if (item.uDataType == QCBOR_TYPE_BYTE_STRING && item.val.string.len > 0) {
        /* Parse the protected header bstr to find alg */
        QCBORDecodeContext prot_ctx;
        QCBORItem prot_item;
        QCBORDecode_Init(&prot_ctx, item.val.string, QCBOR_DECODE_MODE_NORMAL);
        QCBORDecode_EnterMap(&prot_ctx, NULL);
        while (QCBORDecode_GetNext(&prot_ctx, &prot_item) == QCBOR_SUCCESS) {
            if (prot_item.label.int64 == 1) {
                if (prot_item.uDataType == QCBOR_TYPE_INT64)
                    *recipient_alg_out = (int)prot_item.val.int64;
                else if (prot_item.uDataType == QCBOR_TYPE_UINT64)
                    *recipient_alg_out = (int)prot_item.val.uint64;
            }
        }
    }

    /* recipient[1] unprotected header — get alg (A128KW case) and kid */
    QCBORDecode_EnterMap(&ctx, NULL);
    while (1) {
        QCBORError err = QCBORDecode_GetNext(&ctx, &item);
        if (err != QCBOR_SUCCESS) break;
        if (item.label.int64 == 1 && *recipient_alg_out == 0) {
            /* algorithm — only if not already found in protected header */
            if (item.uDataType == QCBOR_TYPE_INT64) {
                *recipient_alg_out = (int)item.val.int64;
            } else if (item.uDataType == QCBOR_TYPE_UINT64) {
                *recipient_alg_out = (int)item.val.uint64;
            }
        }
    }
    QCBORDecode_ExitMap(&ctx);

    /* recipient[2] ciphertext — the wrapped CEK */
    QCBORDecode_GetNext(&ctx, &item);
    if (item.uDataType != QCBOR_TYPE_BYTE_STRING || item.val.string.len == 0)
        return -1;
    if (item.val.string.len > *wrapped_cek_len)
        return -1;
    memcpy(wrapped_cek_out, item.val.string.ptr, item.val.string.len);
    *wrapped_cek_len = item.val.string.len;

    /* Don't bother fully closing — we have what we need */
    return 0;
}

/* Forward declaration — defined below */
static int unwrap_cek_a128kw(
    const uint8_t *kek, size_t kek_len,
    const uint8_t *wrapped_cek, size_t wrapped_len,
    uint8_t cek_out[CEK_LEN]);

/* --- ECDH-ES+A128KW helpers --- */

#define P256_COORD_LEN 32

/**
 * Parse a COSE_Key map to extract EC2 P-256 key components.
 * Extracts x, y (always) and d (if present, for private keys).
 */
static int parse_ec2_cose_key(
    const uint8_t *cose_key, size_t len,
    uint8_t x[P256_COORD_LEN], uint8_t y[P256_COORD_LEN],
    uint8_t d[P256_COORD_LEN], int *has_d)
{
    QCBORDecodeContext ctx;
    QCBORItem item;
    UsefulBufC buf = {cose_key, len};
    int got_x = 0, got_y = 0;

    *has_d = 0;
    QCBORDecode_Init(&ctx, buf, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_EnterMap(&ctx, NULL);

    while (1) {
        QCBORError err = QCBORDecode_GetNext(&ctx, &item);
        if (err != QCBOR_SUCCESS) break;
        if (item.uDataType != QCBOR_TYPE_BYTE_STRING) continue;
        if (item.val.string.len != P256_COORD_LEN) continue;

        if (item.label.int64 == -2) {
            memcpy(x, item.val.string.ptr, P256_COORD_LEN);
            got_x = 1;
        } else if (item.label.int64 == -3) {
            memcpy(y, item.val.string.ptr, P256_COORD_LEN);
            got_y = 1;
        } else if (item.label.int64 == -4) {
            memcpy(d, item.val.string.ptr, P256_COORD_LEN);
            *has_d = 1;
        }
    }
    return (got_x && got_y) ? 0 : -1;
}

/**
 * Parse the ECDH ephemeral public key from the first recipient's
 * unprotected header in a COSE_Encrypt structure.
 *
 * Also captures the recipient's protected header (needed for KDF context).
 */
static int parse_ecdh_ephemeral(
    const uint8_t *enc_info, size_t enc_info_len,
    uint8_t ephem_x[P256_COORD_LEN], uint8_t ephem_y[P256_COORD_LEN],
    const uint8_t **rcpt_prot_hdr, size_t *rcpt_prot_hdr_len)
{
    QCBORDecodeContext ctx;
    QCBORItem item;
    UsefulBufC enc_buf = {enc_info, enc_info_len};

    QCBORDecode_Init(&ctx, enc_buf, QCBOR_DECODE_MODE_NORMAL);

    /* Enter COSE_Encrypt array */
    QCBORDecode_EnterArray(&ctx, NULL);

    /* [0] protected header — skip */
    QCBORDecode_GetNext(&ctx, &item);

    /* [1] unprotected header — skip */
    QCBORDecode_EnterMap(&ctx, NULL);
    while (QCBORDecode_GetNext(&ctx, &item) == QCBOR_SUCCESS) {}
    QCBORDecode_ExitMap(&ctx);

    /* [2] ciphertext — skip */
    QCBORDecode_GetNext(&ctx, &item);

    /* [3] recipients array */
    QCBORDecode_EnterArray(&ctx, NULL);

    /* First recipient array */
    QCBORDecode_EnterArray(&ctx, NULL);

    /* recipient[0] protected header */
    QCBORDecode_GetNext(&ctx, &item);
    if (item.uDataType == QCBOR_TYPE_BYTE_STRING) {
        *rcpt_prot_hdr = item.val.string.ptr;
        *rcpt_prot_hdr_len = item.val.string.len;
    } else {
        *rcpt_prot_hdr = NULL;
        *rcpt_prot_hdr_len = 0;
    }

    /* recipient[1] unprotected header — find ephemeral key (label -1) */
    int got_x = 0, got_y = 0;
    QCBORDecode_EnterMap(&ctx, NULL);
    while (1) {
        QCBORError err = QCBORDecode_GetNext(&ctx, &item);
        if (err != QCBOR_SUCCESS) break;

        if (item.label.int64 == -1 && item.uDataType == QCBOR_TYPE_MAP) {
            /* Ephemeral COSE_Key — enter and parse x, y */
            /* The map is already "entered" by GetNext consuming its header.
             * We need to read its child items. With spiffy decode after
             * EnterMap, nested containers returned by GetNext are NOT
             * auto-entered, so we must EnterMap explicitly. But we already
             * got the map item. In QCBOR spiffy decode, after EnterMap,
             * GetNext returns items at the current level, skipping nested
             * containers entirely — so the map at -1 is returned as a
             * single item and its contents are consumed.
             *
             * We can't re-enter it. Instead, we'll parse the ephemeral
             * key separately below. Just note that we found label -1. */
        }
    }
    QCBORDecode_ExitMap(&ctx);

    /* The spiffy decode approach makes it hard to enter nested maps.
     * Parse the ephemeral key with a second pass using a raw decode. */
    {
        QCBORDecodeContext ctx2;
        QCBORItem item2;
        QCBORDecode_Init(&ctx2, enc_buf, QCBOR_DECODE_MODE_NORMAL);

        /* We need to find the ephemeral key map nested inside the
         * recipient unprotected header. Use raw (non-spiffy) traversal:
         * scan all items looking for the COSE_Key fields at the right
         * nesting level. The ephemeral COSE_Key is inside:
         *   COSE_Encrypt[3][0][1]{-1}{-2: x, -3: y}
         *
         * Strategy: walk all items, track depth. When we see a map-entry
         * with label -1 at the right depth, the next items are the
         * COSE_Key fields. */
        int depth = 0;
        int in_ephem = 0;
        int ephem_depth = 0;

        while (QCBORDecode_GetNext(&ctx2, &item2) == QCBOR_SUCCESS) {
            /* Track depth from array/map opens/closes */
            /* In raw mode, arrays and maps have uNestingLevel */

            if (in_ephem) {
                if ((int)item2.uNestingLevel <= ephem_depth) {
                    /* Left the ephemeral key map */
                    break;
                }
                if (item2.uDataType == QCBOR_TYPE_BYTE_STRING &&
                    item2.val.string.len == P256_COORD_LEN) {
                    if (item2.label.int64 == -2) {
                        memcpy(ephem_x, item2.val.string.ptr, P256_COORD_LEN);
                        got_x = 1;
                    } else if (item2.label.int64 == -3) {
                        memcpy(ephem_y, item2.val.string.ptr, P256_COORD_LEN);
                        got_y = 1;
                    }
                }
            }

            /* Detect the ephemeral key map: label -1, type map.
             * It's nested inside the recipient unprotected header. */
            if (!in_ephem &&
                item2.label.int64 == -1 &&
                item2.uDataType == QCBOR_TYPE_MAP) {
                in_ephem = 1;
                ephem_depth = (int)item2.uNestingLevel;
            }
        }
    }

    return (got_x && got_y) ? 0 : -1;
}

/**
 * Create an OpenSSL EVP_PKEY for a P-256 public key from raw x,y coordinates.
 */
static EVP_PKEY *create_ec_pubkey(const uint8_t x[P256_COORD_LEN],
                                   const uint8_t y[P256_COORD_LEN])
{
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key) return NULL;

    /* Build uncompressed point: 0x04 || x || y */
    uint8_t point[1 + P256_COORD_LEN * 2];
    point[0] = 0x04;
    memcpy(point + 1, x, P256_COORD_LEN);
    memcpy(point + 1 + P256_COORD_LEN, y, P256_COORD_LEN);

    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    EC_POINT *ec_point = EC_POINT_new(group);
    if (!ec_point) { EC_KEY_free(ec_key); return NULL; }

    if (EC_POINT_oct2point(group, ec_point, point, sizeof(point), NULL) != 1) {
        EC_POINT_free(ec_point);
        EC_KEY_free(ec_key);
        return NULL;
    }

    EC_KEY_set_public_key(ec_key, ec_point);
    EC_POINT_free(ec_point);

    pkey = EVP_PKEY_new();
    if (!pkey) { EC_KEY_free(ec_key); return NULL; }
    EVP_PKEY_set1_EC_KEY(pkey, ec_key);
    EC_KEY_free(ec_key);
    return pkey;
}

/**
 * Create an OpenSSL EVP_PKEY for a P-256 private key from raw d,x,y.
 */
static EVP_PKEY *create_ec_privkey(const uint8_t d[P256_COORD_LEN],
                                    const uint8_t x[P256_COORD_LEN],
                                    const uint8_t y[P256_COORD_LEN])
{
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key) return NULL;

    BIGNUM *bn_d = BN_bin2bn(d, P256_COORD_LEN, NULL);
    if (!bn_d) { EC_KEY_free(ec_key); return NULL; }

    if (EC_KEY_set_private_key(ec_key, bn_d) != 1) {
        BN_clear_free(bn_d);
        EC_KEY_free(ec_key);
        return NULL;
    }
    BN_clear_free(bn_d);

    /* Also set the public key */
    uint8_t point[1 + P256_COORD_LEN * 2];
    point[0] = 0x04;
    memcpy(point + 1, x, P256_COORD_LEN);
    memcpy(point + 1 + P256_COORD_LEN, y, P256_COORD_LEN);

    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    EC_POINT *ec_point = EC_POINT_new(group);
    if (!ec_point) { EC_KEY_free(ec_key); return NULL; }

    if (EC_POINT_oct2point(group, ec_point, point, sizeof(point), NULL) != 1) {
        EC_POINT_free(ec_point);
        EC_KEY_free(ec_key);
        return NULL;
    }
    EC_KEY_set_public_key(ec_key, ec_point);
    EC_POINT_free(ec_point);

    pkey = EVP_PKEY_new();
    if (!pkey) { EC_KEY_free(ec_key); return NULL; }
    EVP_PKEY_set1_EC_KEY(pkey, ec_key);
    EC_KEY_free(ec_key);
    return pkey;
}

/**
 * Build the COSE_KDF_Context CBOR for ECDH-ES+A128KW.
 *
 * COSE_KDF_Context = [
 *   AlgorithmID: -3,           // A128KW
 *   PartyUInfo: [null, null, null],
 *   PartyVInfo: [null, null, null],
 *   SuppPubInfo: [128, protected_header_bstr]
 * ]
 */
static int build_kdf_context(
    const uint8_t *rcpt_prot_hdr, size_t rcpt_prot_hdr_len,
    uint8_t *out, size_t out_size, size_t *out_len)
{
    QCBOREncodeContext enc;
    UsefulBuf buf = {out, out_size};
    QCBOREncode_Init(&enc, buf);

    QCBOREncode_OpenArray(&enc);

    /* AlgorithmID: A128KW = -3 */
    QCBOREncode_AddInt64(&enc, -3);

    /* PartyUInfo: [null, null, null] */
    QCBOREncode_OpenArray(&enc);
    QCBOREncode_AddNULL(&enc);
    QCBOREncode_AddNULL(&enc);
    QCBOREncode_AddNULL(&enc);
    QCBOREncode_CloseArray(&enc);

    /* PartyVInfo: [null, null, null] */
    QCBOREncode_OpenArray(&enc);
    QCBOREncode_AddNULL(&enc);
    QCBOREncode_AddNULL(&enc);
    QCBOREncode_AddNULL(&enc);
    QCBOREncode_CloseArray(&enc);

    /* SuppPubInfo: [keyDataLength=128, protected_header, "SUIT Payload Encryption"] */
    QCBOREncode_OpenArray(&enc);
    QCBOREncode_AddUInt64(&enc, 128);
    UsefulBufC prot = {rcpt_prot_hdr, rcpt_prot_hdr_len};
    QCBOREncode_AddBytes(&enc, prot);
    /* supp_pub_other — matches libcsuit's suit_encrypt_cose_encrypt_esdh() */
    UsefulBufC supp_pub_other = {
        (const uint8_t *)"SUIT Payload Encryption", 23};
    QCBOREncode_AddBytes(&enc, supp_pub_other);
    QCBOREncode_CloseArray(&enc);

    QCBOREncode_CloseArray(&enc);

    UsefulBufC encoded;
    if (QCBOREncode_Finish(&enc, &encoded) != QCBOR_SUCCESS)
        return -1;

    *out_len = encoded.len;
    return 0;
}

/**
 * Unwrap CEK using ECDH-ES+A128KW.
 *
 * @param device_cose_key   Device's COSE_Key CBOR (P-256 private key)
 * @param dk_len            Length of device COSE_Key
 * @param enc_info          Raw encryption_info CBOR (COSE_Encrypt)
 * @param enc_info_len      Length of encryption_info
 * @param wrapped_cek       A128KW-wrapped CEK from parse_cose_encrypt()
 * @param wrapped_cek_len   Length of wrapped CEK
 * @param cek_out           Output: unwrapped 16-byte CEK
 */
static int unwrap_cek_esdh(
    const uint8_t *device_cose_key, size_t dk_len,
    const uint8_t *enc_info, size_t enc_info_len,
    const uint8_t *wrapped_cek, size_t wrapped_cek_len,
    uint8_t cek_out[CEK_LEN])
{
    int ret = -1;
    EVP_PKEY *priv_key = NULL;
    EVP_PKEY *ephem_key = NULL;
    EVP_PKEY_CTX *derive_ctx = NULL;
    EVP_PKEY_CTX *hkdf_ctx = NULL;

    /* 1. Parse device private key */
    uint8_t dev_x[P256_COORD_LEN], dev_y[P256_COORD_LEN], dev_d[P256_COORD_LEN];
    int has_d = 0;
    if (parse_ec2_cose_key(device_cose_key, dk_len,
                           dev_x, dev_y, dev_d, &has_d) != 0 || !has_d)
        goto out;

    /* 2. Parse ephemeral public key from COSE_Encrypt recipient */
    uint8_t ephem_x[P256_COORD_LEN], ephem_y[P256_COORD_LEN];
    const uint8_t *rcpt_prot_hdr = NULL;
    size_t rcpt_prot_hdr_len = 0;
    if (parse_ecdh_ephemeral(enc_info, enc_info_len,
                              ephem_x, ephem_y,
                              &rcpt_prot_hdr, &rcpt_prot_hdr_len) != 0)
        goto out;

    /* 3. Create OpenSSL key handles */
    priv_key = create_ec_privkey(dev_d, dev_x, dev_y);
    ephem_key = create_ec_pubkey(ephem_x, ephem_y);
    if (!priv_key || !ephem_key) goto out;

    /* 4. ECDH key agreement */
    uint8_t shared_secret[P256_COORD_LEN]; /* P-256 shared secret = 32 bytes */
    size_t shared_len = sizeof(shared_secret);

    derive_ctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!derive_ctx) goto out;
    if (EVP_PKEY_derive_init(derive_ctx) != 1) goto out;
    if (EVP_PKEY_derive_set_peer(derive_ctx, ephem_key) != 1) goto out;
    if (EVP_PKEY_derive(derive_ctx, shared_secret, &shared_len) != 1) goto out;

    /* 5. Build KDF context */
    uint8_t kdf_ctx_buf[128];
    size_t kdf_ctx_len = 0;
    if (build_kdf_context(rcpt_prot_hdr, rcpt_prot_hdr_len,
                          kdf_ctx_buf, sizeof(kdf_ctx_buf), &kdf_ctx_len) != 0)
        goto out;

    /* 6. HKDF-SHA256: derive 16-byte KEK */
    uint8_t kek[CEK_LEN];
    size_t kek_len = CEK_LEN;

    hkdf_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!hkdf_ctx) goto out;
    if (EVP_PKEY_derive_init(hkdf_ctx) != 1) goto out;
    if (EVP_PKEY_CTX_set_hkdf_md(hkdf_ctx, EVP_sha256()) != 1) goto out;
    if (EVP_PKEY_CTX_set1_hkdf_salt(hkdf_ctx, (const unsigned char *)"", 0) != 1) goto out;
    if (EVP_PKEY_CTX_set1_hkdf_key(hkdf_ctx, shared_secret, (int)shared_len) != 1) goto out;
    if (EVP_PKEY_CTX_add1_hkdf_info(hkdf_ctx, kdf_ctx_buf, (int)kdf_ctx_len) != 1) goto out;
    if (EVP_PKEY_derive(hkdf_ctx, kek, &kek_len) != 1) goto out;

    /* 7. A128KW unwrap CEK */
    ret = unwrap_cek_a128kw(kek, kek_len, wrapped_cek, wrapped_cek_len, cek_out);

    OPENSSL_cleanse(kek, sizeof(kek));
    OPENSSL_cleanse(shared_secret, sizeof(shared_secret));

out:
    OPENSSL_cleanse(dev_d, sizeof(dev_d));
    if (hkdf_ctx) EVP_PKEY_CTX_free(hkdf_ctx);
    if (derive_ctx) EVP_PKEY_CTX_free(derive_ctx);
    if (ephem_key) EVP_PKEY_free(ephem_key);
    if (priv_key) EVP_PKEY_free(priv_key);
    return ret;
}

/* --- CEK unwrap --- */

static int unwrap_cek_a128kw(
    const uint8_t *kek, size_t kek_len,
    const uint8_t *wrapped_cek, size_t wrapped_len,
    uint8_t cek_out[CEK_LEN])
{
    if (kek_len != CEK_LEN) return -1;
    /* A128KW wrapped output is CEK_LEN + 8 bytes */
    if (wrapped_len != CEK_LEN + 8) return -1;

    int ret = -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_wrap(), NULL, kek, NULL) != 1)
        goto out;

    int outl = 0;
    if (EVP_DecryptUpdate(ctx, cek_out, &outl,
                          wrapped_cek, (int)wrapped_len) != 1)
        goto out;

    int finl = 0;
    if (EVP_DecryptFinal_ex(ctx, cek_out + outl, &finl) != 1)
        goto out;

    ret = ((outl + finl) == CEK_LEN) ? 0 : -1;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/* --- Encryption info extraction from manifest --- */

/**
 * Search both shared and install/fetch command sequences for
 * the encryption_info parameter (label 19) for a given component.
 */
static UsefulBufC find_encryption_info(
    const sumo_manifest_t *m, size_t component_index);

/* sumo_manifest is defined in sumo_internal.h */

static UsefulBufC search_cmd_seq_for_param(
    const suit_command_sequence_t *seq,
    size_t component_index, int64_t param_label)
{
    UsefulBufC empty = {NULL, 0};
    for (size_t i = 0; i < seq->len; i++) {
        const suit_command_sequence_item_t *cmd = &seq->commands[i];
        if (cmd->label != SUIT_DIRECTIVE_OVERRIDE_PARAMETERS &&
            cmd->label != SUIT_DIRECTIVE_SET_PARAMETERS)
            continue;

        const suit_parameters_list_t *pl = &cmd->value.params_list;
        if (pl->index != (uint8_t)component_index)
            continue;

        for (size_t j = 0; j < pl->len; j++) {
            if (pl->params[j].label == param_label)
                return pl->params[j].value.string;
        }
    }
    return empty;
}

static UsefulBufC find_encryption_info(
    const sumo_manifest_t *m, size_t component_index)
{
    UsefulBufC result;
    const suit_manifest_t *man = &m->envelope.manifest;

    /* Check shared sequence first */
    result = search_cmd_seq_for_param(&man->common.shared_seq,
                                       component_index,
                                       SUIT_PARAMETER_ENCRYPTION_INFO);
    if (result.ptr) return result;

    /* Check install sequence */
    result = search_cmd_seq_for_param(&man->sev_man_mem.install,
                                       component_index,
                                       SUIT_PARAMETER_ENCRYPTION_INFO);
    if (result.ptr) return result;

    /* Check payload_fetch sequence */
    result = search_cmd_seq_for_param(&man->sev_man_mem.payload_fetch,
                                       component_index,
                                       SUIT_PARAMETER_ENCRYPTION_INFO);
    return result;
}

/* --- Public API --- */

sumo_decryptor_t *sumo_decryptor_create(
    const sumo_manifest_t *manifest,
    size_t component_index,
    const uint8_t *device_key, size_t dk_len)
{
    if (!manifest || !device_key) return NULL;

    /* Extract encryption_info CBOR from the manifest */
    UsefulBufC enc_info = find_encryption_info(manifest, component_index);
    if (!enc_info.ptr || enc_info.len == 0) return NULL;

    /* Parse the COSE_Encrypt structure */
    uint8_t iv[GCM_IV_LEN];
    uint8_t wrapped_cek[CEK_LEN + 8 + 16]; /* room for A128KW or larger */
    size_t wrapped_cek_len = sizeof(wrapped_cek);
    int recipient_alg = 0;
    const uint8_t *prot_hdr = NULL;
    size_t prot_hdr_len = 0;

    if (parse_cose_encrypt(enc_info.ptr, enc_info.len,
                           iv, wrapped_cek, &wrapped_cek_len,
                           &recipient_alg,
                           &prot_hdr, &prot_hdr_len) != 0) {
        return NULL;
    }

    /* Unwrap the CEK based on recipient algorithm */
    uint8_t cek[CEK_LEN];
    if (recipient_alg == -3) {
        /* A128KW: device_key is the 16-byte KEK */
        if (unwrap_cek_a128kw(device_key, dk_len,
                              wrapped_cek, wrapped_cek_len, cek) != 0) {
            return NULL;
        }
    } else if (recipient_alg == -29) {
        /* ECDH-ES+A128KW: device_key is COSE_Key CBOR (P-256 private key) */
        if (unwrap_cek_esdh(device_key, dk_len,
                            enc_info.ptr, enc_info.len,
                            wrapped_cek, wrapped_cek_len, cek) != 0) {
            return NULL;
        }
    } else {
        return NULL; /* Unsupported algorithm */
    }

    /* Allocate and initialize the decryptor */
    sumo_decryptor_t *d = calloc(1, sizeof(*d));
    if (!d) {
        OPENSSL_cleanse(cek, sizeof(cek));
        return NULL;
    }

    memcpy(d->cek, cek, CEK_LEN);
    memcpy(d->iv, iv, GCM_IV_LEN);
    OPENSSL_cleanse(cek, sizeof(cek));

    d->ctx = EVP_CIPHER_CTX_new();
    if (!d->ctx) goto fail;

    if (EVP_DecryptInit_ex(d->ctx, EVP_aes_128_gcm(),
                           NULL, NULL, NULL) != 1)
        goto fail;

    if (EVP_CIPHER_CTX_ctrl(d->ctx, EVP_CTRL_GCM_SET_IVLEN,
                            GCM_IV_LEN, NULL) != 1)
        goto fail;

    if (EVP_DecryptInit_ex(d->ctx, NULL, NULL, d->cek, d->iv) != 1)
        goto fail;

    /* Build COSE Enc_structure AAD per RFC 9052 Section 5.3:
     *   Enc_structure = ["Encrypt", protected_header, external_aad]
     * where external_aad is empty (h''). */
    {
        uint8_t aad_buf[64];
        UsefulBuf aad_usbuf = {aad_buf, sizeof(aad_buf)};
        UsefulBufC aad_encoded;
        QCBOREncodeContext qenc;

        QCBOREncode_Init(&qenc, aad_usbuf);
        QCBOREncode_OpenArray(&qenc);
        QCBOREncode_AddSZString(&qenc, "Encrypt");
        UsefulBufC prot_hdr_buf = {prot_hdr, prot_hdr_len};
        QCBOREncode_AddBytes(&qenc, prot_hdr_buf);
        UsefulBufC empty_aad = {NULL, 0};
        QCBOREncode_AddBytes(&qenc, empty_aad);
        QCBOREncode_CloseArray(&qenc);

        if (QCBOREncode_Finish(&qenc, &aad_encoded) != QCBOR_SUCCESS)
            goto fail;

        int outl = 0;
        if (EVP_DecryptUpdate(d->ctx, NULL, &outl,
                              aad_encoded.ptr, (int)aad_encoded.len) != 1)
            goto fail;
    }

    d->initialized = 1;
    return d;

fail:
    if (d->ctx) EVP_CIPHER_CTX_free(d->ctx);
    OPENSSL_cleanse(d, sizeof(*d));
    free(d);
    return NULL;
}

int sumo_decryptor_update(
    sumo_decryptor_t *d,
    const uint8_t *ct, size_t ct_len,
    uint8_t *pt, size_t *pt_len)
{
    if (!d || !d->ctx || !d->initialized || !ct || !pt || !pt_len)
        return -1;

    /*
     * GCM tag handling: in COSE, the GCM authentication tag (16 bytes)
     * is appended to the ciphertext. We need to hold back the last 16
     * bytes and set them as the GCM tag at finalize time.
     *
     * Strategy: maintain a 16-byte tail buffer. On each update, decrypt
     * the data from the *previous* tail plus new data minus new tail.
     */
    size_t total = d->tail_len + ct_len;
    if (total <= GCM_TAG_LEN) {
        /* Not enough data yet — just buffer */
        memcpy(d->tail + d->tail_len, ct, ct_len);
        d->tail_len = total;
        *pt_len = 0;
        return 0;
    }

    /* We have enough to keep a full tail and decrypt something */
    size_t decrypt_len = total - GCM_TAG_LEN;

    /* Build contiguous input: old_tail + new_data - new_tail */
    /* First, decrypt from old tail if any */
    size_t pt_written = 0;

    if (d->tail_len > 0) {
        /* How much of the old tail can we decrypt? */
        size_t from_tail = (decrypt_len < d->tail_len) ? decrypt_len : d->tail_len;
        if (from_tail > 0) {
            int outl = 0;
            if (EVP_DecryptUpdate(d->ctx, pt, &outl,
                                  d->tail, (int)from_tail) != 1) {
                *pt_len = 0;
                return -1;
            }
            pt_written += (size_t)outl;
            decrypt_len -= from_tail;
        }
    }

    /* Now decrypt from new ciphertext */
    size_t from_new = (decrypt_len < ct_len) ? decrypt_len : ct_len;
    if (from_new > 0) {
        int outl = 0;
        if (EVP_DecryptUpdate(d->ctx, pt + pt_written, &outl,
                              ct, (int)from_new) != 1) {
            *pt_len = 0;
            return -1;
        }
        pt_written += (size_t)outl;
    }

    /* Update tail: last GCM_TAG_LEN bytes of (old_tail + new_data) */
    if (ct_len >= GCM_TAG_LEN) {
        memcpy(d->tail, ct + ct_len - GCM_TAG_LEN, GCM_TAG_LEN);
        d->tail_len = GCM_TAG_LEN;
    } else {
        /* Shift old tail left and append new data */
        size_t keep = GCM_TAG_LEN - ct_len;
        memmove(d->tail, d->tail + d->tail_len - keep, keep);
        memcpy(d->tail + keep, ct, ct_len);
        d->tail_len = GCM_TAG_LEN;
    }

    *pt_len = pt_written;
    return 0;
}

int sumo_decryptor_finalize(
    sumo_decryptor_t *d,
    uint8_t *pt, size_t *pt_len)
{
    if (!d || !d->ctx || !d->initialized || !pt_len) return -1;

    /* The tail buffer should contain exactly the 16-byte GCM tag */
    if (d->tail_len != GCM_TAG_LEN) {
        *pt_len = 0;
        return -1;
    }

    /* Set the GCM authentication tag */
    if (EVP_CIPHER_CTX_ctrl(d->ctx, EVP_CTRL_GCM_SET_TAG,
                            GCM_TAG_LEN, d->tail) != 1) {
        *pt_len = 0;
        return -1;
    }

    int outl = 0;
    if (EVP_DecryptFinal_ex(d->ctx, pt, &outl) != 1) {
        *pt_len = 0;
        return -1;  /* GCM tag mismatch */
    }
    *pt_len = (size_t)outl;
    return 0;
}

void sumo_decryptor_free(sumo_decryptor_t *d)
{
    if (!d) return;
    if (d->ctx) EVP_CIPHER_CTX_free(d->ctx);
    OPENSSL_cleanse(d->cek, sizeof(d->cek));
    OPENSSL_cleanse(d->iv, sizeof(d->iv));
    OPENSSL_cleanse(d->tail, sizeof(d->tail));
    memset(d, 0, sizeof(*d));
    free(d);
}
