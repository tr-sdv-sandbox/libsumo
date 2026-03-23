/**
 * @file keygen.cpp
 * @brief COSE_Key generation using OpenSSL.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sum2/keygen.h"

#include <stdexcept>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>

#include "cose_key_impl.h"
#include "csuit_wrapper.h"

namespace sum2 {

/* ---- CBOR encoding helpers (minimal, no QCBOR dependency) ---- */

static void cbor_encode_uint(std::vector<uint8_t>& buf, uint8_t major, uint64_t val) {
    uint8_t mt = static_cast<uint8_t>(major << 5);
    if (val < 24) {
        buf.push_back(mt | static_cast<uint8_t>(val));
    } else if (val <= 0xFF) {
        buf.push_back(mt | 24);
        buf.push_back(static_cast<uint8_t>(val));
    } else if (val <= 0xFFFF) {
        buf.push_back(mt | 25);
        buf.push_back(static_cast<uint8_t>(val >> 8));
        buf.push_back(static_cast<uint8_t>(val));
    }
}

static void cbor_encode_int(std::vector<uint8_t>& buf, int64_t val) {
    if (val >= 0) {
        cbor_encode_uint(buf, 0, static_cast<uint64_t>(val));
    } else {
        cbor_encode_uint(buf, 1, static_cast<uint64_t>(-1 - val));
    }
}

static void cbor_encode_bstr(std::vector<uint8_t>& buf,
                              const uint8_t *data, size_t len) {
    cbor_encode_uint(buf, 2, len);
    buf.insert(buf.end(), data, data + len);
}

static void cbor_encode_map_header(std::vector<uint8_t>& buf, size_t n) {
    cbor_encode_uint(buf, 5, n);
}

/* ---- Build COSE_Key CBOR for EC2 (P-256) ---- */

static std::vector<uint8_t> build_ec2_cose_key(
    const uint8_t x[32], const uint8_t y[32],
    const uint8_t *d, /* nullptr for public-only */
    const uint8_t *kid, size_t kid_len,
    int algorithm)
{
    std::vector<uint8_t> buf;
    /* kty(1) + kid(optional) + alg(1) + crv(-1) + x(-2) + y(-3) + d(-4, optional) */
    size_t n_entries = 5 + (kid_len > 0 ? 1 : 0) + (d ? 1 : 0);

    cbor_encode_map_header(buf, n_entries);

    cbor_encode_int(buf, 1);
    cbor_encode_int(buf, 2); /* kty = EC2 */

    if (kid_len > 0) {
        cbor_encode_int(buf, 2);
        cbor_encode_bstr(buf, kid, kid_len);
    }

    cbor_encode_int(buf, 3);
    cbor_encode_int(buf, algorithm);

    cbor_encode_int(buf, -1);
    cbor_encode_int(buf, 1); /* crv = P-256 */

    cbor_encode_int(buf, -2);
    cbor_encode_bstr(buf, x, 32);

    cbor_encode_int(buf, -3);
    cbor_encode_bstr(buf, y, 32);

    if (d) {
        cbor_encode_int(buf, -4);
        cbor_encode_bstr(buf, d, 32);
    }

    return buf;
}

/* ---- Build COSE_Key CBOR for OKP (Ed25519) ---- */

static std::vector<uint8_t> build_okp_cose_key(
    const uint8_t *pub, size_t pub_len,
    const uint8_t *priv, size_t priv_len, /* nullptr/0 for public-only */
    const uint8_t *kid, size_t kid_len,
    int algorithm, int curve)
{
    std::vector<uint8_t> buf;
    /* kty(1) + kid(optional) + alg(1) + crv(-1) + x(-2) + d(-4, optional) */
    size_t n_entries = 3 + (kid_len > 0 ? 1 : 0) + (priv ? 1 : 0);

    cbor_encode_map_header(buf, n_entries);

    cbor_encode_int(buf, 1);
    cbor_encode_int(buf, 1); /* kty = OKP */

    if (kid_len > 0) {
        cbor_encode_int(buf, 2);
        cbor_encode_bstr(buf, kid, kid_len);
    }

    cbor_encode_int(buf, 3);
    cbor_encode_int(buf, algorithm);

    cbor_encode_int(buf, -1);
    cbor_encode_int(buf, curve);

    cbor_encode_int(buf, -2);
    cbor_encode_bstr(buf, pub, pub_len);

    if (priv && priv_len > 0) {
        cbor_encode_int(buf, -4);
        cbor_encode_bstr(buf, priv, priv_len);
    }

    return buf;
}

/* ---- Extract P-256 coordinates from EVP_PKEY ---- */

struct EC2Coords {
    uint8_t x[32];
    uint8_t y[32];
    uint8_t d[32];
    bool has_private;
};

static EC2Coords extract_ec2_coords(EVP_PKEY *pkey) {
    EC2Coords c{};
    BIGNUM *bn_x = nullptr, *bn_y = nullptr, *bn_d = nullptr;

    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &bn_x);
    EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &bn_y);
    c.has_private = (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn_d) == 1);

    if (bn_x) { BN_bn2binpad(bn_x, c.x, 32); BN_free(bn_x); }
    if (bn_y) { BN_bn2binpad(bn_y, c.y, 32); BN_free(bn_y); }
    if (bn_d && c.has_private) { BN_bn2binpad(bn_d, c.d, 32); BN_free(bn_d); }

    return c;
}

/* ---- Compute kid = SHA-256(x || y) ---- */

static std::vector<uint8_t> compute_kid(const uint8_t x[32], const uint8_t y[32]) {
    uint8_t combined[64];
    memcpy(combined, x, 32);
    memcpy(combined + 32, y, 32);

    std::vector<uint8_t> kid(32);
    sum2_sha256(combined, 64, kid.data());
    return kid;
}

/* ---- Public API ---- */

CoseKey GenerateSigningKey(int algorithm) {
    if (algorithm == ES256) {
        EVP_PKEY *pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
        if (!pkey)
            throw std::runtime_error("EVP_PKEY_Q_keygen(EC, P-256) failed");

        auto coords = extract_ec2_coords(pkey);
        auto kid = compute_kid(coords.x, coords.y);

        auto full = build_ec2_cose_key(
            coords.x, coords.y, coords.d, kid.data(), kid.size(), -7);
        auto pub_bytes = build_ec2_cose_key(
            coords.x, coords.y, nullptr, kid.data(), kid.size(), -7);

        CoseKey k;
        k.impl_->key_bytes = std::move(full);
        k.impl_->public_key_bytes = std::move(pub_bytes);
        k.impl_->kid = std::move(kid);
        k.impl_->algorithm = -7;
        k.impl_->evp_pkey = pkey;
        return k;
    }

    if (algorithm == EdDSA) {
        EVP_PKEY *pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
        if (!pkey)
            throw std::runtime_error("EVP_PKEY_Q_keygen(ED25519) failed");

        /* Extract raw public and private key bytes */
        uint8_t pub[32], priv[64]; /* Ed25519 private may be 64 bytes (seed+pub) */
        size_t pub_len = 32, priv_len = 64;

        if (EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len) != 1)
            throw std::runtime_error("Failed to extract Ed25519 public key");

        priv_len = 32; /* We want just the 32-byte seed */
        if (EVP_PKEY_get_raw_private_key(pkey, priv, &priv_len) != 1)
            throw std::runtime_error("Failed to extract Ed25519 private key");

        /* kid = SHA-256(pub) */
        std::vector<uint8_t> kid(32);
        sum2_sha256(pub, pub_len, kid.data());

        auto full = build_okp_cose_key(
            pub, pub_len, priv, priv_len, kid.data(), kid.size(),
            -8 /* EdDSA */, 6 /* Ed25519 */);
        auto pub_only = build_okp_cose_key(
            pub, pub_len, nullptr, 0, kid.data(), kid.size(),
            -8, 6);

        CoseKey k;
        k.impl_->key_bytes = std::move(full);
        k.impl_->public_key_bytes = std::move(pub_only);
        k.impl_->kid = std::move(kid);
        k.impl_->algorithm = -8;
        k.impl_->evp_pkey = pkey;
        return k;
    }

    throw std::runtime_error("GenerateSigningKey: unsupported algorithm");
}

CoseKey GenerateDeviceKey(int algorithm) {
    if (algorithm != ES256)
        throw std::runtime_error("GenerateDeviceKey: only ES256 is supported");

    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
    if (!pkey)
        throw std::runtime_error("EVP_PKEY_Q_keygen(EC, P-256) failed");

    auto coords = extract_ec2_coords(pkey);
    auto kid = compute_kid(coords.x, coords.y);

    /* Device keys use ECDH-ES+A128KW algorithm (-29) */
    auto full = build_ec2_cose_key(
        coords.x, coords.y, coords.d, kid.data(), kid.size(), -29);
    auto pub = build_ec2_cose_key(
        coords.x, coords.y, nullptr, kid.data(), kid.size(), -29);

    CoseKey k;
    k.impl_->key_bytes = std::move(full);
    k.impl_->public_key_bytes = std::move(pub);
    k.impl_->kid = std::move(kid);
    k.impl_->algorithm = -29;
    k.impl_->evp_pkey = pkey;

    return k;
}

std::vector<uint8_t> SerializeKey(const CoseKey& key, bool include_private) {
    if (include_private) {
        if (!key.impl_->key_bytes.empty())
            return key.impl_->key_bytes;
    }
    return key.PublicKeyBytes();
}

std::string SerializeKeyPem(const CoseKey& key, bool include_private) {
    EVP_PKEY *pkey = key.impl_->evp_pkey;
    if (!pkey)
        throw std::runtime_error("SerializeKeyPem: key has no EVP_PKEY (was not generated or loaded from PEM)");

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
        throw std::runtime_error("BIO_new failed");

    int ok;
    if (include_private) {
        ok = PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    } else {
        ok = PEM_write_bio_PUBKEY(bio, pkey);
    }

    if (!ok) {
        BIO_free(bio);
        throw std::runtime_error("PEM serialization failed");
    }

    char *data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string result(data, static_cast<size_t>(len));
    BIO_free(bio);
    return result;
}

} // namespace sum2
