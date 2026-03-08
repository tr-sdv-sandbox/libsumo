/**
 * @file encryptor.cpp
 * @brief Firmware encryption with per-device COSE_Encrypt key wrapping.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "sum2/encryptor.h"

#include <stdexcept>

#include <zstd.h>

#include "csuit_wrapper.h"

namespace sum2 {

EncryptedPayload EncryptFirmware(
    std::span<const uint8_t> plaintext,
    std::span<const Recipient> recipients)
{
    if (recipients.empty())
        throw std::runtime_error("EncryptFirmware: at least one recipient required");

    /* For now, support single A128KW recipient.
     * The key bytes in the recipient's CoseKey are the COSE_Key CBOR. */
    const auto &r = recipients[0];
    auto kb = r.public_key.PublicKeyBytes();
    if (kb.empty())
        throw std::runtime_error("EncryptFirmware: recipient key is empty");

    /* Output buffers: ciphertext = plaintext + 16 (GCM tag), enc_info ~256 */
    std::vector<uint8_t> ct(plaintext.size() + 128);
    std::vector<uint8_t> ei(512);
    size_t ct_len = 0, ei_len = 0;

    int rc = sum2_encrypt_a128kw(
        plaintext.data(), plaintext.size(),
        kb.data(), kb.size(),
        ct.data(), ct.size(), &ct_len,
        ei.data(), ei.size(), &ei_len);

    if (rc != 0)
        throw std::runtime_error("sum2_encrypt_a128kw failed (rc=" + std::to_string(rc) + ")");

    ct.resize(ct_len);
    ei.resize(ei_len);

    return EncryptedPayload{std::move(ct), std::move(ei)};
}

EncryptedPayload EncryptFirmwareEcdh(
    std::span<const uint8_t> plaintext,
    const CoseKey& sender_key,
    std::span<const Recipient> recipients)
{
    if (recipients.empty())
        throw std::runtime_error("EncryptFirmwareEcdh: at least one recipient required");

    const auto &r = recipients[0];
    auto sender_kb = sender_key.PublicKeyBytes();
    auto recv_kb = r.public_key.PublicKeyBytes();
    if (sender_kb.empty())
        throw std::runtime_error("EncryptFirmwareEcdh: sender key is empty");
    if (recv_kb.empty())
        throw std::runtime_error("EncryptFirmwareEcdh: recipient key is empty");

    std::vector<uint8_t> ct(plaintext.size() + 128);
    std::vector<uint8_t> ei(1024);
    size_t ct_len = 0, ei_len = 0;

    int rc = sum2_encrypt_esdh(
        plaintext.data(), plaintext.size(),
        sender_kb.data(), sender_kb.size(),
        recv_kb.data(), recv_kb.size(),
        r.kid.data(), r.kid.size(),
        ct.data(), ct.size(), &ct_len,
        ei.data(), ei.size(), &ei_len);

    if (rc != 0)
        throw std::runtime_error("sum2_encrypt_esdh failed (rc=" + std::to_string(rc) + ")");

    ct.resize(ct_len);
    ei.resize(ei_len);

    return EncryptedPayload{std::move(ct), std::move(ei)};
}

std::vector<uint8_t> CompressFirmware(
    std::span<const uint8_t> plaintext,
    int level)
{
    size_t bound = ZSTD_compressBound(plaintext.size());
    std::vector<uint8_t> compressed(bound);

    size_t rc = ZSTD_compress(
        compressed.data(), compressed.size(),
        plaintext.data(), plaintext.size(),
        level);
    if (ZSTD_isError(rc))
        throw std::runtime_error(
            std::string("ZSTD_compress failed: ") + ZSTD_getErrorName(rc));

    compressed.resize(rc);
    return compressed;
}

std::vector<uint8_t> Sha256(std::span<const uint8_t> data) {
    std::vector<uint8_t> digest(32);
    if (sum2_sha256(data.data(), data.size(), digest.data()) != 0)
        throw std::runtime_error("SHA-256 computation failed");
    return digest;
}

} // namespace sum2
