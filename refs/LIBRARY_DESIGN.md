# libsum2 — Library Design

SUIT-based secure update manifest library. Replaces libsum's X.509+Protobuf
approach with CBOR/COSE throughout, using a two-level manifest architecture.

## Design Principles

1. **Standards-first** — SUIT manifest (draft-ietf-suit-manifest-34), COSE (RFC 9052),
   CBOR (RFC 8949). Custom extensions only where SUIT has real gaps.
2. **Two-level manifests** — Campaign manifest (L1) orchestrates ECU image manifests (L2).
   Maps to Uptane Director/Image split.
3. **Same library, two profiles** — Full profile (backend + orchestration) and tiny
   profile (device-side validation + decryption). Single codebase, compile-time feature
   selection.
4. **C core, C++ wrapper** — Core library in C99 for embedded portability. Optional
   C++17 builder/ergonomics layer on top.
5. **Pluggable crypto** — Abstract crypto interface with backends for mbedTLS
   (embedded), OpenSSL (server), and libsodium (optional).

---

## Architecture

```
libsum2/
├── core/              C99 — shared between all profiles
│   ├── cbor/          CBOR encoding/decoding (qcbor or nanocbor)
│   ├── cose/          COSE_Sign1, COSE_Encrypt, COSE_Mac0, COSE_Key
│   ├── suit/          SUIT manifest parsing & command sequence processor
│   │   ├── manifest.h       Parse/serialize SUIT_Manifest
│   │   ├── envelope.h       Parse/serialize SUIT_Envelope + auth wrapper
│   │   ├── commands.h       Command sequence processor (conditions + directives)
│   │   └── dependency.h     Dependency resolution (trust-domains)
│   └── crypto/        Abstract crypto interface
│       ├── crypto.h         Operations: sign, verify, encrypt, decrypt, hash, kdf
│       ├── backend_mbedtls.c
│       ├── backend_openssl.c
│       └── backend_libsodium.c
│
├── backend/           C++17 — server-side manifest generation
│   ├── campaign_builder.h   Build L1 campaign manifests
│   ├── image_builder.h      Build L2 ECU image manifests
│   ├── envelope_signer.h    Sign envelopes with COSE_Sign1
│   ├── encryptor.h          Encrypt firmware + wrap keys per device
│   └── keygen.h             Generate COSE_Key pairs (Ed25519, X25519)
│
├── client/            C99 — device-side validation and decryption
│   ├── validator.h          Validate SUIT_Envelope auth, process commands
│   ├── decryptor.h          Streaming AES-GCM decryption
│   ├── dependency.h         Fetch + validate dependency manifests
│   └── policy.h             Anti-rollback, revocation (device-side policy)
│
├── platform/          Platform abstraction
│   ├── platform.h           Logging, persistent storage, memory allocation
│   ├── platform_esp32.c
│   ├── platform_linux.c
│   └── platform_zephyr.c
│
└── tools/             CLI tools
    ├── sum2-keygen          Generate Ed25519/X25519 COSE_Key pairs
    ├── sum2-build           Build campaign + image manifests
    ├── sum2-sign            Sign SUIT envelopes
    ├── sum2-encrypt         Encrypt firmware payloads
    ├── sum2-verify          Verify + decrypt on device (testing)
    └── sum2-inspect         Dump manifest contents (human-readable)
```

---

## Core Data Model

### SUIT_Envelope (both levels)

```
SUIT_Envelope = {
  2: bstr .cbor SUIT_Authentication,    ; auth wrapper
  3: bstr .cbor SUIT_Manifest,          ; manifest
  ? suit-severable-members,             ; detached payload-fetch, install, text
  * tstr => bstr,                       ; integrated payloads / dependencies
}

SUIT_Authentication = [
  bstr .cbor SUIT_Digest,               ; manifest digest
  * bstr .cbor COSE_Sign1               ; one or more signatures
]
```

### Campaign Manifest (L1)

```
L1_Manifest = SUIT_Manifest where:
  sequence-number = global campaign counter
  common:
    components = []                      ; no direct components
    dependencies = {                     ; one per ECU
      0: { prefix: ['ecu-a'] },
      1: { prefix: ['ecu-b'] },
    }
    shared-sequence = [
      override-parameters: {
        vendor-id: h'<uuid>',
        class-id:  h'<uuid>',
      },
      condition-vendor-identifier,
      condition-class-identifier,
    ]
  payload-fetch = [
    ; for each dependency: set params, fetch child manifest
    set-component-index(0),
    override-parameters({ uri: "https://updates.example.com/ecu-a.suit" }),
    fetch,
    set-component-index(1),
    override-parameters({ uri: "https://updates.example.com/ecu-b.suit" }),
    fetch,
  ]
  install = [
    ; process dependencies in order
    set-component-index(0),
    condition-dependency-integrity,
    process-dependency,
    set-component-index(1),
    condition-dependency-integrity,
    process-dependency,
  ]
  validate = [
    set-component-index(0),
    condition-dependency-integrity,
    set-component-index(1),
    condition-dependency-integrity,
  ]
```

### ECU Image Manifest (L2)

```
L2_Manifest = SUIT_Manifest where:
  sequence-number = per-ECU rollback counter
  manifest-component-id = ['ecu-a', 'firmware']
  common:
    components = [ ['ecu-a', 'firmware'] ]
    shared-sequence = [
      override-parameters: {
        vendor-id: h'<uuid>',
        class-id:  h'<uuid>',
        image-digest: [SHA-256, h'<hash>'],
        image-size: 245760,
        ; custom: semver, ciphertext-digest (if needed)
      },
      condition-vendor-identifier,
      condition-class-identifier,
    ]
  payload-fetch = [
    set-component-index(0),
    override-parameters({
      uri: "https://firmware.example.com/ecu-a-v2.1.0.enc",
      encryption-info: COSE_Encrypt { ... },
    }),
    try-each([
      [fetch],                           ; try primary URI
      [override-parameters({uri: "ipfs://..."}), fetch],  ; fallback
    ]),
  ]
  install = [
    set-component-index(0),
    override-parameters({
      encryption-info: COSE_Encrypt {
        alg: AES-GCM-128,
        iv: h'...',
        ciphertext: nil,                 ; detached
        recipients: [
          COSE_recipient {               ; per-device key wrapping
            alg: ECDH-ES+A128KW,
            ephemeral-key: COSE_Key { ... },
            kid: h'device-001',
            ciphertext: h'<wrapped-CEK>',
          }
        ]
      }
    }),
    directive-copy,                      ; decrypt + write to flash
    condition-image-match,               ; verify plaintext hash
  ]
  validate = [
    set-component-index(0),
    condition-image-match,               ; re-verify on boot
  ]
  invoke = [
    set-component-index(0),
    directive-invoke,                    ; boot the image
  ]
```

---

## Public API

### Backend (C++17) — Server-Side

```cpp
namespace sum2 {

// --- Key Management ---

// Generate Ed25519 signing keypair as COSE_Key
CoseKey GenerateSigningKey();

// Generate X25519 key agreement keypair as COSE_Key
CoseKey GenerateDeviceKey();

// --- Image Manifest (L2) Builder ---

class ImageManifestBuilder {
public:
    // Identity
    ImageManifestBuilder& SetComponentId(
        std::vector<std::string> component_id);     // e.g. {"ecu-a", "firmware"}
    ImageManifestBuilder& SetSequenceNumber(uint64_t seq);
    ImageManifestBuilder& SetVendorId(Uuid vendor);
    ImageManifestBuilder& SetClassId(Uuid class_id);

    // Payload
    ImageManifestBuilder& SetPayloadUri(std::string uri);
    ImageManifestBuilder& AddFallbackUri(std::string uri);
    ImageManifestBuilder& SetPayload(
        std::span<const uint8_t> plaintext);         // computes hash + size

    // Encryption (optional — can build unencrypted manifests too)
    ImageManifestBuilder& Encrypt(
        std::span<const uint8_t> plaintext,
        std::span<const CoseKey> device_keys);       // per-device wrapping

    // Custom parameters
    ImageManifestBuilder& SetSemVer(SemVer version);

    // Build
    // Returns signed SUIT_Envelope bytes
    std::vector<uint8_t> Build(const CoseKey& signing_key);
};

// --- Campaign Manifest (L1) Builder ---

class CampaignBuilder {
public:
    CampaignBuilder& SetSequenceNumber(uint64_t seq);
    CampaignBuilder& SetVendorId(Uuid vendor);
    CampaignBuilder& SetClassId(Uuid class_id);

    // Add L2 manifest as dependency
    // fetch_uri: where device fetches the L2 envelope
    // envelope: the signed L2 envelope bytes (digest computed automatically)
    CampaignBuilder& AddImage(
        std::string fetch_uri,
        std::span<const uint8_t> l2_envelope);

    // Optionally embed L2 manifests as integrated payloads
    CampaignBuilder& AddIntegratedImage(
        std::string key,                             // e.g. "#ecu-a"
        std::span<const uint8_t> l2_envelope);

    // Build
    std::vector<uint8_t> Build(const CoseKey& signing_key);
};

// --- Firmware Encryption (standalone, before manifest building) ---

struct EncryptedPayload {
    std::vector<uint8_t> ciphertext;
    CoseEncryptInfo encryption_info;                  // COSE_Encrypt structure
};

EncryptedPayload EncryptFirmware(
    std::span<const uint8_t> plaintext,
    std::span<const CoseKey> device_keys);           // wraps CEK per device

} // namespace sum2
```

### Client (C99) — Device-Side

```c
// --- Envelope Validation ---

// Create validator with trust anchor(s) and device identity
sum2_validator_t *sum2_validator_create(
    const uint8_t *trust_anchor_cose_key, size_t ta_len,
    const uint8_t *device_key, size_t dk_len,
    const sum2_device_id_t *device_id
);

// Anti-rollback policy
int sum2_validator_set_min_sequence(
    sum2_validator_t *v,
    const uint8_t *component_id_cbor, size_t cid_len,   // which component
    uint64_t min_seq                                      // minimum sequence number
);

// Timestamp-based revocation
int sum2_validator_set_reject_before(
    sum2_validator_t *v,
    int64_t timestamp
);

// Validate a SUIT_Envelope. Returns parsed manifest on success.
// For L1 (campaign): returns manifest with dependency list.
// For L2 (image): returns manifest with component + encryption info.
int sum2_validate_envelope(
    sum2_validator_t *v,
    const uint8_t *envelope, size_t envelope_len,
    int64_t trusted_time,
    sum2_manifest_t **manifest_out
);

// --- Command Sequence Processing ---

// Callbacks for command sequence execution (device provides these)
typedef struct {
    // Fetch payload from URI into staging buffer
    int (*fetch)(const char *uri, size_t uri_len,
                 uint8_t *buf, size_t buf_size, size_t *fetched,
                 void *ctx);

    // Write decrypted data to component storage
    int (*write)(const uint8_t *component_id, size_t cid_len,
                 const uint8_t *data, size_t data_len,
                 void *ctx);

    // Invoke (boot) a component
    int (*invoke)(const uint8_t *component_id, size_t cid_len,
                  void *ctx);

    // Swap two components (A/B)
    int (*swap)(const uint8_t *component_a, size_t a_len,
                const uint8_t *component_b, size_t b_len,
                void *ctx);

    // Resolve a dependency manifest (fetch + validate)
    int (*resolve_dependency)(const uint8_t *prefix, size_t prefix_len,
                              const uint8_t *uri, size_t uri_len,
                              const uint8_t *expected_digest, size_t digest_len,
                              sum2_manifest_t **dep_manifest_out,
                              void *ctx);

    void *user_ctx;
} sum2_platform_ops_t;

// Process the manifest's command sequences
// Executes: shared-sequence -> payload-fetch -> install -> validate
int sum2_process_update(
    sum2_validator_t *v,
    const sum2_manifest_t *manifest,
    const sum2_platform_ops_t *ops
);

// Process invocation procedure
// Executes: shared-sequence -> validate -> load -> invoke
int sum2_process_invoke(
    sum2_validator_t *v,
    const sum2_manifest_t *manifest,
    const sum2_platform_ops_t *ops
);

// --- Streaming Decryption ---

sum2_decryptor_t *sum2_decryptor_create(
    const sum2_manifest_t *manifest,
    size_t component_index,
    const uint8_t *device_key, size_t dk_len
);

int sum2_decryptor_update(
    sum2_decryptor_t *d,
    const uint8_t *ciphertext, size_t ct_len,
    uint8_t *plaintext, size_t *pt_len
);

int sum2_decryptor_finalize(
    sum2_decryptor_t *d,
    uint8_t *plaintext, size_t *pt_len
);

void sum2_decryptor_free(sum2_decryptor_t *d);

// --- Manifest Accessors ---

uint64_t sum2_manifest_get_sequence_number(const sum2_manifest_t *m);
size_t   sum2_manifest_get_component_count(const sum2_manifest_t *m);
size_t   sum2_manifest_get_dependency_count(const sum2_manifest_t *m);
int      sum2_manifest_get_component_id(
             const sum2_manifest_t *m, size_t index,
             const uint8_t **cid_out, size_t *cid_len_out);
int      sum2_manifest_get_image_size(
             const sum2_manifest_t *m, size_t component_index,
             uint64_t *size_out);

void sum2_manifest_free(sum2_manifest_t *m);
void sum2_validator_free(sum2_validator_t *v);
```

---

## Crypto Abstraction

```c
// crypto.h — pluggable backend interface

typedef struct {
    // Signing (Ed25519)
    int (*sign)(const uint8_t *key, size_t key_len,
                const uint8_t *msg, size_t msg_len,
                uint8_t *sig, size_t *sig_len);
    int (*verify)(const uint8_t *key, size_t key_len,
                  const uint8_t *msg, size_t msg_len,
                  const uint8_t *sig, size_t sig_len);

    // AEAD (AES-128-GCM)
    int (*aead_encrypt)(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *pt, size_t pt_len,
                        uint8_t *ct, uint8_t *tag, size_t tag_len);
    int (*aead_decrypt_init)(void **ctx,
                             const uint8_t *key, const uint8_t *iv, size_t iv_len,
                             const uint8_t *aad, size_t aad_len);
    int (*aead_decrypt_update)(void *ctx,
                               const uint8_t *ct, size_t ct_len,
                               uint8_t *pt, size_t *pt_len);
    int (*aead_decrypt_finalize)(void *ctx,
                                 const uint8_t *tag, size_t tag_len,
                                 uint8_t *pt, size_t *pt_len);
    void (*aead_decrypt_free)(void *ctx);

    // Key agreement (X25519 / P-256)
    int (*ecdh)(const uint8_t *priv_key, size_t priv_len,
                const uint8_t *pub_key, size_t pub_len,
                uint8_t *shared_secret, size_t *ss_len);

    // Key wrapping (AES-KW)
    int (*kw_wrap)(const uint8_t *kek, size_t kek_len,
                   const uint8_t *pt, size_t pt_len,
                   uint8_t *ct, size_t *ct_len);
    int (*kw_unwrap)(const uint8_t *kek, size_t kek_len,
                     const uint8_t *ct, size_t ct_len,
                     uint8_t *pt, size_t *pt_len);

    // Hashing (SHA-256)
    int (*hash_init)(void **ctx);
    int (*hash_update)(void *ctx, const uint8_t *data, size_t len);
    int (*hash_finalize)(void *ctx, uint8_t *digest, size_t *digest_len);
    void (*hash_free)(void *ctx);

    // KDF (HKDF-SHA256)
    int (*hkdf)(const uint8_t *ikm, size_t ikm_len,
                const uint8_t *salt, size_t salt_len,
                const uint8_t *info, size_t info_len,
                uint8_t *okm, size_t okm_len);
} sum2_crypto_ops_t;

// Backends
const sum2_crypto_ops_t *sum2_crypto_mbedtls(void);
const sum2_crypto_ops_t *sum2_crypto_openssl(void);
const sum2_crypto_ops_t *sum2_crypto_libsodium(void);
```

---

## CBOR Library Selection

| Library | Language | Size | Notes |
|---|---|---|---|
| **QCBOR** (Qualcomm) | C99 | ~5KB code | Battle-tested, used by t_cose. Best fit for core. |
| **nanocbor** (RIOT OS) | C99 | ~2KB code | Smaller but less featured. Good for ultra-constrained. |
| **tinycbor** (Intel) | C99 | ~4KB code | Mature but less maintained. |

**Recommendation**: QCBOR for the core library. It pairs with **t_cose** (also
Qualcomm) which provides COSE_Sign1/COSE_Encrypt/COSE_Mac0 out of the box with
pluggable crypto backends. This avoids writing COSE from scratch.

### t_cose

t_cose already provides:
- COSE_Sign1 create + verify
- COSE_Encrypt / COSE_Encrypt0 (in progress, recent additions)
- COSE_Mac0
- Pluggable crypto (mbedTLS, OpenSSL, PSA Crypto API)
- Uses QCBOR internally

This means our `core/cose/` layer is mostly thin wrappers around t_cose rather
than custom COSE implementation.

---

## Dependencies

### Core (C99, embedded-safe)

| Dependency | Purpose | Size |
|---|---|---|
| QCBOR | CBOR encode/decode | ~5KB |
| t_cose | COSE operations | ~8KB |
| Crypto backend (one of): | | |
|   mbedTLS | Crypto for embedded | ~200KB |
|   OpenSSL | Crypto for server | ~1.5MB |
|   libsodium | Crypto (optional) | ~150KB |

### Backend (C++17, server-side)

| Dependency | Purpose |
|---|---|
| Core (above) | CBOR/COSE/crypto |
| No additional deps | Builder is pure C++ on top of core |

### Comparison to libsum

| | libsum | libsum-tiny | libsum2 (core) |
|---|---|---|---|
| Serialization | Protobuf | nanopb | QCBOR |
| Signing | OpenSSL X.509 | custom Ed25519 ASN.1 parser | t_cose + COSE_Sign1 |
| Encryption | OpenSSL | mbedTLS + libsodium | crypto backend (pluggable) |
| Manifest format | Custom Protobuf | Custom Protobuf | SUIT standard |
| Extra deps | glog, nlohmann/json | — | — |

---

## Build System

CMake with feature toggles:

```cmake
option(SUM2_BUILD_BACKEND   "Build server-side manifest generation (C++17)" ON)
option(SUM2_BUILD_CLIENT    "Build device-side validation (C99)"            ON)
option(SUM2_BUILD_TOOLS     "Build CLI tools"                               ON)
option(SUM2_BUILD_TESTS     "Build tests"                                   ON)

option(SUM2_CRYPTO_MBEDTLS  "Use mbedTLS crypto backend"                    OFF)
option(SUM2_CRYPTO_OPENSSL  "Use OpenSSL crypto backend"                    ON)
option(SUM2_CRYPTO_LIBSODIUM "Use libsodium crypto backend"                 OFF)

option(SUM2_PLATFORM_ESP32  "Build for ESP-IDF"                             OFF)
option(SUM2_PLATFORM_ZEPHYR "Build for Zephyr RTOS"                         OFF)
```

ESP-IDF integration via `idf_component_register()` when `IDF_PATH` is set
(same pattern as libsum-tiny).

---

## Migration Path from libsum

1. **Phase 1**: Core library — CBOR/COSE/SUIT parsing + crypto abstraction
2. **Phase 2**: Client — L2 image manifest validation + decryption (replaces libsum-tiny)
3. **Phase 3**: Backend — L2 image manifest builder + encryption (replaces libsum backend)
4. **Phase 4**: L1 campaign manifest builder + dependency processing
5. **Phase 5**: CLI tools + interop tests with libsum (verify migration)
6. **Phase 6**: Platform ports (ESP32, Zephyr)

Each phase is independently testable. Phase 2 can ship to devices while
Phase 3-4 are in progress (generate L2 manifests with a script, validate
on device with the new client).

---

## Open Questions

1. **QCBOR + t_cose vs. custom CBOR/COSE?** — t_cose saves significant effort
   but adds an opinionated dependency. Need to evaluate its COSE_Encrypt
   maturity (it was recently added).

2. **X25519 vs P-256 for key agreement?** — libsum uses X25519 + ChaCha20-Poly1305.
   SUIT examples use P-256 + AES-KW. Both are valid COSE algorithms. X25519 is
   simpler and faster but P-256 has broader hardware accelerator support on
   embedded chips (ESP32 has P-256 hardware). Could support both via crypto
   backend.

3. **How much of the SUIT command sequence processor to implement?** — Full
   processor is complex. Could start with a "static profile" that handles the
   common case (fetch → decrypt → write → verify) without a general-purpose
   command interpreter. Expand later.

4. **suit-text support?** — Human-readable descriptions, vendor names, version
   strings. Nice for debugging/display but not security-critical. Implement as
   optional/severable.

5. **Delegation chains (trust-domains)?** — Required for multi-signer L1+L2
   model. But the draft is still evolving. Implement core support, keep the
   wire format aligned with draft-ietf-suit-trust-domains-10.
