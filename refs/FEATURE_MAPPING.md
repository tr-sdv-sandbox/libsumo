# libsum → SUIT Feature Mapping

Feature-by-feature mapping of libsum's current capabilities onto the SUIT
manifest ecosystem (draft-ietf-suit-manifest-34, draft-ietf-suit-firmware-encryption-18,
RFC 9052 COSE, RFC 9019 architecture, RFC 9124 information model).

## Legend

- DIRECT  — SUIT has a direct equivalent
- PARTIAL — SUIT covers this but with different semantics or limitations
- GAP     — SUIT does not cover this; would need custom extension
- BETTER  — SUIT's approach is richer than libsum's

---

## 1. Manifest Structure & Signing

| libsum Feature | SUIT Equivalent | Status | Notes |
|---|---|---|---|
| Protobuf-serialized Manifest | CBOR-serialized SUIT_Manifest | DIRECT | CBOR replaces Protobuf; single serialization format end-to-end |
| Manifest embedded in X.509 cert extension | SUIT_Envelope (CBOR tag 107) | DIRECT | Manifest is a standalone CBOR document, not embedded in a cert. Simpler. |
| Ed25519 signature over manifest | COSE_Sign1 in SUIT_Authentication wrapper | DIRECT | COSE_Sign1 (tag 18) with EdDSA algorithm (-8). Cleaner separation of signing from manifest content. |
| `signing_cert` (DER cert embedded in manifest) | COSE header `x5chain` or `kid` | DIRECT | Key identification via COSE headers rather than embedding raw certs |
| X.509 3-tier PKI (Root → Intermediate → Update) | COSE_Sign1 + trust anchors + delegation chains | PARTIAL | SUIT defines trust anchors and authorization policies but does NOT mandate X.509. Can use raw COSE keys, C509, or X.509. More flexible but less opinionated. See trust-domains draft for delegation. |
| Certificate chain validation | Trust anchor verification of COSE_Sign1 | PARTIAL | SUIT verifies signatures against provisioned trust anchors. Chain walking is implementation-defined, not standardized in the manifest format itself. |

**Assessment**: Signing is a clean mapping. The big win is dropping X.509 as the manifest container — SUIT_Envelope with COSE_Sign1 is purpose-built and much simpler. PKI is more flexible but less prescribed.

---

## 2. Anti-Rollback & Replay Protection

| libsum Feature | SUIT Equivalent | Status | Notes |
|---|---|---|---|
| `manifest_version` (global monotonic counter) | `suit-manifest-sequence-number` (uint) | DIRECT | Exact same semantics. MUST reject manifests with sequence number ≤ current. |
| `security_version` (per-artifact monotonic) | No per-component equivalent in base spec | GAP | SUIT only has a global sequence number. Per-artifact rollback protection would need a **custom parameter** or the suit-update-management draft. |
| SemVer `version` (per-artifact feature version) | `suit-text-component-version` (text only, in suit-text) | PARTIAL | SUIT has a version-matching condition in the update-management draft, but the base manifest spec only has a human-readable text version. No structured SemVer comparison built in. |

**Assessment**: Global replay protection maps perfectly. Per-artifact rollback is a real gap — libsum's dual-version model (SemVer for features + security_version for rollback) is more sophisticated than base SUIT. This would require a custom SUIT parameter (negative integer key, private use range).

---

## 3. Multi-Component / Multi-Artifact Updates

| libsum Feature | SUIT Equivalent | Status | Notes |
|---|---|---|---|
| `repeated Artifact` (multiple artifacts per manifest) | `suit-components` list in SUIT_Common | DIRECT | SUIT natively supports multiple components per manifest |
| `Artifact.name` (unique identifier) | SUIT_Component_Identifier `[* bstr]` | DIRECT | SUIT uses hierarchical bstr arrays instead of string names. More flexible (filesystem paths, slot identifiers). |
| `Artifact.type` ("firmware", "bootloader", etc.) | No direct equivalent | GAP | SUIT identifies components purely by their component identifier. Type-based routing is not a SUIT concept. Could be a custom parameter. |
| `Artifact.target_ecu` (Uptane ecuIdentifier) | Component Identifier hierarchy | PARTIAL | In SUIT, component ID implicitly routes to the right target (e.g., `['ecu0', 'firmware']`). No separate `target_ecu` field — it's baked into the component ID structure. |
| `Artifact.install_order` (deterministic sequencing) | suit-directive-set-component-index + command sequence ordering | BETTER | SUIT's command sequence model is strictly ordered. You control execution order by the sequence of directives. More powerful than a simple integer — supports conditional branching via try-each. |
| `remove_artifacts` (DELTA manifest removals) | No built-in removal directive | GAP | SUIT has no "delete component" directive. Would need a custom directive or handle at application layer. |
| `ManifestType` (FULL vs DELTA) | No direct equivalent | GAP | SUIT manifests are always additive — they describe what to install, not whether they represent complete or partial state. Application-level concern. |

**Assessment**: Multi-component is well-supported. SUIT's command sequence model is more powerful than libsum's install_order. But artifact typing and FULL/DELTA semantics are gaps.

---

## 4. Encryption & Key Management

| libsum Feature | SUIT Equivalent | Status | Notes |
|---|---|---|---|
| AES-128-GCM content encryption | AES-GCM-128 via `suit-parameter-encryption-info` | DIRECT | Identical algorithm. SUIT also supports AES-GCM-192/256, AES-CBC, AES-CTR. |
| X25519 ECDH key agreement | ECDH-ES+AES-KW via COSE_recipient | PARTIAL | SUIT spec examples use P-256, not X25519. However, COSE supports X25519 (OKP key type, crv=4). Would need to ensure the SUIT processor supports it. |
| ChaCha20-Poly1305 key wrapping | AES Key Wrap (A128KW/A192KW/A256KW) | PARTIAL | SUIT uses AES-KW (RFC 3394) not ChaCha20-Poly1305 for key wrapping. AES-KW is more widely supported in hardware. Functionally equivalent but different algorithm. |
| Per-device encryption (one EncryptionParams per device) | Multiple COSE_recipient entries in COSE_Encrypt | DIRECT | Same concept — one recipient structure per device. SUIT's model is cleaner (standard COSE multi-recipient). |
| `device_id` mandatory in EncryptionParams | `kid` (key identifier) in COSE_recipient unprotected header | DIRECT | Device identified by `kid` parameter (label 4) in recipient structure. |
| IV stored in manifest (not in encrypted file) | IV in COSE_Encrypt unprotected header (label 5) | DIRECT | Same approach — IV carried in metadata, not in payload. |
| GCM auth tag stored in manifest | Tag is part of AEAD ciphertext in COSE | PARTIAL | In COSE, the GCM tag is appended to ciphertext (standard AEAD). libsum stores it separately in the manifest. SUIT's approach is more standard. |
| `wrapped_key` = ephemeral_pubkey ‖ nonce ‖ ciphertext ‖ tag | COSE_recipient with ephemeral key in header + ciphertext field | DIRECT | Same data, structured differently. COSE puts the ephemeral public key in the unprotected header (label -1) and wrapped CEK in the ciphertext field. |
| HKDF-SHA256 key derivation | HKDF via COSE_KDF_Context with protocol binding | BETTER | SUIT's HKDF context includes `"SUIT Payload Encryption"` domain separator and structured algorithm binding. More rigorous than ad-hoc HKDF usage. |

**Assessment**: Encryption maps well. The main change is AES-KW instead of ChaCha20-Poly1305 for key wrapping, and using standard COSE structures. X25519 is supported by COSE but not the default in SUIT examples — would need to confirm implementation support in target SUIT processors.

---

## 5. Hash & Integrity Verification

| libsum Feature | SUIT Equivalent | Status | Notes |
|---|---|---|---|
| SHA-256 of plaintext (`expected_hash`) | `suit-parameter-image-digest` (SUIT_Digest with SHA-256) | DIRECT | SUIT_Digest = [algorithm-id, digest-bytes]. SHA-256 = algorithm -16. |
| SHA-256 of ciphertext (`ciphertext_hash`) | Additional suit-parameter-image-digest on encrypted component | PARTIAL | SUIT can verify digest before and after decryption via command sequence ordering. But there's no dedicated "ciphertext hash" field — you'd use image-digest at different points in the command sequence. |
| `Artifact.size` (plaintext size) | `suit-parameter-image-size` (uint, label 14) | DIRECT | Exact equivalent. |
| `ciphertext_size` (encrypted payload size) | No separate ciphertext size parameter | GAP | Could be inferred or added as custom parameter. |
| Ed25519 per-artifact signature | suit-condition-image-match (digest verification) | PARTIAL | SUIT verifies integrity via hash matching against the signed manifest, not per-artifact signatures. The manifest signature covers all digests. No separate per-artifact Ed25519 signature — the COSE_Sign1 on the envelope covers everything. |

**Assessment**: Hash verification maps cleanly. The per-artifact signature in libsum is redundant with SUIT's model — if the manifest is signed and contains the digest, a separate artifact signature adds no security value (the signed digest IS the proof of authenticity). This is actually a simplification.

---

## 6. Content-Addressable Storage & Source Discovery

| libsum Feature | SUIT Equivalent | Status | Notes |
|---|---|---|---|
| `Source.uri` (download URI) | `suit-parameter-uri` (tstr, label 21) | DIRECT | Set via directive-override-parameters, used by directive-fetch. |
| `Source.priority` (priority-based fallback) | `suit-directive-try-each` with ordered alternatives | BETTER | SUIT's try-each directive tests multiple fetch strategies in sequence. More powerful — can include conditions, not just priority ordering. |
| `Source.type` ("http", "ipfs", "ca", etc.) | URI scheme in suit-parameter-uri | PARTIAL | SUIT doesn't have a separate type hint — the URI scheme implies the fetch method. `ipfs://`, `http://`, etc. |
| `ciphertext_hash` as IPFS CID / BitTorrent infohash | No built-in content-addressable mechanism | GAP | SUIT has no concept of content-addressable distribution. Would need to encode CID in the URI (`ipfs://<cid>`) or add a custom parameter. |
| Multiple sources per artifact | Multiple try-each alternatives with different URIs | DIRECT | Achievable via try-each with different parameter overrides per attempt. |

**Assessment**: Basic fetch works. Priority-based fallback is actually better in SUIT (try-each is more flexible). Content-addressable storage is a gap that would need URI-scheme conventions or a custom parameter.

---

## 7. Device Metadata & Compatibility

| libsum Feature | SUIT Equivalent | Status | Notes |
|---|---|---|---|
| `DeviceMetadata.device_type` | `suit-parameter-vendor-identifier` + `suit-parameter-class-identifier` | PARTIAL | SUIT uses UUID-based vendor + class identifiers. More structured (UUID vs free-form string) but less human-readable. |
| `DeviceMetadata.hardware_id` | `suit-parameter-device-identifier` (UUID, label 24) | DIRECT | Per-device UUID matching. |
| `DeviceMetadata.manufacturer` | `suit-parameter-vendor-identifier` (UUID, label 1) | PARTIAL | UUID-based, not a human-readable string. Human text goes in suit-text. |
| `DeviceMetadata.hardware_version` | No direct equivalent in base spec | GAP | Would need custom parameter or suit-text. |
| `ArtifactConstraint` (min/max security_version) | `suit-condition-vendor-identifier` + `suit-condition-class-identifier` | PARTIAL | SUIT checks device identity but has no built-in version-range constraint mechanism. The update-management draft adds version matching but it's not in the base spec. |
| `Prerequisite` (workshop upgrade path planning) | No equivalent | GAP | SUIT manifests are device-processed. There's no concept of workshop-side metadata embedded in the manifest for upgrade path planning. This is an application-layer concern. |

**Assessment**: Device identification maps to SUIT's UUID-based system. But libsum's workshop-oriented features (prerequisites, version-range constraints) have no SUIT equivalent — they're a higher-level orchestration concern that SUIT intentionally leaves out.

---

## 8. Revocation

| libsum Feature | SUIT Equivalent | Status | Notes |
|---|---|---|---|
| Timestamp-based revocation (`reject_before`) | Not in manifest spec | GAP | SUIT has no revocation mechanism in the manifest itself. Revocation is delegated to the trust anchor / authorization policy layer. Implementation-defined. |
| No CRL/OCSP needed | Same — SUIT also avoids CRL/OCSP | DIRECT | Neither system uses traditional certificate revocation. |

**Assessment**: libsum's timestamp-based revocation is elegant and simple. SUIT leaves this entirely to the implementation. We'd carry this forward as application-layer logic regardless.

---

## 9. Command Sequence Model (SUIT-unique, no libsum equivalent)

SUIT introduces a concept libsum doesn't have: **programmable command sequences**.

| SUIT Feature | libsum Equivalent | Notes |
|---|---|---|
| suit-common shared-sequence | N/A | Runs before every other sequence. Sets parameters, checks vendor/class ID. |
| suit-payload-fetch sequence | Implicit (client fetches from Source URIs) | SUIT makes fetch an explicit, scriptable step. |
| suit-install sequence | Implicit (client copies to flash) | SUIT makes install an explicit step with conditions. |
| suit-validate sequence | `ManifestValidator::ValidateCertificate()` | In SUIT, validation is a command sequence the device executes. |
| suit-load sequence | N/A | Prepare payload for execution (copy to RAM, decompress). |
| suit-invoke sequence | N/A | Transfer execution to updated component. |
| suit-directive-try-each | N/A | Conditional branching — try alternatives, fail over. |
| suit-directive-swap | N/A | Atomic A/B swap of components. |
| suit-directive-copy | N/A | Copy between components (e.g., staging → active). |
| suit-parameter-strict-order | N/A | Enforce sequential processing. |
| suit-parameter-soft-failure | N/A | Allow non-fatal failures in conditions. |

**Assessment**: This is where SUIT is fundamentally richer. The command sequence model turns the manifest into a mini-program that the device executes. libsum's approach is simpler (the manifest is pure data, the client code decides what to do), but SUIT's model enables complex multi-step updates without custom client logic.

---

## 10. Two-Level Manifest Architecture (Campaign + ECU Image)

Using SUIT's dependency model (draft-ietf-suit-trust-domains-10), the libsum
flat manifest naturally splits into two levels:

```
Campaign Manifest (Level 1 — "what to deploy")
  Signed by: Fleet operator / OEM
  suit-manifest-sequence-number: global campaign counter
  suit-dependencies:
    dependency[0] -> ECU-A image manifest
    dependency[1] -> ECU-B image manifest
    dependency[2] -> ECU-C image manifest
  suit-common/shared-sequence:
    condition-vendor-identifier, condition-class-identifier
  suit-payload-fetch: fetch all child manifests
  suit-install: process-dependency for each child (ordered)
  suit-validate: condition-dependency-integrity for each child

ECU Image Manifest (Level 2 — "what to install on one ECU")
  Signed by: Firmware author (can be different signer!)
  suit-manifest-sequence-number: per-ECU rollback counter
  suit-manifest-component-id: ['ecu-a', 'firmware']
  suit-parameter-encryption-info: per-device COSE_Encrypt
  suit-payload-fetch: directive-fetch from URI
  suit-install: directive-copy (decrypt + write to flash)
  suit-validate: condition-image-match (hash check)
  suit-invoke: directive-invoke (boot new image)
```

### How this maps to libsum

| libsum Concept | Campaign Manifest (L1) | ECU Image Manifest (L2) |
|---|---|---|
| `Manifest` (top-level) | The campaign manifest IS this | — |
| `Artifact` (per-image entry) | — | Each artifact becomes its own L2 manifest |
| `manifest_version` | `sequence-number` on L1 (replay protection) | — |
| `security_version` | — | `sequence-number` on L2 (per-ECU rollback) |
| `Artifact.name` / `target_ecu` | — | `suit-manifest-component-id` e.g. `['ecu-a', 'firmware']` |
| `Artifact.type` | — | Encoded in component-id hierarchy |
| `install_order` | Command sequence order of `process-dependency` directives | — |
| `EncryptionParams` | — | `suit-parameter-encryption-info` in L2 |
| `Source` URIs | — | `suit-parameter-uri` in L2 fetch sequence |
| `DeviceMetadata` | Vendor/class/device conditions in L1 shared-sequence | — |
| `Prerequisite` | Application-layer (workshop logic, not in manifest) | — |

### Gaps resolved by the two-level model

| Original Gap | How Two-Level Solves It |
|---|---|
| Per-artifact `security_version` | Each L2 manifest has its own `sequence-number` — that IS the per-ECU rollback counter |
| Artifact type classification | Implicit in component-id hierarchy (`['ecu-a', 'firmware']` vs `['ecu-b', 'bootloader']`) |
| Install ordering across ECUs | L1 command sequence controls order of `process-dependency` calls |
| Different signing authorities | L1 signed by operator, L2 signed by firmware author (via delegation chains) |
| FULL vs DELTA | L1 command sequences determine what gets processed — no explicit type field needed |

### Remaining gaps (need custom params or application-layer)

| Gap | Recommendation |
|---|---|
| Structured SemVer | Custom parameter (-257) in L2 manifest, or suit-text |
| Content-addressable storage | Encode in URI scheme (`ipfs://<cid>`) or custom parameter (-259) |
| Ciphertext size | Custom parameter (-260) or infer from fetch |
| Prerequisites / version-range | Application-layer workshop logic (not in manifest) |
| Timestamp-based revocation | Application-layer device policy (not in manifest) |
| Artifact removal | L1 command sequence can omit components; application-layer cleanup |

### Separation of concerns

This two-level split maps cleanly to the **Uptane Director + Image repo** model:

- **Campaign manifest (L1)** = Uptane Director metadata. "Which devices get which
  images, in what order." Signed by the fleet operator.
- **ECU image manifest (L2)** = Uptane Image metadata. "This specific firmware image,
  its hash, its encryption, its version." Signed by the firmware author.

The firmware author doesn't need to know about deployment topology. The fleet
operator doesn't need to know about firmware internals. Each signs only what
they're authoritative over.

---

## Summary: Gap Analysis

### Features that map cleanly to SUIT (no issues)
- Manifest signing (COSE_Sign1 replaces X.509 embedded signing)
- Global replay protection (L1 sequence number)
- Per-ECU rollback protection (L2 sequence number — resolved by two-level model)
- Multi-component manifests (L1 dependencies)
- Content encryption (AES-GCM via COSE_Encrypt)
- Per-device key wrapping (ECDH + COSE_recipient)
- Hash verification (SUIT_Digest)
- Payload size (suit-parameter-image-size)
- Download URIs (suit-parameter-uri)
- Device identification (UUID-based vendor/class/device)
- No CRL/OCSP revocation
- Install ordering (L1 command sequence)
- Artifact type (component-id hierarchy)

### Features where SUIT is better
- **Command sequences** — programmable update logic vs. static data
- **Source fallback** — try-each vs. priority integer
- **Key derivation** — COSE_KDF_Context with domain separation
- **Severable elements** — detach large sections, replace with digests
- **Integrated payloads** — small payloads embedded directly in envelope
- **Multi-signer** — different signing authorities per manifest level
- **A/B swap** — native directive-swap for atomic partition switching

### Remaining gaps (custom extensions or application-layer)
1. **Structured SemVer** — custom parameter or suit-text
2. **Content-addressable storage** — URI-scheme convention or custom parameter
3. **Ciphertext size** — custom parameter
4. **Prerequisites / version-range constraints** — application-layer
5. **Timestamp-based revocation** — application-layer device policy

### Features libsum has that become unnecessary with SUIT
- **Per-artifact Ed25519 signature** — redundant; COSE_Sign1 on L2 envelope covers digest
- **`signing_cert` in manifest** — COSE headers handle key identification
- **X.509 as manifest container** — SUIT_Envelope replaces this entirely
- **Protobuf** — CBOR everywhere
- **`ManifestType` FULL/DELTA** — expressed by L1 command sequences instead

---

## Recommended Custom SUIT Parameters (Private Use range, key <= -256)

Only 3 custom parameters still needed after the two-level model:

| Custom Parameter | Proposed Key | Type | Purpose |
|---|---|---|---|
| suit-parameter-semver | -257 | [uint, uint, uint, ?tstr, ?tstr] | Structured SemVer for feature version display/comparison |
| suit-parameter-ciphertext-digest | -259 | SUIT_Digest | Hash of encrypted payload for content-addressable storage |
| suit-parameter-ciphertext-size | -260 | uint | Encrypted payload size for download progress |

The original -256 (security-version) and -258 (artifact-type) are no longer needed
thanks to the two-level model.
