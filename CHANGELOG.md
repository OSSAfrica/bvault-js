## bvault-js@1.0.0-preview.1 (preview)

### Invalidate destroyed keys across browser tabs

- fix(storage): invalidate destroyed keys across browser tabs

- fix(storage): retain coordination when channel posting fails

---

## bvault-js@1.0.0-preview.0 (preview)

### Format retained prerelease changelogs

### Prepare preview releases with formatted changelogs

### Unblock ESM package validation and App releases

### Propagate storage errors from setItem instead of wrapping as EncryptionError (#49)

Preserve the contribution with a verified squash commit.

### Fine-tune CodeQL and stalebot config

### Encrypt storage with a non-extractable CryptoKey

bVault derived its encryption key from a password, and recommended sourcing
that password from a browser fingerprint. That key can be recomputed by any
script in the origin, carries roughly 13 bits of entropy, and drifts often
enough that stored data becomes silently undecryptable.

Generate the key with crypto.subtle.generateKey(..., extractable: false) and
persist it in IndexedDB instead. Its raw bytes are never exposed to
JavaScript, so storage that is copied and replayed in another browser cannot
be decrypted. Live XSS can still use the key handle on the page; it can no
longer steal it for offline or cross-browser use.

The IV now travels inline with the ciphertext as
version(1) || iv(12) || ciphertext+tag, which removes the per-read IndexedDB
lookup for metadata.

Also fixes three bugs found while reworking this:

- getItem deleted the stored value whenever decryption failed, so a transient
  error or an evicted key destroyed user data.
- secure-storage read localStorage at module load, making the package throw
  on import under server-side rendering.
- bufferToBase64 spread the byte array into String.fromCharCode and overflowed
  the call stack past ~100KB.

Remove the bvault_js_rs crate. It implemented AES-CBC with a 16-byte IV and
standard base64 against a library writing AES-GCM with a 12-byte IV and
URL-safe base64, so it could not decrypt anything bVault wrote.

BREAKING CHANGE: initializeSecureStorage() no longer takes a password, the
encrypt/decrypt exports are removed, and data written by 0.x is cleared once
on initialization because its key is not recoverable.

Refs #5

## 0.3.2

### Patch Changes

- d1bacfd: Docs update and badge removal

## 0.3.1

### Patch Changes

- c7c58fa: Docs update

## 0.3.0

### Minor Changes

- e4d6207: add support for session storage

## 0.2.3

### Patch Changes

- 9e98fbf: Update secure storage apis

## 0.2.2

### Patch Changes

- 88317d7: clean dist

## 0.2.1

### Patch Changes

- ffe9155: clean debris

## 0.2.0

### Minor Changes

- 3b2f46a: feat: Add secure storage with encryption and IndexedDB support

### Patch Changes

- dccc06e: feat: Initialize Rust-Wasm project with encryption library
- 1f86554: fix: format

## 0.1.3

### Patch Changes

- c4d29de: add comments to the codebase

## 0.1.3-v0.1.2.0

### Patch Changes

- c4d29de: add comments to the codebase

## 0.1.2

### Patch Changes

- 64245e6: Add Docs

## 0.1.1

### Patch Changes

- d7950c0: Update Package Info

## 0.1.0

### Minor Changes

- e6afc81: ## v0.0.1 - Initial Release

  ### ✨ Features:
  - Added secure AES-GCM 256-bit encryption/decryption
  - Implemented PBKDF2 key derivation (100k iterations)
  - Included browser-compatible Base64 URL-safe encoding
  - Added TypeScript support with full type definitions
  - Comprehensive error handling (EncryptionError/DecryptionError)

  ### 🛠️ Technical:
  - Zero dependencies - pure Web Crypto API implementation
  - ESM module format for modern browsers
  - Full test coverage with Vitest (100% coverage target)
  - Built-in data conversion utilities

  ### 📦 Package:
  - Ready for npm publishing
  - Includes browser and TypeScript type declarations
  - Demo/test application included in documentation

  ### 🔒 Security:
  - Randomized IV/salt for each operation
  - Fail-secure error handling
  - Resistance to common cryptographic attacks
