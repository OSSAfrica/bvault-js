# bvault-js

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
