# bVault-js - Secure Frontend Encryption Library

[![npm version](https://img.shields.io/npm/v/bvault-js?logo=npm)](https://www.npmjs.com/package/bvault-js)
[![wakatime](https://wakatime.com/badge/user/9657174f-2430-4dfd-aaef-2b316eb71a36/project/4f0c1980-a3b3-432d-a157-1068783e6a7c.svg)](https://wakatime.com/badge/user/9657174f-2430-4dfd-aaef-2b316eb71a36/project/4f0c1980-a3b3-432d-a157-1068783e6a7c)
[![NPM Type Definitions](https://img.shields.io/npm/types/bvault-js?logo=typescript)](https://img.shields.io/npm/types/bvault-js)
[![GitHub commit activity](https://img.shields.io/github/commit-activity/m/kurtiz/bvault-js)](https://img.shields.io/github/commit-activity/m/kurtiz/bvault-js)
[![npm bundle size](https://img.shields.io/bundlephobia/minzip/bvault-js)](https://img.shields.io/bundlephobia/minzip/bvault-js)
[![npm bundle size](https://img.shields.io/bundlephobia/min/bvault-js)](https://img.shields.io/bundlephobia/min/bvault-js)
[![GitHub License](https://img.shields.io/github/license/kurtiz/bvault-js)](https://github.com/kurtiz/bvault-js)

bVault-js is a type-safe, lightweight, zero-dependency cryptographic library for secure encryption and decryption in
browser
environments. It implements AES-GCM encryption with PBKDF2 key derivation, providing a simple API for data protection.

## Features

- 🔒 AES-GCM 256-bit encryption
- 🔑 Password-based key derivation (PBKDF2 with 100,000 iterations)
- 🧂 Automatic salt and IV generation
- 🛡️ Built-in error handling for cryptographic operations
- 💻 Works in browsers (using Web Crypto API)
- 📦 **Secure Local Storage Wrapper** – store/retrieve data in `localStorage` securely with automatic
  encryption/decryption

## Installation

```bash
npm install bvault-js
```

## Usage

### Basic Encryption & Decryption

```javascript
import { encrypt, decrypt } from 'bvault-js';

const password = 'supersecretpassword';
const sensitiveData = 'My confidential information';

// Encrypt data
const { encryptedData, iv, salt } = await encrypt(sensitiveData, password);
console.log('Encrypted:', encryptedData);
console.log('IV:', iv);
console.log('Salt:', salt);

// Decrypt data
const decrypted = await decrypt(encryptedData, password, iv, salt);
console.log('Decrypted:', decrypted); // 'My confidential information'
```

### 🔐 Secure Local Storage Wrapper

bVault-js provides a wrapper around `localStorage` so you can safely persist sensitive data in the browser.

#### Initialization (must be done once at app entry point)

```javascript
import { initializeSecureStorage } from 'bvault-js';

async function bootstrap() {
  await initializeSecureStorage('my-strong-password');
  // Continue with app startup...
}

bootstrap();
```

#### Usage Example

```javascript
import { secureLocalStorage } from 'bvault-js';

// Store data securely
await secureLocalStorage.setItem('userProfile', {
  username: 'alice',
  email: 'alice@example.com',
});

// Retrieve data securely
const stored = await secureLocalStorage.getItem('userProfile');
const profile = stored ? JSON.parse(stored) : null;
console.log(profile);

// Remove a specific key
secureLocalStorage.removeItem('userProfile');

// Clear everything
secureLocalStorage.clear();
```

#### Framework Examples

- **React (entry point initialization)**

```tsx
// main.tsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { initializeSecureStorage } from 'bvault-js';

async function bootstrap() {
  await initializeSecureStorage('react-password');
  ReactDOM.createRoot(document.getElementById('root')!).render(<App />);
}

bootstrap();
```

or

```tsx
// main.tsx
import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { initializeSecureStorage } from 'bvault-js';

(async () => {
  await initializeSecureStorage('react-password');
  ReactDOM.createRoot(document.getElementById('root')!).render(<App />);
})();
```

then

```tsx
// App.tsx
import { useEffect, useState } from 'react';
import { secureLocalStorage } from 'bvault-js';

export default function App() {
  const [profile, setProfile] = useState<any>(null);

  useEffect(() => {
    (async () => {
      await secureLocalStorage.setItem('profile', { username: 'alice' });
      const data = await secureLocalStorage.getItem('profile');
      if (data) setProfile(JSON.parse(data));
    })();
  }, []);

  return <p>{profile ? `Hello ${profile.username}` : 'Loading...'}</p>;
}
```

- **Vue 3**

```ts
// main.ts
import { createApp } from 'vue';
import App from './App.vue';
import { initializeSecureStorage } from 'bvault-js';

async function bootstrap() {
  await initializeSecureStorage('vue-password');
  createApp(App).mount('#app');
}

bootstrap();
```

or

```ts
// main.ts
import { createApp } from 'vue';
import App from './App.vue';
import { initializeSecureStorage } from 'bvault-js';

(async () => {
  await initializeSecureStorage('vue-password');
  createApp(App).mount('#app');
})();
```

then

```vue
<!-- App.vue -->
<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { secureLocalStorage } from 'bvault-js';

const profile = ref<any>(null);

onMounted(async () => {
  await secureLocalStorage.setItem('profile', { username: 'bob' });
  const data = await secureLocalStorage.getItem('profile');
  if (data) profile.value = JSON.parse(data);
});
</script>

<template>
  <p v-if="profile">Hello {{ profile.username }}</p>
  <p v-else>Loading...</p>
</template>
```

- **Svelte**

```ts
// main.ts
import App from './App.svelte';
import { initializeSecureStorage } from 'bvault-js';

async function bootstrap() {
  await initializeSecureStorage('svelte-password');
  new App({ target: document.getElementById('app')! });
}

bootstrap();
```

or

```ts
// main.ts
import App from './App.svelte';
import { initializeSecureStorage } from 'bvault-js';

(async () => {
  await initializeSecureStorage('svelte-password');
  new App({ target: document.getElementById('app')! });
})();
```

then

```svelte
<!-- App.svelte -->
<script lang="ts">
  import { onMount } from 'svelte';
  import { secureLocalStorage } from 'bvault-js';

  let profile: any = null;

  onMount(async () => {
    await secureLocalStorage.setItem('profile', { username: 'carol' });
    const data = await secureLocalStorage.getItem('profile');
    if (data) profile = JSON.parse(data);
  });
</script>

<p>{#if profile}Hello {profile.username}{:else}Loading...{/if}</p>
```

---

### File Encryption

```javascript
import { encrypt } from 'bvault-js';

async function encryptFile(file, password) {
  const reader = new FileReader();

  return new Promise((resolve, reject) => {
    reader.onload = async () => {
      try {
        const encrypted = await encrypt(reader.result, password);
        resolve(encrypted);
      } catch (error) {
        reject(error);
      }
    };
    reader.readAsText(file);
  });
}
```

### Secure Configuration Storage

```javascript
import { encrypt, decrypt } from 'bvault-js';

async function saveConfig(config, password) {
  const encrypted = await encrypt(JSON.stringify(config), password);
  return {
    config: encrypted.encryptedData,
    iv: encrypted.iv,
    salt: encrypted.salt,
  };
}

async function loadConfig(storedConfig, password) {
  try {
    const decrypted = await decrypt(
      storedConfig.config,
      password,
      storedConfig.iv,
      storedConfig.salt,
    );
    return JSON.parse(decrypted);
  } catch (error) {
    return null;
  }
}
```

## API Reference

### `encrypt(data: string, password: string)`

Encrypts data using a password

**Parameters:**

- `data`: String to encrypt
- `password`: Encryption password

**Returns:** Promise resolving to:

```javascript
{
  encryptedData: string,
    iv
:
  string,
    salt
:
  string
}
```

### `decrypt(encryptedData: string, password: string, iv: string, salt: string)`

Decrypts data using the original password and stored parameters

### `secureLocalStorage`

Secure wrapper around `localStorage` with async encryption/decryption.

- `await secureLocalStorage.setItem(key: string, value: unknown)`
- `await secureLocalStorage.getItem(key: string): Promise<string | null>`
- `secureLocalStorage.removeItem(key: string)`
- `secureLocalStorage.clear()`

### `initializeSecureStorage(password: string)`

Initializes secure storage. Must be called once (e.g., at app startup).

### `isSecureStorageInitialized()`

Checks if secure storage has been initialized.

---

## Error Handling

The library throws specific error types for cryptographic operations:

- `EncryptionError`
- `DecryptionError`

```javascript
try {
  const decrypted = await secureLocalStorage.getItem('someKey');
} catch (error) {
  if (error instanceof DecryptionError) {
    console.error('Decryption failed - check your password');
  }
}
```

---

## Security Notes

1. **Password Strength**: Always use strong, unique passwords for encryption
2. **Secure Storage**: Safely store IVs and salts with encrypted data
3. **Never Hardcode**: Never embed passwords in source code
4. **Key Management**: Consider rotating encryption keys periodically
5. **Transport Security**: Use HTTPS when transmitting encrypted data

## Limitations

While bVault-js provides robust encryption capabilities, it has some intentional limitations in its current version:

### 1. **Password-Based Key Constraints**

- **No Key Rotation**: Changing passwords requires re-encrypting all data
- **No Key Export**: Derived keys cannot be exported/backed up independently

### 2. **Performance Considerations**

- **Fixed Iterations**: PBKDF2 fixed at 100,000 iterations (secure but computationally expensive)
- **Large Data**: Not optimized for encrypting files >1GB due to memory constraints

### 3. **Algorithm Constraints**

- **Fixed Algorithms**: Only supports AES-GCM with 256-bit keys
- **No Algorithm Agility**: Cannot switch to other encryption algorithms

### 4. **Input Type Constraints**

- **String-Only Input**: Only encrypts/decrypts UTF-8 strings (not binary data)
- **No Stream Support**: Requires complete data in memory

### 5. **Operational Constraints**

- **No Key Stretching**: Requires full PBKDF2 derivation on each operation
- **No Session Caching**: Keys aren't cached between operations

### 6. **Environmental Constraints**

- **Web Crypto Dependency**: Requires modern browsers or Node.js v15+
- **No Fallback**: No alternative implementations for non-Web Crypto environments

### 7. **Security Model Constraints**

- **No Authentication**: Doesn't verify data integrity before decryption
- **No Key Separation**: Same derivation parameters for encryption/decryption

## Roadmap & Future Improvements

We're actively working to enhance bVault-js with these planned features:

- [ ] **Binary Data Support**: Encrypt/decrypt ArrayBuffer and Blob types
- [ ] **Configurable Algorithms**: Allow choosing between AES-GCM and ChaCha20-Poly1305
- [ ] **Key Management**: Add key rotation and export capabilities
- [ ] **Stream Processing**: Support for large file encryption through stream processing
- [ ] **Web Worker Support**: Offload crypto operations to background threads
- [ ] **Enhanced Security**:
  - [ ] Add authenticated data support (AAD) for AES-GCM
  - [ ] Implement configurable iteration counts
  - [ ] Add key derivation memory hardening (Argon2 support)
- [ ] **Extended Environments**:
  - [ ] React Native compatibility
  - [ ] Service worker support
- [ ] **Developer Experience**:
  - [ ] Additional error diagnostics
  - [ ] Password strength meter integration
  - [ ] TypeScript type enhancements

## When to Consider Alternatives

Consider other solutions if you need:

- Binary data encryption/decryption today
- Encryption of files larger than 1GB
- Algorithm agility (e.g., ChaCha20-Poly1305 support)
- Hardware Security Module (HSM) integration
- Post-quantum cryptography algorithms

## Contribution

Contributions are welcome! Please read the [Contribution Guidelines](CONTRIBUTING.md) before submitting pull requests.
We especially welcome help with items from our roadmap.

## License

MIT © [Aaron Will Djaba](https://github.com/kurtiz)
