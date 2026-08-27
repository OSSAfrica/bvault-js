# bVault-js — Encrypted Browser Storage

[![npm version](https://img.shields.io/npm/v/bvault-js?logo=npm)](https://www.npmjs.com/package/bvault-js)
[![wakatime](https://wakatime.com/badge/user/9657174f-2430-4dfd-aaef-2b316eb71a36/project/4f0c1980-a3b3-432d-a157-1068783e6a7c.svg)](https://wakatime.com/badge/user/9657174f-2430-4dfd-aaef-2b316eb71a36/project/4f0c1980-a3b3-432d-a157-1068783e6a7c)
[![NPM Type Definitions](https://img.shields.io/npm/types/bvault-js?logo=typescript)](https://img.shields.io/npm/types/bvault-js)
[![GitHub License](https://img.shields.io/github/license/kurtiz/bvault-js)](https://github.com/kurtiz/bvault-js)

bVault-js encrypts data in `localStorage` and `sessionStorage` with a key that **cannot be exported
from the browser**. Applications routinely keep session tokens and personal data in browser storage,
where anyone who can read that storage can copy it and replay it elsewhere. bVault-js is built to
make that copy worthless.

- 🔒 AES-GCM 256-bit authenticated encryption
- 🔑 Non-extractable `CryptoKey` — the key material is never visible to JavaScript
- 🧂 Fresh IV per write, carried inline with the ciphertext
- 📦 Drop-in-shaped wrappers for `localStorage` and `sessionStorage`
- 🌍 Safe to import under SSR (Next.js, Remix, SvelteKit)
- 📐 Zero dependencies, fully typed

## What this protects against

Be precise about this before adopting it. bVault-js narrows the blast radius of stolen storage; it is
not a defence against an attacker who is already executing script on your page.

| Attack                                                                    | Result           | Why                                               |
| ------------------------------------------------------------------------- | ---------------- | ------------------------------------------------- |
| Storage copied and replayed in another browser                            | **Defeated**     | The key does not serialize into the dump          |
| Passive exfiltration (`JSON.stringify(localStorage)`, extension scraping) | **Defeated**     | Yields ciphertext only                            |
| Casual inspection via DevTools                                            | **Defeated**     | Nothing readable at rest                          |
| Live XSS calling `subtle.decrypt()`                                       | **Not defeated** | Script in your origin can use the key handle      |
| Whole-profile file copy                                                   | **Unverified**   | Browser and platform dependent — we make no claim |

Injected script can _use_ the key while it runs on your page; it cannot _steal_ it for offline or
cross-browser use. That turns permanent session compromise into access that ends when the script
does. **bVault-js is not a substitute for preventing XSS**, and session tokens are still safest in
`httpOnly` cookies, which JavaScript cannot read at all.

## Installation

```bash
npm install bvault-js
```

## Usage

Initialize once at your application's entry point, then use the wrappers anywhere.

```javascript
import { initializeSecureStorage } from 'bvault-js';

async function bootstrap() {
  await initializeSecureStorage();
  // Continue with app startup...
}

bootstrap();
```

On first run this generates an AES-GCM key and stores it in IndexedDB. On later runs it loads the
same key. No password is involved — see [Why there is no password](#why-there-is-no-password).

### Secure local storage

```javascript
import { secureLocalStorage } from 'bvault-js';

await secureLocalStorage.setItem('userProfile', {
  username: 'alice',
  email: 'alice@example.com',
});

const stored = await secureLocalStorage.getItem('userProfile');
const profile = stored ? JSON.parse(stored) : null;

secureLocalStorage.removeItem('userProfile');
secureLocalStorage.clear(); // removes only bVault's own entries
```

### Secure session storage

```javascript
import { secureSessionStorage } from 'bvault-js';

await secureSessionStorage.setItem('authToken', 'abc123');
const token = await secureSessionStorage.getItem('authToken'); // "abc123"
```

`setItem` and `getItem` are asynchronous because the Web Crypto API is asynchronous. This is not an
implementation detail that can be removed: a synchronous API would require the raw key bytes to be
held in JavaScript memory, which is exactly what makes a key stealable.

### Framework examples

**React**

```tsx
// main.tsx
import ReactDOM from 'react-dom/client';
import App from './App';
import { initializeSecureStorage } from 'bvault-js';

(async () => {
  await initializeSecureStorage();
  ReactDOM.createRoot(document.getElementById('root')!).render(<App />);
})();
```

```tsx
// App.tsx
import { useEffect, useState } from 'react';
import { secureLocalStorage } from 'bvault-js';

export default function App() {
  const [profile, setProfile] = useState<{ username: string } | null>(null);

  useEffect(() => {
    (async () => {
      await secureLocalStorage.setItem('profile', { username: 'carol' });
      const data = await secureLocalStorage.getItem('profile');
      if (data) setProfile(JSON.parse(data));
    })();
  }, []);

  return <p>{profile ? `Hello ${profile.username}` : 'Loading...'}</p>;
}
```

**Vue 3**

```ts
// main.ts
import { createApp } from 'vue';
import App from './App.vue';
import { initializeSecureStorage } from 'bvault-js';

(async () => {
  await initializeSecureStorage();
  createApp(App).mount('#app');
})();
```

```vue
<!-- App.vue -->
<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { secureLocalStorage } from 'bvault-js';

const profile = ref<{ username: string } | null>(null);

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

**Svelte**

```ts
// main.ts
import App from './App.svelte';
import { initializeSecureStorage } from 'bvault-js';

(async () => {
  await initializeSecureStorage();
  new App({ target: document.getElementById('app')! });
})();
```

## Limitations you must plan for

### Key loss is total data loss

There is no password and therefore no recovery path. If IndexedDB is cleared — the user clears site
data, or the browser evicts it under storage pressure — every stored value becomes permanently
unreadable. bVault-js calls `navigator.storage.persist()` to reduce the risk, but browsers may
refuse.

When a value cannot be decrypted, `getItem` returns `null` and logs a warning. **It never deletes the
stored value**, so your application can decide what to do.

Treat bVault-js as a cache for data you can re-fetch, not as a system of record.

### Safari discards everything after 7 days

WebKit deletes all script-writable storage — IndexedDB, `localStorage`, `sessionStorage`, Service
Workers — after seven days of browser use without interaction with your site. The key and the
ciphertext go together, so nothing is orphaned, but **the vault is ephemeral on Safari**. Web apps
added to the home screen are exempt.

### Why there is no password

Earlier versions derived the key from a password, and recommended sourcing it from a browser
fingerprint. That recommendation has been withdrawn. A fingerprint is not secret — any script in your
origin can recompute it — and it carries roughly
[13 bits of entropy](https://arxiv.org/pdf/1812.03920) where key material needs 100+. It is also
unstable: fingerprinting libraries report
[90.5–95.5% accuracy](https://www.thumbmarkjs.com/resources/tech/), so a browser or driver update
silently changes the key and renders stored data undecryptable.

A generated non-extractable key has none of these problems: full entropy, perfectly stable, and
impossible to reconstruct off-device.

## API Reference

### `initializeSecureStorage(): Promise<void>`

Loads the encryption key for this origin, generating one on first use, and clears any data written by
v0.x. Call once at startup before using the wrappers.

### `secureLocalStorage` / `secureSessionStorage`

- `await setItem(key: string, value: unknown): Promise<void>` — objects are JSON-stringified
- `await getItem(key: string): Promise<string | null>` — `null` if absent or undecryptable
- `removeItem(key: string): void`
- `clear(): void` — removes only entries written by bVault-js

Keys are stored under a `bv1:` prefix so bVault-js never collides with, or clears, storage belonging
to other libraries.

### `destroySecureStorage(): Promise<void>`

Deletes the key and every value stored under it. Intended for logout or account switching. There is
no recovery path.

### `isSecureStorageInitialized(): boolean`

### Errors

`EncryptionError` and `DecryptionError` are exported. `setItem` throws `EncryptionError` on failure;
`getItem` returns `null` rather than throwing.

## Migrating from 0.x

1.0.0 is a breaking release.

- `initializeSecureStorage()` no longer takes a password
- `encrypt` and `decrypt` have been removed — the library now does one job
- Data written by 0.x **cannot be migrated**, because keys derived from a password or fingerprint are
  not recoverable. It is deleted once on first initialization, with a warning. Only keys that 0.x
  recorded in its own metadata are touched; storage belonging to other libraries is left alone.

If you need password-based encryption for something other than browser storage, use the Web Crypto
API directly or a dedicated library.

## License

MIT
