// src/lib/keystore.ts

import BVaultDB from './bvault-db.js';

/**
 * Object store holding the encryption key.
 */
const KEY_STORE = 'keys';

/**
 * Record key under which the single storage key is kept.
 */
const KEY_ID = 'storage-key';

/**
 * Algorithm used for the generated storage key.
 */
const KEY_ALGORITHM: AesKeyGenParams = { name: 'AES-GCM', length: 256 };

/**
 * In-memory handle so repeated lookups don't hit IndexedDB.
 */
let cachedKey: CryptoKey | null = null;

/**
 * Asks the browser to keep this origin's storage from being evicted under
 * pressure. Best-effort: the key is the only copy, so eviction means the
 * stored data becomes unreadable, but a refusal is not an error.
 */
const requestPersistence = async (): Promise<void> => {
  try {
    if (typeof navigator === 'undefined' || !navigator.storage?.persist) return;
    if (await navigator.storage.persisted?.()) return;
    await navigator.storage.persist();
  } catch {
    // Storage manager unavailable or blocked; nothing to do.
  }
};

/**
 * Returns the stored encryption key, generating and persisting one on first use.
 *
 * The key is generated with `extractable: false`, so its raw bytes are never
 * exposed to JavaScript — `crypto.subtle.exportKey()` on it rejects. It is
 * structured-clonable, which is what allows it to persist in IndexedDB.
 *
 * @returns {Promise<CryptoKey>} The AES-GCM key for this origin.
 */
export const getOrCreateKey = async (): Promise<CryptoKey> => {
  if (cachedKey) return cachedKey;

  const existing = await BVaultDB.getData<CryptoKey>(KEY_STORE, KEY_ID);
  if (existing) {
    cachedKey = existing;
    return existing;
  }

  const key = await crypto.subtle.generateKey(KEY_ALGORITHM, false, [
    'encrypt',
    'decrypt',
  ]);

  await BVaultDB.storeData(KEY_STORE, key, KEY_ID);
  await requestPersistence();

  cachedKey = key;
  return key;
};

/**
 * Reports whether a key has already been generated for this origin.
 *
 * @returns {Promise<boolean>}
 */
export const hasKey = async (): Promise<boolean> => {
  if (cachedKey) return true;
  return (await BVaultDB.getData<CryptoKey>(KEY_STORE, KEY_ID)) !== undefined;
};

/**
 * Permanently deletes the encryption key.
 *
 * Every value written under it becomes unreadable — there is no recovery path.
 * This is the intended "wipe" primitive for logout or account switching.
 *
 * @returns {Promise<void>}
 */
export const destroyKey = async (): Promise<void> => {
  cachedKey = null;
  await BVaultDB.deleteData(KEY_STORE, KEY_ID);
};

/**
 * Clears the in-memory key handle without touching IndexedDB.
 * Intended for tests that need to simulate a fresh page load.
 *
 * @internal
 */
export const resetKeyCache = (): void => {
  cachedKey = null;
};
