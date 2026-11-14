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
 * The lookup or creation currently in flight, shared by concurrent callers so
 * one tab never generates two keys.
 */
let pendingKey: Promise<CryptoKey> | null = null;

/**
 * Reads the stored key, or generates one and writes it with `add()`.
 *
 * `add()` is atomic across tabs: exactly one writer succeeds and every other
 * gets a `ConstraintError`. The loser discards its own key and adopts the
 * winner's, in a fresh transaction. Any other error propagates.
 */
const loadOrCreateKey = async (): Promise<CryptoKey> => {
  const existing = await BVaultDB.getData<CryptoKey>(KEY_STORE, KEY_ID);
  if (existing) return existing;

  const key = await crypto.subtle.generateKey(KEY_ALGORITHM, false, [
    'encrypt',
    'decrypt',
  ]);

  try {
    await BVaultDB.addData(KEY_STORE, key, KEY_ID);
  } catch (error) {
    if ((error as DOMException)?.name !== 'ConstraintError') throw error;

    const winner = await BVaultDB.getData<CryptoKey>(KEY_STORE, KEY_ID);
    if (!winner) throw error;
    return winner;
  }

  await requestPersistence();
  return key;
};

/**
 * Returns the stored encryption key, generating and persisting one on first use.
 *
 * Concurrent callers share one lookup, and across tabs the first write wins, so
 * every caller ends up with the same persisted key. The key is cached only once
 * its write has committed. A failed attempt is not cached, so callers can retry.
 *
 * The key is generated with `extractable: false`, so its raw bytes are never
 * exposed to JavaScript — `crypto.subtle.exportKey()` on it rejects. It is
 * structured-clonable, which is what allows it to persist in IndexedDB.
 *
 * @returns {Promise<CryptoKey>} The AES-GCM key for this origin.
 */
export const getOrCreateKey = async (): Promise<CryptoKey> => {
  if (cachedKey) return cachedKey;

  pendingKey ??= loadOrCreateKey()
    .then((key) => {
      cachedKey = key;
      return key;
    })
    .finally(() => {
      pendingKey = null;
    });

  return pendingKey;
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
  // shortcut: destroying while a key is being created in this tab can re-cache the old key.
  cachedKey = null;
  pendingKey = null;
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
  pendingKey = null;
};
