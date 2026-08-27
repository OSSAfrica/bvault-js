// src/lib/secure-storage.ts
import BVaultDB from './bvault-db.js';
import { decryptWithKey, encryptWithKey } from './crypto.js';
import { EncryptionError, DecryptionError } from './errors.js';
import { getOrCreateKey, destroyKey, resetKeyCache } from './keystore.js';
import { clearLegacyData } from './migration.js';

let isInitialized = false;
let storageKey: CryptoKey | null = null;
let keyLossReported = false;

/**
 * Prefix applied to every key bVault writes.
 *
 * Values live in the same namespace as the rest of the application's storage,
 * so the prefix keeps bVault from colliding with — or clearing — data written
 * by other code.
 */
const KEY_PREFIX = 'bv1:';

/**
 * Returns the requested Storage object, or throws a useful error when the
 * module is loaded outside a browser.
 *
 * Read lazily: touching `localStorage` at module scope makes importing
 * bvault-js throw during server-side rendering.
 */
const getStorage = (target: 'local' | 'session'): Storage => {
  const storage =
    typeof globalThis !== 'undefined'
      ? target === 'local'
        ? globalThis.localStorage
        : globalThis.sessionStorage
      : undefined;

  if (!storage) {
    throw new Error(
      `${target}Storage is unavailable. bvault-js requires a browser environment.`,
    );
  }

  return storage;
};

/**
 * Initializes secure storage.
 *
 * Loads the encryption key for this origin, generating one on first use, and
 * clears any data left by v0.x. Must be called once before the storage
 * wrappers are used.
 *
 * The key is generated non-extractable: its raw bytes are never exposed to
 * JavaScript, so it cannot be copied out of the browser and used elsewhere.
 *
 * @example
 * ```ts
 * await initializeSecureStorage();
 * await secureLocalStorage.setItem('user', { id: 1, name: 'Alice' });
 * ```
 *
 * @returns {Promise<void>}
 * @throws {Error} If the key cannot be loaded or generated.
 */
export const initializeSecureStorage = async (): Promise<void> => {
  if (isInitialized) return;

  try {
    await clearLegacyData();
    await BVaultDB.initialize();
    storageKey = await getOrCreateKey();
    isInitialized = true;
  } catch (error) {
    const caughtError = error as Error;
    console.error('SecureStorage initialization failed:', caughtError.message);
    throw new Error(
      `Secure storage initialization failed: ${caughtError.message}`,
    );
  }
};

/**
 * Returns the active key, or throws if the library has not been initialized.
 */
const requireKey = (): CryptoKey => {
  if (!isInitialized || !storageKey) {
    throw new Error(
      'Secure storage not initialized. Call initializeSecureStorage() first.',
    );
  }
  return storageKey;
};

/**
 * Converts a value to a string representation before encryption.
 *
 * @param {unknown} value - Any value to be stringified.
 * @returns {string}
 */
const processValue = (value: unknown): string => {
  if (typeof value === 'object' && value !== null) return JSON.stringify(value);
  return String(value);
};

/**
 * Warns once when the key has gone but ciphertext remains, which happens when
 * site data is cleared or the browser evicts IndexedDB. Every stored value is
 * unreadable at that point; nothing is deleted, so the caller can decide.
 */
const reportPossibleKeyLoss = async (): Promise<void> => {
  if (keyLossReported) return;
  keyLossReported = true;
  console.warn(
    'bvault-js: stored values could not be decrypted. The encryption key may ' +
      'have been evicted or cleared, which makes previously stored data ' +
      'permanently unreadable. Stored values have been left untouched.',
  );
};

// ---------- Generic creators so we don't duplicate logic ----------

/**
 * Creates a secure setItem wrapper.
 */
function createSecureSetItem(target: 'local' | 'session') {
  return async (key: string, value: unknown): Promise<void> => {
    const cryptoKey = requireKey();

    try {
      const payload = await encryptWithKey(processValue(value), cryptoKey);
      getStorage(target).setItem(KEY_PREFIX + key, payload);
    } catch (error) {
      throw new EncryptionError(`Failed to encrypt and store key "${key}"`, {
        cause: error,
        context: { target, key },
      });
    }
  };
}

/**
 * Creates a secure getItem wrapper.
 *
 * Returns `null` when a value cannot be decrypted. The stored value is never
 * removed on failure: a transient error or a missing key would otherwise
 * destroy data the caller may still be able to recover.
 */
function createSecureGetItem(target: 'local' | 'session') {
  return async (key: string): Promise<string | null> => {
    const cryptoKey = requireKey();

    const payload = getStorage(target).getItem(KEY_PREFIX + key);
    if (payload === null) return null;

    try {
      return await decryptWithKey(payload, cryptoKey);
    } catch (error) {
      if (error instanceof DecryptionError) {
        console.error(`Decryption failed for key "${key}":`, error.message);
        await reportPossibleKeyLoss();
      } else {
        console.error(`Data retrieval failed for key "${key}":`, error);
      }
      return null;
    }
  };
}

/**
 * Creates a secure removeItem wrapper.
 */
function createSecureRemoveItem(target: 'local' | 'session') {
  return (key: string): void => {
    getStorage(target).removeItem(KEY_PREFIX + key);
  };
}

/**
 * Creates a secure clear wrapper.
 *
 * Removes only bVault's own entries, leaving the rest of the application's
 * storage alone.
 */
function createSecureClear(target: 'local' | 'session') {
  return (): void => {
    const storage = getStorage(target);
    const owned: string[] = [];

    for (let i = 0; i < storage.length; i++) {
      const key = storage.key(i);
      if (key?.startsWith(KEY_PREFIX)) owned.push(key);
    }

    owned.forEach((key) => storage.removeItem(key));
  };
}

// ---------- LocalStorage Secure Wrapper ----------
/**
 * Secure wrapper around `localStorage`.
 * Values are encrypted with a key that cannot be exported from the browser.
 */
export const secureLocalStorage = {
  setItem: createSecureSetItem('local'),
  getItem: createSecureGetItem('local'),
  removeItem: createSecureRemoveItem('local'),
  clear: createSecureClear('local'),
};

// ---------- SessionStorage Secure Wrapper ----------
/**
 * Secure wrapper around `sessionStorage`.
 * Values are encrypted with a key that cannot be exported from the browser.
 */
export const secureSessionStorage = {
  setItem: createSecureSetItem('session'),
  getItem: createSecureGetItem('session'),
  removeItem: createSecureRemoveItem('session'),
  clear: createSecureClear('session'),
};

/**
 * Returns true if secure storage has been initialized.
 *
 * @returns {boolean}
 */
export const isSecureStorageInitialized = (): boolean => isInitialized;

/**
 * Deletes the encryption key and every value stored under it.
 *
 * Intended for logout or account switching. There is no recovery path — once
 * the key is gone, any remaining ciphertext is permanently unreadable.
 *
 * @returns {Promise<void>}
 */
export const destroySecureStorage = async (): Promise<void> => {
  secureLocalStorage.clear();
  secureSessionStorage.clear();
  await destroyKey();
  storageKey = null;
  isInitialized = false;
  keyLossReported = false;
};

/**
 * Resets in-memory state so the next initialization behaves like a fresh page
 * load. Does not touch stored data or the persisted key.
 *
 * @internal
 */
export const resetSecureStorageState = (): void => {
  isInitialized = false;
  storageKey = null;
  keyLossReported = false;
  resetKeyCache();
};
