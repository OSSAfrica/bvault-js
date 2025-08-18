// src/lib/secure-storage.ts
import BVaultDB from './bvault-db.js';
import { decrypt, encrypt } from './crypto.js';
import { EncryptionError, DecryptionError } from './errors.js';

let isInitialized = false;
let encryptionPassword = '';

/**
 * Metadata stores to keep local/session IV+salt separated in IndexedDB.
 */
const LOCAL_METADATA_STORE = 'encryption_metadata_local';
const SESSION_METADATA_STORE = 'encryption_metadata_session';

/**
 * In-memory caches for IV + salt metadata (to avoid IndexedDB lookups every time).
 */
const localMetadataCache = new Map<string, { iv: string; salt: string }>();
const sessionMetadataCache = new Map<string, { iv: string; salt: string }>();

/**
 * Preserve the original Storage methods so they can still be used internally.
 */
const originalLocal = {
  setItem: localStorage.setItem,
  getItem: localStorage.getItem,
  removeItem: localStorage.removeItem,
  clear: localStorage.clear,
};

const originalSession = {
  setItem: sessionStorage.setItem,
  getItem: sessionStorage.getItem,
  removeItem: sessionStorage.removeItem,
  clear: sessionStorage.clear,
};

/**
 * Initializes secure storage by setting up the encryption password and verifying
 * the database connection. This must be called once before using secure storage functions.
 *
 * @example
 * ```ts
 * await initializeSecureStorage('myStrongPassword');
 * await secureLocalStorage.setItem('user', { id: 1, name: 'Alice' });
 * ```
 *
 * @param {string} password - The encryption password used for securing storage.
 * @returns {Promise<void>}
 * @throws {Error} If initialization fails or no password is provided.
 */
export const initializeSecureStorage = async (
  password: string,
): Promise<void> => {
  if (isInitialized) return;
  if (!password) {
    throw new Error('Provide a password to initialize secure storage.');
  }

  encryptionPassword = password;

  try {
    await BVaultDB.initialize();
    await testDatabaseConnection(LOCAL_METADATA_STORE);
    await testDatabaseConnection(SESSION_METADATA_STORE);
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
 * Tests the connection to the IndexedDB database by writing/deleting a test record.
 *
 * @param {string} store - The name of the metadata store to test.
 */
async function testDatabaseConnection(store: string): Promise<void> {
  const testKey = `__connection_test_${store}__`;
  const testValue = { iv: 'test', salt: 'test' };
  try {
    await BVaultDB.storeData(store, { key: testKey, ...testValue });
    const result = await BVaultDB.getData<{ iv: string; salt: string }>(
      store,
      testKey,
    );
    if (!result)
      throw new Error(`Failed to verify database connection for ${store}`);
    await BVaultDB.deleteData(store, testKey);
  } catch (error) {
    await BVaultDB.deleteData(store, testKey).catch(() => {});
    throw error;
  }
}

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

// ---------- Generic creators so we don’t duplicate logic ----------

/**
 * Creates a secure setItem wrapper.
 */
function createSecureSetItem(
  storage: typeof localStorage | typeof sessionStorage,
  originalSet: typeof localStorage.setItem | typeof sessionStorage.setItem,
  cache: Map<string, { iv: string; salt: string }>,
  store: string,
) {
  return async (key: string, value: unknown): Promise<void> => {
    if (!isInitialized) {
      throw new Error(
        'Secure storage not initialized. Call initializeSecureStorage() first.',
      );
    }

    try {
      const processedValue = processValue(value);
      const encryptionResult = await encrypt(
        processedValue,
        encryptionPassword,
      );

      // Store encrypted value
      originalSet.call(storage, key, encryptionResult.encryptedData);

      // Cache and persist IV + salt
      const metadata = { iv: encryptionResult.iv, salt: encryptionResult.salt };
      cache.set(key, metadata);
      await BVaultDB.storeData(store, { key, ...metadata });
    } catch (error) {
      throw new EncryptionError(`Failed to encrypt and store key "${key}"`, {
        cause: error,
        context: { store, key },
      });
    }
  };
}

/**
 * Creates a secure getItem wrapper.
 */
function createSecureGetItem(
  storage: typeof localStorage | typeof sessionStorage,
  originalGet: typeof localStorage.getItem | typeof sessionStorage.getItem,
  originalRemove: typeof localStorage.removeItem,
  cache: Map<string, { iv: string; salt: string }>,
  store: string,
) {
  return async (key: string): Promise<string | null> => {
    if (!isInitialized) {
      throw new Error(
        'Secure storage not initialized. Call initializeSecureStorage() first.',
      );
    }

    const encryptedValue = originalGet.call(storage, key);

    if (!encryptedValue) return null;

    try {
      let metadata = cache.get(key);
      if (!metadata) {
        metadata = await BVaultDB.getData<{ iv: string; salt: string }>(
          store,
          key,
        );
        if (!metadata) {
          throw new DecryptionError('Missing encryption metadata', {
            context: { store, key },
          });
        }
        cache.set(key, metadata);
      }

      return await decrypt(
        encryptedValue,
        encryptionPassword,
        metadata.iv,
        metadata.salt,
      );
    } catch (error) {
      if (error instanceof DecryptionError) {
        console.error(`Decryption failed for key "${key}":`, error.message);
      } else {
        console.error(`Data retrieval failed for key "${key}":`, error);
      }

      // Clean up corrupted data
      originalRemove.call(storage, key);
      cache.delete(key);
      BVaultDB.deleteData(store, key).catch(console.error);

      return null;
    }
  };
}

/**
 * Creates a secure removeItem wrapper.
 */
function createSecureRemoveItem(
  storage: typeof localStorage | typeof sessionStorage,
  originalRemove:
    | typeof localStorage.removeItem
    | typeof sessionStorage.removeItem,
  cache: Map<string, { iv: string; salt: string }>,
  store: string,
) {
  return (key: string): void => {
    originalRemove.call(storage, key);
    cache.delete(key);
    BVaultDB.deleteData(store, key).catch(console.error);
  };
}

/**
 * Creates a secure clear wrapper.
 */
function createSecureClear(
  storage: typeof localStorage | typeof sessionStorage,
  originalClear: typeof localStorage.clear | typeof sessionStorage.clear,
  cache: Map<string, { iv: string; salt: string }>,
  store: string,
) {
  return (): void => {
    originalClear.call(storage);
    cache.clear();
    BVaultDB.clearStore(store).catch(console.error);
  };
}

// ---------- LocalStorage Secure Wrapper ----------
/**
 * Secure wrapper around `localStorage`.
 * Automatically encrypts/decrypts values and manages IV + salt in IndexedDB.
 */
export const secureLocalStorage = {
  setItem: createSecureSetItem(
    localStorage,
    originalLocal.setItem,
    localMetadataCache,
    LOCAL_METADATA_STORE,
  ),
  getItem: createSecureGetItem(
    localStorage,
    originalLocal.getItem,
    originalLocal.removeItem,
    localMetadataCache,
    LOCAL_METADATA_STORE,
  ),
  removeItem: createSecureRemoveItem(
    localStorage,
    originalLocal.removeItem,
    localMetadataCache,
    LOCAL_METADATA_STORE,
  ),
  clear: createSecureClear(
    localStorage,
    originalLocal.clear,
    localMetadataCache,
    LOCAL_METADATA_STORE,
  ),
};

// ---------- SessionStorage Secure Wrapper ----------
/**
 * Secure wrapper around `sessionStorage`.
 * Automatically encrypts/decrypts values and manages IV + salt in IndexedDB.
 */
export const secureSessionStorage = {
  setItem: createSecureSetItem(
    sessionStorage,
    originalSession.setItem,
    sessionMetadataCache,
    SESSION_METADATA_STORE,
  ),
  getItem: createSecureGetItem(
    sessionStorage,
    originalSession.getItem,
    originalSession.removeItem,
    sessionMetadataCache,
    SESSION_METADATA_STORE,
  ),
  removeItem: createSecureRemoveItem(
    sessionStorage,
    originalSession.removeItem,
    sessionMetadataCache,
    SESSION_METADATA_STORE,
  ),
  clear: createSecureClear(
    sessionStorage,
    originalSession.clear,
    sessionMetadataCache,
    SESSION_METADATA_STORE,
  ),
};

/**
 * Returns true if secure storage has been initialized.
 *
 * @returns {boolean}
 */
export const isSecureStorageInitialized = (): boolean => isInitialized;
