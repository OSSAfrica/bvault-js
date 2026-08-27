// src/lib/migration.ts

/**
 * Object stores used by 0.x to hold per-item IV and salt.
 */
const LEGACY_STORES = {
  encryption_metadata_local: 'local',
  encryption_metadata_session: 'session',
} as const;

/**
 * Opens the bVault database at whatever version currently exists, without
 * triggering a schema upgrade. Resolves `null` if it cannot be opened.
 */
const openExisting = (): Promise<IDBDatabase | null> =>
  new Promise((resolve) => {
    let request: IDBOpenDBRequest;
    try {
      request = indexedDB.open('bvault');
    } catch {
      resolve(null);
      return;
    }
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => resolve(null);
    request.onblocked = () => resolve(null);
  });

/**
 * Reads every record key from a store, resolving to an empty list on failure.
 */
const readKeys = (db: IDBDatabase, storeName: string): Promise<string[]> =>
  new Promise((resolve) => {
    try {
      const request = db
        .transaction(storeName, 'readonly')
        .objectStore(storeName)
        .getAllKeys();
      request.onsuccess = () => resolve(request.result.map(String));
      request.onerror = () => resolve([]);
    } catch {
      resolve([]);
    }
  });

/**
 * Removes data written by 0.x.
 *
 * Values encrypted under a password- or fingerprint-derived key cannot be
 * migrated, because that key is not recoverable. They are deleted instead.
 *
 * Only keys recorded in the legacy metadata stores are touched. bVault 0.x
 * wrote ciphertext under the caller's own key, so its entries are otherwise
 * indistinguishable from data belonging to other libraries — clearing anything
 * that merely fails to parse would destroy unrelated values.
 *
 * @returns {Promise<number>} Count of legacy entries removed.
 */
export const clearLegacyData = async (): Promise<number> => {
  const db = await openExisting();
  if (!db) return 0;

  let removed = 0;

  try {
    for (const [storeName, target] of Object.entries(LEGACY_STORES)) {
      if (!db.objectStoreNames.contains(storeName)) continue;

      const storage = target === 'local' ? localStorage : sessionStorage;
      for (const key of await readKeys(db, storeName)) {
        if (storage.getItem(key) !== null) {
          storage.removeItem(key);
          removed++;
        }
      }
    }
  } finally {
    db.close();
  }

  if (removed > 0) {
    console.warn(
      `bvault-js: removed ${removed} value(s) written by v0.x. Data encrypted ` +
        'under the previous key scheme cannot be migrated and must be written again. ' +
        'See https://github.com/OSSAfrica/bvault-js/issues/5',
    );
  }

  return removed;
};
