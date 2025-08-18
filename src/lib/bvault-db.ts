// src/lib/bvault-db.ts

/**
 * Interface defining the BVault database contract for IndexedDB operations.
 */
interface BVaultDatabase {
  db: IDBDatabase | null;

  initialize(): Promise<IDBDatabase>;

  storeData(
    storeName: string,
    data: any,
    key?: IDBValidKey,
  ): Promise<IDBValidKey>;

  getData<T>(storeName: string, key: IDBValidKey): Promise<T | undefined>;

  getAllData<T>(storeName: string): Promise<T[]>;

  deleteData(storeName: string, key: IDBValidKey): Promise<void>;

  clearStore(storeName: string): Promise<void>;

  verifyStore(storeName: string): Promise<IDBDatabase>;
}

/**
 * Schema definition for the BVault IndexedDB database.
 * Contains separate stores for local and session encryption metadata.
 */
interface DatabaseSchema {
  version: number;
  stores: {
    name: string;
    options?: IDBObjectStoreParameters;
  }[];
}

/**
 * IndexedDB schema for BVault.
 * We keep separate object stores for local and session storage metadata
 * to avoid collisions and ensure proper cleanup.
 */
const DB_SCHEMA: DatabaseSchema = {
  version: 2, // bump version when schema changes
  stores: [
    {
      name: 'encryption_metadata_local',
      options: { keyPath: 'key' },
    },
    {
      name: 'encryption_metadata_session',
      options: { keyPath: 'key' },
    },
  ],
};

/**
 * BVaultDB provides a simple wrapper around IndexedDB for storing encryption metadata.
 * It handles initialization, schema verification, and CRUD operations.
 */
const BVaultDB: BVaultDatabase = {
  db: null,

  /**
   * Initializes the database and ensures object stores exist.
   * Recreates DB if schema mismatch is detected.
   */
  async initialize(): Promise<IDBDatabase> {
    if (this.db) return this.db;

    return new Promise((resolve, reject) => {
      const request = indexedDB.open('bvault', DB_SCHEMA.version);

      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;

        // Create all defined stores
        DB_SCHEMA.stores.forEach((store) => {
          if (!db.objectStoreNames.contains(store.name)) {
            db.createObjectStore(store.name, store.options);
          }
        });
      };

      request.onsuccess = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;

        // Verify schema consistency
        const missingStores = DB_SCHEMA.stores.filter(
          (store) => !db.objectStoreNames.contains(store.name),
        );

        if (missingStores.length > 0) {
          console.warn(
            'Missing stores detected, deleting and recreating DB...',
          );
          db.close();
          indexedDB.deleteDatabase('bvault').onsuccess = () => {
            this.db = null;
            this.initialize().then(resolve).catch(reject);
          };
          return;
        }

        this.db = db;
        resolve(this.db);
      };

      request.onerror = (event) => {
        reject(
          new Error(
            `Database failed to open: ${(event.target as IDBOpenDBRequest).error}`,
          ),
        );
      };
    });
  },

  /**
   * Stores a record in the given object store.
   */
  async storeData(
    storeName: string,
    data: any,
    key?: IDBValidKey,
  ): Promise<IDBValidKey> {
    const db = await this.verifyStore(storeName);
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(storeName, 'readwrite');
      const store = transaction.objectStore(storeName);

      const request =
        key !== undefined ? store.put(data, key) : store.put(data);

      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  },

  /**
   * Retrieves a record by key from the given object store.
   */
  async getData<T>(
    storeName: string,
    key: IDBValidKey,
  ): Promise<T | undefined> {
    const db = await this.verifyStore(storeName);
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(storeName, 'readonly');
      const store = transaction.objectStore(storeName);
      const request = store.get(key);

      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  },

  /**
   * Retrieves all records from the given object store.
   */
  async getAllData<T>(storeName: string): Promise<T[]> {
    const db = await this.verifyStore(storeName);
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(storeName, 'readonly');
      const store = transaction.objectStore(storeName);
      const request = store.getAll();

      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
    });
  },

  /**
   * Deletes a record by key from the given object store.
   */
  async deleteData(storeName: string, key: IDBValidKey): Promise<void> {
    const db = await this.verifyStore(storeName);
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(storeName, 'readwrite');
      const store = transaction.objectStore(storeName);
      const request = store.delete(key);

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  },

  /**
   * Clears all records from the given object store.
   */
  async clearStore(storeName: string): Promise<void> {
    const db = await this.verifyStore(storeName);
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(storeName, 'readwrite');
      const store = transaction.objectStore(storeName);
      const request = store.clear();

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  },

  /**
   * Ensures that the object store exists and returns the active DB instance.
   */
  async verifyStore(storeName: string): Promise<IDBDatabase> {
    const db = await this.initialize();
    if (!db.objectStoreNames.contains(storeName)) {
      throw new Error(`Object store "${storeName}" does not exist`);
    }
    return db;
  },
};

export default BVaultDB;
