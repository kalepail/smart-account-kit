/**
 * IndexedDB Storage Adapter
 *
 * Recommended storage for web applications. Provides:
 * - Larger storage limits than localStorage
 * - Structured data with indexing
 * - Async API that doesn't block the main thread
 * - Better support for binary data (Uint8Array)
 */

import type { StorageAdapter, StoredCredential, StoredSession } from "../types.js";
import {
  DB_NAME,
  DB_VERSION,
  IDB_STORE_CREDENTIALS,
  IDB_STORE_SESSION,
  IDB_SESSION_KEY,
  IDB_INDEX_CONTRACT_ID,
  IDB_INDEX_CREATED_AT,
  IDB_INDEX_IS_PRIMARY,
} from "../constants.js";

export class IndexedDBStorage implements StorageAdapter {
  private dbName: string;
  private dbPromise: Promise<IDBDatabase> | null = null;

  constructor(dbName: string = DB_NAME) {
    this.dbName = dbName;
  }

  private async getDB(): Promise<IDBDatabase> {
    if (this.dbPromise) {
      return this.dbPromise;
    }

    this.dbPromise = new Promise((resolve, reject) => {
      if (typeof indexedDB === "undefined") {
        reject(new Error("IndexedDB is not available in this environment"));
        return;
      }

      const request = indexedDB.open(this.dbName, DB_VERSION);

      request.onerror = () => {
        reject(new Error(`Failed to open IndexedDB: ${request.error?.message}`));
      };

      request.onsuccess = () => {
        resolve(request.result);
      };

      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;

        // Create the credentials object store
        if (!db.objectStoreNames.contains(IDB_STORE_CREDENTIALS)) {
          const store = db.createObjectStore(IDB_STORE_CREDENTIALS, {
            keyPath: "credentialId",
          });

          // Create indexes for efficient queries
          store.createIndex(IDB_INDEX_CONTRACT_ID, IDB_INDEX_CONTRACT_ID, { unique: false });
          store.createIndex(IDB_INDEX_CREATED_AT, IDB_INDEX_CREATED_AT, { unique: false });
          store.createIndex(IDB_INDEX_IS_PRIMARY, IDB_INDEX_IS_PRIMARY, { unique: false });
        }

        // Create the session object store (added in v2)
        if (!db.objectStoreNames.contains(IDB_STORE_SESSION)) {
          db.createObjectStore(IDB_STORE_SESSION, { keyPath: "id" });
        }
      };
    });

    return this.dbPromise;
  }

  private async withStore<T>(
    mode: IDBTransactionMode,
    callback: (store: IDBObjectStore) => IDBRequest<T>
  ): Promise<T> {
    const db = await this.getDB();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(IDB_STORE_CREDENTIALS, mode);
      const store = transaction.objectStore(IDB_STORE_CREDENTIALS);
      const request = callback(store);

      request.onsuccess = () => resolve(request.result);
      request.onerror = () =>
        reject(new Error(`IndexedDB operation failed: ${request.error?.message}`));
    });
  }

  async save(credential: StoredCredential): Promise<void> {
    await this.withStore("readwrite", (store) => store.put(credential));
  }

  async get(credentialId: string): Promise<StoredCredential | null> {
    const result = await this.withStore<StoredCredential | undefined>(
      "readonly",
      (store) => store.get(credentialId)
    );
    return result ?? null;
  }

  async getByContract(contractId: string): Promise<StoredCredential[]> {
    const db = await this.getDB();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(IDB_STORE_CREDENTIALS, "readonly");
      const store = transaction.objectStore(IDB_STORE_CREDENTIALS);
      const index = store.index(IDB_INDEX_CONTRACT_ID);
      const request = index.getAll(contractId);

      request.onsuccess = () => resolve(request.result);
      request.onerror = () =>
        reject(
          new Error(`Failed to query by contract: ${request.error?.message}`)
        );
    });
  }

  async getAll(): Promise<StoredCredential[]> {
    return this.withStore<StoredCredential[]>("readonly", (store) =>
      store.getAll()
    );
  }

  async delete(credentialId: string): Promise<void> {
    await this.withStore("readwrite", (store) => store.delete(credentialId));
  }

  async update(
    credentialId: string,
    updates: Partial<Omit<StoredCredential, "credentialId" | "publicKey">>
  ): Promise<void> {
    const existing = await this.get(credentialId);
    if (existing) {
      await this.save({ ...existing, ...updates });
    }
  }

  async clear(): Promise<void> {
    await this.withStore("readwrite", (store) => store.clear());
    await this.clearSession();
  }

  async saveSession(session: StoredSession): Promise<void> {
    const db = await this.getDB();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(IDB_STORE_SESSION, "readwrite");
      const store = transaction.objectStore(IDB_STORE_SESSION);
      const request = store.put({ id: IDB_SESSION_KEY, ...session });

      request.onsuccess = () => resolve();
      request.onerror = () =>
        reject(new Error(`Failed to save session: ${request.error?.message}`));
    });
  }

  async getSession(): Promise<StoredSession | null> {
    const db = await this.getDB();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(IDB_STORE_SESSION, "readonly");
      const store = transaction.objectStore(IDB_STORE_SESSION);
      const request = store.get(IDB_SESSION_KEY);

      request.onsuccess = () => {
        if (request.result) {
          const { id, ...session } = request.result;
          resolve(session as StoredSession);
        } else {
          resolve(null);
        }
      };
      request.onerror = () =>
        reject(new Error(`Failed to get session: ${request.error?.message}`));
    });
  }

  async clearSession(): Promise<void> {
    const db = await this.getDB();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(IDB_STORE_SESSION, "readwrite");
      const store = transaction.objectStore(IDB_STORE_SESSION);
      const request = store.delete(IDB_SESSION_KEY);

      request.onsuccess = () => resolve();
      request.onerror = () =>
        reject(new Error(`Failed to clear session: ${request.error?.message}`));
    });
  }

  /**
   * Close the database connection
   */
  async close(): Promise<void> {
    if (this.dbPromise) {
      const db = await this.dbPromise;
      db.close();
      this.dbPromise = null;
    }
  }

  /**
   * Delete the entire database
   */
  static async deleteDatabase(dbName: string = DB_NAME): Promise<void> {
    return new Promise((resolve, reject) => {
      const request = indexedDB.deleteDatabase(dbName);
      request.onsuccess = () => resolve();
      request.onerror = () =>
        reject(new Error(`Failed to delete database: ${request.error?.message}`));
    });
  }
}
