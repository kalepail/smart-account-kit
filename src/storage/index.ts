/**
 * Storage Adapters for Credential Persistence
 *
 * This module provides various storage implementations for persisting
 * WebAuthn credential data (including the crucial credential IDs).
 */

export { MemoryStorage } from "./memory.js";
export { LocalStorageAdapter } from "./localStorage.js";
export { IndexedDBStorage } from "./indexeddb.js";

export type { StorageAdapter } from "../types.js";
