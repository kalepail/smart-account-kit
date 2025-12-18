/**
 * Storage Adapters for Credential Persistence
 *
 * This module provides various storage implementations for persisting
 * WebAuthn credential data (including the crucial credential IDs).
 */

export { MemoryStorage } from "./memory";
export { LocalStorageAdapter } from "./localStorage";
export { IndexedDBStorage } from "./indexeddb";

export type { StorageAdapter } from "../types";
