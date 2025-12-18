/**
 * In-Memory Storage Adapter
 *
 * Simple in-memory storage for credentials. Useful for testing or
 * server-side environments where persistence isn't needed.
 *
 * WARNING: Data is lost when the application restarts.
 */

import type { StorageAdapter, StoredCredential, StoredSession } from "../types";

export class MemoryStorage implements StorageAdapter {
  private credentials: Map<string, StoredCredential> = new Map();
  private session: StoredSession | null = null;

  async save(credential: StoredCredential): Promise<void> {
    this.credentials.set(credential.credentialId, { ...credential });
  }

  async get(credentialId: string): Promise<StoredCredential | null> {
    const credential = this.credentials.get(credentialId);
    return credential ? { ...credential } : null;
  }

  async getByContract(contractId: string): Promise<StoredCredential[]> {
    const results: StoredCredential[] = [];
    for (const credential of this.credentials.values()) {
      if (credential.contractId === contractId) {
        results.push({ ...credential });
      }
    }
    return results;
  }

  async getAll(): Promise<StoredCredential[]> {
    return Array.from(this.credentials.values()).map((c) => ({ ...c }));
  }

  async delete(credentialId: string): Promise<void> {
    this.credentials.delete(credentialId);
  }

  async update(
    credentialId: string,
    updates: Partial<Omit<StoredCredential, "credentialId" | "publicKey">>
  ): Promise<void> {
    const credential = this.credentials.get(credentialId);
    if (credential) {
      this.credentials.set(credentialId, { ...credential, ...updates });
    }
  }

  async clear(): Promise<void> {
    this.credentials.clear();
    this.session = null;
  }

  async saveSession(session: StoredSession): Promise<void> {
    this.session = { ...session };
  }

  async getSession(): Promise<StoredSession | null> {
    return this.session ? { ...this.session } : null;
  }

  async clearSession(): Promise<void> {
    this.session = null;
  }
}
