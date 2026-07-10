import "fake-indexeddb/auto";
import { describe, expect, it } from "vitest";
import { IndexedDBStorage } from "./indexeddb";
import type { StoredCredential, StoredSession } from "../types";

let dbCounter = 0;
/** A fresh, isolated database per test. */
function freshStore(): IndexedDBStorage {
  return new IndexedDBStorage(`sak-test-${dbCounter++}`);
}

function makeCredential(
  id: string,
  contractId: string,
  extra: Partial<StoredCredential> = {}
): StoredCredential {
  return {
    credentialId: id,
    publicKey: new Uint8Array([4, 5, 6]),
    contractId,
    createdAt: 1,
    ...extra,
  };
}

describe("IndexedDBStorage", () => {
  it("saves and retrieves credentials, preserving the Uint8Array public key", async () => {
    const store = freshStore();
    await store.save(makeCredential("a", "C1"));
    const got = await store.get("a");
    expect(got?.credentialId).toBe("a");
    expect(got?.publicKey).toBeInstanceOf(Uint8Array);
    expect(Array.from(got!.publicKey)).toEqual([4, 5, 6]);
    expect(await store.get("missing")).toBeNull();
    await store.close();
  });

  it("queries by contract via the contractId index and lists all", async () => {
    const store = freshStore();
    await store.save(makeCredential("a", "C1"));
    await store.save(makeCredential("b", "C1"));
    await store.save(makeCredential("c", "C2"));
    expect(await store.getByContract("C1")).toHaveLength(2);
    expect(await store.getByContract("C2")).toHaveLength(1);
    expect(await store.getAll()).toHaveLength(3);
    await store.close();
  });

  it("updates mutable fields and ignores unknown credentials", async () => {
    const store = freshStore();
    await store.save(makeCredential("a", "C1"));
    await store.update("a", { nickname: "primary" });
    expect((await store.get("a"))?.nickname).toBe("primary");
    await store.update("missing", { nickname: "x" }); // no throw
    expect(await store.get("missing")).toBeNull();
    await store.close();
  });

  it("deletes credentials and clears the store", async () => {
    const store = freshStore();
    await store.save(makeCredential("a", "C1"));
    await store.save(makeCredential("b", "C1"));
    await store.delete("a");
    expect(await store.get("a")).toBeNull();
    await store.clear();
    expect(await store.getAll()).toHaveLength(0);
    await store.close();
  });

  it("stores, reads and clears the session (v2 session store)", async () => {
    const store = freshStore();
    const session: StoredSession = {
      contractId: "C1",
      credentialId: "a",
      connectedAt: 1,
      expiresAt: 2,
    };
    await store.saveSession(session);
    // The internal `id` key is stripped from the returned session.
    expect(await store.getSession()).toEqual(session);
    await store.clearSession();
    expect(await store.getSession()).toBeNull();
    await store.close();
  });

  it("clear() also wipes the session", async () => {
    const store = freshStore();
    await store.saveSession({ contractId: "C1", credentialId: "a", connectedAt: 1, expiresAt: 2 });
    await store.clear();
    expect(await store.getSession()).toBeNull();
    await store.close();
  });

  it("deleteDatabase removes a database", async () => {
    const name = `sak-test-del-${dbCounter++}`;
    const store = new IndexedDBStorage(name);
    await store.save(makeCredential("a", "C1"));
    await store.close();
    await expect(IndexedDBStorage.deleteDatabase(name)).resolves.toBeUndefined();
  });
});
