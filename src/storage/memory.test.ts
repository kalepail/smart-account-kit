import { describe, expect, it } from "vitest";
import { MemoryStorage } from "./memory";
import type { StoredCredential, StoredSession } from "../types";

function makeCredential(id: string, contractId: string): StoredCredential {
  return {
    credentialId: id,
    publicKey: new Uint8Array([1, 2, 3]),
    contractId,
    createdAt: 1,
  };
}

describe("MemoryStorage", () => {
  it("saves and retrieves credentials by id", async () => {
    const store = new MemoryStorage();
    await store.save(makeCredential("a", "C1"));
    const got = await store.get("a");
    expect(got?.credentialId).toBe("a");
    expect(await store.get("missing")).toBeNull();
  });

  it("returns a copy, not the stored reference", async () => {
    const store = new MemoryStorage();
    const cred = makeCredential("a", "C1");
    await store.save(cred);
    const got = await store.get("a");
    got!.contractId = "MUTATED";
    expect((await store.get("a"))?.contractId).toBe("C1");
  });

  it("filters by contract and lists all", async () => {
    const store = new MemoryStorage();
    await store.save(makeCredential("a", "C1"));
    await store.save(makeCredential("b", "C1"));
    await store.save(makeCredential("c", "C2"));
    expect(await store.getByContract("C1")).toHaveLength(2);
    expect(await store.getAll()).toHaveLength(3);
  });

  it("updates mutable fields but leaves unknown credentials untouched", async () => {
    const store = new MemoryStorage();
    await store.save(makeCredential("a", "C1"));
    await store.update("a", { nickname: "primary" });
    expect((await store.get("a"))?.nickname).toBe("primary");
    await store.update("missing", { nickname: "x" }); // no throw
  });

  it("deletes credentials", async () => {
    const store = new MemoryStorage();
    await store.save(makeCredential("a", "C1"));
    await store.delete("a");
    expect(await store.get("a")).toBeNull();
  });

  it("stores and clears sessions", async () => {
    const store = new MemoryStorage();
    const session: StoredSession = {
      contractId: "C1",
      credentialId: "a",
      connectedAt: 1,
      expiresAt: 2,
    };
    await store.saveSession(session);
    expect(await store.getSession()).toEqual(session);
    await store.clearSession();
    expect(await store.getSession()).toBeNull();
  });

  it("clear() wipes credentials and session", async () => {
    const store = new MemoryStorage();
    await store.save(makeCredential("a", "C1"));
    await store.saveSession({ contractId: "C1", credentialId: "a", connectedAt: 1, expiresAt: 2 });
    await store.clear();
    expect(await store.getAll()).toHaveLength(0);
    expect(await store.getSession()).toBeNull();
  });
});
