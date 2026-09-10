import { describe, expect, test } from "bun:test";
import { MemoryCredentialStore } from "../../credentials/memoryStore.js";
import {
  CREDENTIAL_RECORD_VERSION,
  type CredentialRecord,
} from "../../credentials/record.js";

const record = (
  overrides: Partial<CredentialRecord> = {},
): CredentialRecord => ({
  version: CREDENTIAL_RECORD_VERSION,
  tailnet: "example.com",
  apiKey: "secret",
  allowedRisk: "read",
  expiresAt: 0,
  ...overrides,
});

const clock = () => {
  let now = 0;
  return { now: () => now, advance: (ms: number) => (now += ms) };
};

describe("MemoryCredentialStore", () => {
  test("set then get round-trips", async () => {
    const store = new MemoryCredentialStore();
    await store.set("k", record(), 60_000);
    expect(await store.get("k")).toEqual(record());
    await store.close();
  });

  test("a missing key is a miss", async () => {
    const store = new MemoryCredentialStore();
    expect(await store.get("nope")).toBeUndefined();
    await store.close();
  });

  test("TTL expires the entry", async () => {
    const t = clock();
    const store = new MemoryCredentialStore(t.now);
    await store.set("k", record(), 1_000);
    t.advance(1_000);
    expect(await store.get("k")).toBeUndefined();
    await store.close();
  });

  test("the record's own expiresAt bounds the entry even with a longer ttl", async () => {
    const t = clock();
    const store = new MemoryCredentialStore(t.now);
    await store.set("k", record({ expiresAt: 500 }), 60_000);
    t.advance(500);
    expect(await store.get("k")).toBeUndefined();
    await store.close();
  });

  test("a non-positive ttl is a no-op", async () => {
    const store = new MemoryCredentialStore();
    await store.set("k", record(), 0);
    expect(await store.get("k")).toBeUndefined();
    await store.close();
  });

  test("delete removes the entry and is idempotent", async () => {
    const store = new MemoryCredentialStore();
    await store.set("k", record(), 60_000);
    await store.delete("k");
    expect(await store.get("k")).toBeUndefined();
    await store.delete("k");
    await store.close();
  });

  test("ping never throws", async () => {
    const store = new MemoryCredentialStore();
    await expect(store.ping()).resolves.toBeUndefined();
    await store.close();
  });
});
