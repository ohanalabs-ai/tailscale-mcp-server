import { describe, expect, test } from "bun:test";
import {
  CREDENTIAL_RECORD_VERSION,
  type CredentialRecord,
} from "../../credentials/record.js";
import {
  RedisCredentialStore,
  type RedisLike,
} from "../../credentials/redisStore.js";

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

// A fake Redis backing a shared Map, so two store instances pointed at the
// same backing simulate two replicas sharing one Redis. Honors PX expiry
// against an injectable clock. Ported from argocd-mcp-server's
// src/server/credentials/redisStore.test.ts FakeRedis.
type Backing = Map<string, { value: string; expireAt: number }>;

class FakeRedis implements RedisLike {
  quitCalls = 0;
  constructor(
    private readonly backing: Backing,
    private readonly now: () => number,
  ) {}
  async get(key: string): Promise<string | null> {
    const entry = this.backing.get(key);
    if (!entry) return null;
    if (this.now() >= entry.expireAt) {
      this.backing.delete(key);
      return null;
    }
    return entry.value;
  }
  async set(
    key: string,
    value: string,
    options: { PX: number },
  ): Promise<unknown> {
    this.backing.set(key, { value, expireAt: this.now() + options.PX });
    return "OK";
  }
  async del(key: string): Promise<unknown> {
    return this.backing.delete(key) ? 1 : 0;
  }
  async ping(): Promise<unknown> {
    return "PONG";
  }
  async quit(): Promise<unknown> {
    this.quitCalls += 1;
    return "OK";
  }
}

const clock = () => {
  let now = 0;
  return { now: () => now, advance: (ms: number) => (now += ms) };
};

const makeStore = (
  backing: Backing,
  now: () => number,
  keyPrefix = "test:v1:",
) =>
  new RedisCredentialStore({
    client: new FakeRedis(backing, now),
    keyPrefix,
    operationTimeoutMs: 1000,
    now,
  });

describe("RedisCredentialStore", () => {
  test("set then get round-trips through Redis", async () => {
    const t = clock();
    const store = makeStore(new Map(), t.now);
    await store.set("k", record(), 60_000);
    expect(await store.get("k")).toEqual(record());
  });

  test("two independent stores share one backing (cross-replica resolution)", async () => {
    const t = clock();
    const backing: Backing = new Map();
    const replicaA = makeStore(backing, t.now);
    const replicaB = makeStore(backing, t.now);

    await replicaA.set("user-1", record({ apiKey: "from-a" }), 60_000);
    expect((await replicaB.get("user-1"))?.apiKey).toBe("from-a");

    await replicaB.delete("user-1");
    expect(await replicaA.get("user-1")).toBeUndefined();
  });

  test("Redis TTL (PX) expires the entry", async () => {
    const t = clock();
    const store = makeStore(new Map(), t.now);
    await store.set("k", record(), 1_000);
    t.advance(1_000);
    expect(await store.get("k")).toBeUndefined();
  });

  test("a malformed stored value reads as a miss (fail closed)", async () => {
    const t = clock();
    const backing: Backing = new Map();
    const store = makeStore(backing, t.now);
    await store.set("k", record(), 60_000);
    const key = [...backing.keys()][0] as string;
    backing.set(key, { value: "not json", expireAt: t.now() + 60_000 });
    expect(await store.get("k")).toBeUndefined();
  });

  test("different keys get isolated Redis entries", async () => {
    const t = clock();
    const backing: Backing = new Map();
    const store = makeStore(backing, t.now);
    await store.set("user-a", record({ apiKey: "a" }), 60_000);
    await store.set("user-b", record({ apiKey: "b" }), 60_000);
    expect(backing.size).toBe(2);
    expect((await store.get("user-a"))?.apiKey).toBe("a");
    expect((await store.get("user-b"))?.apiKey).toBe("b");
  });

  test("every key carries the configured prefix and no principal appears verbatim", async () => {
    const t = clock();
    const backing: Backing = new Map();
    const store = makeStore(backing, t.now, "tailscale-mcp:credentials:v1:");
    await store.set("very-secret-token", record(), 60_000);
    const key = [...backing.keys()][0] as string;
    expect(key.startsWith("tailscale-mcp:credentials:v1:")).toBe(true);
    expect(key.includes("very-secret-token")).toBe(false);
  });

  test("close calls quit", async () => {
    const t = clock();
    const client = new FakeRedis(new Map(), t.now);
    const store = new RedisCredentialStore({
      client,
      keyPrefix: "x:",
      operationTimeoutMs: 1000,
      now: t.now,
    });
    await store.close();
    expect(client.quitCalls).toBe(1);
  });
});
