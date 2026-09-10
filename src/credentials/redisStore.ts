import {
  type CredentialRecord,
  isExpired,
  parseCredentialRecord,
  serializeCredentialRecord,
} from "./record.js";
import type { CredentialStore } from "./store.js";
import { hashCacheKey } from "./store.js";

// The subset of a Redis client this store needs. Declaring it as an
// interface — rather than importing the `redis` package's types here — keeps
// the store decoupled from any particular client and, crucially,
// unit-testable against a fake without a running Redis server. The factory
// adapts the real `redis` (node-redis) client, whose method shapes match
// this, to it. Ported from argocd-mcp-server's
// src/server/credentials/redisStore.ts.
export interface RedisLike {
  get(key: string): Promise<string | null>;
  // node-redis: client.set(key, value, { PX: ttlMs }).
  set(key: string, value: string, options: { PX: number }): Promise<unknown>;
  del(key: string): Promise<unknown>;
  ping(): Promise<unknown>;
  quit(): Promise<unknown>;
}

// A hung Redis command must never hold an MCP request open indefinitely.
// Every command races this deadline; on timeout the request fails fast (a
// miss, for get) rather than blocking. The underlying command may still
// complete on the socket — we simply stop waiting for it.
const withTimeout = async <T>(
  op: Promise<T>,
  timeoutMs: number,
  label: string,
): Promise<T> => {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new Error(`Redis ${label} timed out after ${timeoutMs}ms`)),
      timeoutMs,
    );
    timer.unref?.();
  });
  try {
    return await Promise.race([op, timeout]);
  } finally {
    if (timer) {
      clearTimeout(timer);
    }
  }
};

export type RedisCredentialStoreOptions = {
  client: RedisLike;
  // Namespace + schema-version prefix, e.g. "tailscale-mcp:credentials:v1:".
  // Every key this store writes begins with it, so a shared Redis can host
  // other data and a future record-schema change can bump the version
  // without colliding.
  keyPrefix: string;
  // Per-command timeout. Bounds how long any single get/set/del/ping may
  // block.
  operationTimeoutMs: number;
  now?: () => number;
};

// A Redis-backed credential store. Redis holds versioned JSON envelopes with
// a server-side TTL (PX) on every key, so credentials expire even if this
// process never deletes them, and any replica pointed at the same Redis
// resolves what another cached. It stores reconstructable credentials
// only — never live MCP transports (see record.ts).
export class RedisCredentialStore implements CredentialStore {
  private readonly client: RedisLike;
  private readonly keyPrefix: string;
  private readonly operationTimeoutMs: number;
  private readonly now: () => number;

  constructor(options: RedisCredentialStoreOptions) {
    this.client = options.client;
    this.keyPrefix = options.keyPrefix;
    this.operationTimeoutMs = options.operationTimeoutMs;
    this.now = options.now ?? Date.now;
  }

  // The logical key is hashed, so it never appears verbatim in Redis, and an
  // attacker-influenced value cannot inject key metacharacters.
  private redisKey(key: string): string {
    return `${this.keyPrefix}${hashCacheKey(key)}`;
  }

  async get(key: string): Promise<CredentialRecord | undefined> {
    const raw = await withTimeout(
      this.client.get(this.redisKey(key)),
      this.operationTimeoutMs,
      "GET",
    );
    if (raw === null) {
      return undefined;
    }
    const record = parseCredentialRecord(raw);
    // Redis TTL already bounds staleness, but honor the record's own expiry
    // too in case the two ever drift (clock skew, an over-long PX). Fail
    // closed.
    if (!record || isExpired(record, this.now())) {
      return undefined;
    }
    return record;
  }

  async set(
    key: string,
    record: CredentialRecord,
    ttlMs: number,
  ): Promise<void> {
    if (ttlMs <= 0) {
      return;
    }
    const now = this.now();
    const ttlDeadline = now + ttlMs;
    const expiresAt =
      record.expiresAt === 0
        ? ttlDeadline
        : Math.min(ttlDeadline, record.expiresAt);
    const effectiveTtl = expiresAt - now;
    if (effectiveTtl <= 0) {
      return;
    }
    await withTimeout(
      this.client.set(this.redisKey(key), serializeCredentialRecord(record), {
        PX: effectiveTtl,
      }),
      this.operationTimeoutMs,
      "SET",
    );
  }

  async delete(key: string): Promise<void> {
    await withTimeout(
      this.client.del(this.redisKey(key)),
      this.operationTimeoutMs,
      "DEL",
    );
  }

  async ping(): Promise<void> {
    await withTimeout(this.client.ping(), this.operationTimeoutMs, "PING");
  }

  async close(): Promise<void> {
    // Best-effort: a shutdown should not hang on a Redis that is already
    // gone.
    try {
      await withTimeout(this.client.quit(), this.operationTimeoutMs, "QUIT");
    } catch {
      // Nothing actionable during shutdown; the socket is torn down
      // regardless.
    }
  }
}
