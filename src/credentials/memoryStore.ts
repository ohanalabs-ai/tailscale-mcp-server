import { type CredentialRecord, isExpired } from "./record.js";
import type { CredentialStore } from "./store.js";

// An in-process credential store. This is the default when a store is
// enabled without Redis, and it is the honest ceiling of what one replica
// can share: entries live in this process only, so a second replica sees
// none of them. For multi-replica credential sharing, use RedisCredentialStore.
// Ported from argocd-mcp-server's src/server/credentials/memoryStore.ts.
//
// Unlike a naive map, expired entries are actively removed — both lazily on
// read and by a periodic sweep — so a caller that stops appearing cannot pin
// its credential in memory until the process restarts.
type Entry = {
  record: CredentialRecord;
  // Absolute epoch-ms deadline: min(record expiry, now + ttl). The entry is
  // gone once now >= expiresAt.
  expiresAt: number;
};

// How often to sweep expired entries. The sweep is a backstop for entries
// that are never read again; correctness does not depend on it (get()
// checks expiry), so a coarse interval is fine.
const SWEEP_INTERVAL_MS = 60_000;

export class MemoryCredentialStore implements CredentialStore {
  private entries = new Map<string, Entry>();
  private readonly sweep: NodeJS.Timeout;
  private readonly now: () => number;

  // now is injectable so tests can advance time deterministically instead of
  // sleeping. It defaults to the wall clock.
  constructor(now: () => number = Date.now) {
    this.now = now;
    this.sweep = setInterval(() => this.evictExpired(), SWEEP_INTERVAL_MS);
    // Do not keep the event loop alive just for the sweep; a server with
    // nothing else pending should still be able to exit.
    this.sweep.unref?.();
  }

  async get(key: string): Promise<CredentialRecord | undefined> {
    const entry = this.entries.get(key);
    if (!entry) {
      return undefined;
    }
    const now = this.now();
    if (now >= entry.expiresAt || isExpired(entry.record, now)) {
      this.entries.delete(key);
      return undefined;
    }
    return entry.record;
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
    // The entry is bounded by BOTH the requested TTL and the record's own
    // expiry: caching a credential past the instant it stops working would
    // only serve a dead credential.
    const ttlDeadline = now + ttlMs;
    const expiresAt =
      record.expiresAt === 0
        ? ttlDeadline
        : Math.min(ttlDeadline, record.expiresAt);
    if (expiresAt <= now) {
      return;
    }
    this.entries.set(key, { record, expiresAt });
  }

  async delete(key: string): Promise<void> {
    this.entries.delete(key);
  }

  async ping(): Promise<void> {
    // In-process: if this code is running, the store is reachable.
  }

  async close(): Promise<void> {
    clearInterval(this.sweep);
    this.entries.clear();
  }

  private evictExpired(): void {
    const now = this.now();
    for (const [key, entry] of this.entries) {
      if (now >= entry.expiresAt || isExpired(entry.record, now)) {
        this.entries.delete(key);
      }
    }
  }
}
