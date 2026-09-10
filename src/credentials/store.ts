import { createHash } from "node:crypto";
import type { CredentialRecord } from "./record.js";

// A keyed, TTL-bounded cache of reconstructable outbound credentials. Two
// implementations exist — in-process memory and Redis — and they are
// contract-compatible: the same key written through one is readable through
// another pointed at the same backing store (this is what lets any replica
// resolve a credential another replica cached). See memoryStore.ts and
// redisStore.ts. Ported from argocd-mcp-server's
// src/server/credentials/store.ts.
//
// The store is intentionally dumb: it does not know how a credential was
// obtained or how to refresh it. Whoever calls set() owns that policy and
// hands the store a ready-made record plus the TTL to keep it for.
export interface CredentialStore {
  // Return the record for key, or undefined on a miss or an expired/unusable
  // entry. Never throws for a miss — a miss and a malformed record look the
  // same to the caller.
  get(key: string): Promise<CredentialRecord | undefined>;

  // Store record under key for at most ttlMs. A non-positive ttlMs is a
  // no-op: there is no point caching something already expired.
  set(key: string, record: CredentialRecord, ttlMs: number): Promise<void>;

  // Remove key. Idempotent — deleting a missing key is not an error.
  delete(key: string): Promise<void>;

  // Liveness check for a readiness probe. Memory is always ready; Redis
  // pings. Throws when the backing store is unreachable.
  ping(): Promise<void>;

  // Release resources (timers, socket). Idempotent.
  close(): Promise<void>;
}

// The cache key for an outbound credential: the caller's principal (here, the
// opaque OAuth access token minted at login) plus the normalized target base
// URL. Two invariants ride on this key:
//
//   1. Different callers must never share a cached credential — so the
//      principal is part of the key.
//   2. A credential cached for one Tailscale API base URL must never satisfy
//      a request against a different one.
//
// The two components are joined with a newline, which neither can contain, so
// the key is unambiguous. redisStore hashes this before using it as a Redis
// key.
export const credentialCacheKey = (
  principal: string,
  baseUrl: string,
): string => `${principal}\n${baseUrl}`;

// A fixed-length, opaque key derived from the logical cache key. Used by the
// Redis store so the principal never appears verbatim in a Redis key name,
// and so an attacker-influenced value cannot smuggle Redis glob
// metacharacters into keys.
export const hashCacheKey = (key: string): string =>
  createHash("sha256").update(key, "utf8").digest("hex");
