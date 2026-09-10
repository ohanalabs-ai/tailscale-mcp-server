import type { ToolRisk } from "../config/env.js";

// A reconstructable outbound Tailscale credential — the ONLY thing a
// credential store ever persists. It is a tailnet identifier plus the API
// key to present to Tailscale's API, the risk tier the caller was granted at
// login, and the instant the record stops being valid.
//
// It deliberately holds no live objects (no HttpClient, no MCP transport), so
// it can be serialized into Redis and reconstructed on any replica. Ported
// from argocd-mcp-server's src/server/credentials/record.ts.
export const CREDENTIAL_RECORD_VERSION = 1 as const;

export type CredentialRecord = {
  version: typeof CREDENTIAL_RECORD_VERSION;
  tailnet: string;
  apiKey: string;
  allowedRisk: ToolRisk;
  // Epoch milliseconds at which apiKey stops being valid. 0 means "no known
  // expiry". A stored record is treated as absent once now >= expiresAt
  // (when non-zero).
  expiresAt: number;
};

// A record is usable until its expiry instant. A zero expiry never expires on
// its own; the store's TTL still bounds how long it is retained.
export const isExpired = (record: CredentialRecord, now: number): boolean =>
  record.expiresAt !== 0 && now >= record.expiresAt;

const ALLOWED_RISK_VALUES: readonly ToolRisk[] = ["read", "write", "admin"];

// Parse a stored JSON envelope back into a record, or return undefined when
// it is unusable. Fails closed on anything not written by this code: a
// missing/mismatched version, a wrong shape, or a non-object. A malformed
// record is indistinguishable from a cache miss to the caller.
export const parseCredentialRecord = (
  raw: string,
): CredentialRecord | undefined => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (typeof parsed !== "object" || parsed === null) {
    return undefined;
  }
  const candidate = parsed as Record<string, unknown>;
  if (candidate.version !== CREDENTIAL_RECORD_VERSION) {
    return undefined;
  }
  if (
    typeof candidate.tailnet !== "string" ||
    typeof candidate.apiKey !== "string" ||
    typeof candidate.expiresAt !== "number" ||
    typeof candidate.allowedRisk !== "string" ||
    !ALLOWED_RISK_VALUES.includes(candidate.allowedRisk as ToolRisk)
  ) {
    return undefined;
  }
  return {
    version: CREDENTIAL_RECORD_VERSION,
    tailnet: candidate.tailnet,
    apiKey: candidate.apiKey,
    allowedRisk: candidate.allowedRisk as ToolRisk,
    expiresAt: candidate.expiresAt,
  };
};

export const serializeCredentialRecord = (record: CredentialRecord): string =>
  JSON.stringify(record);

// A log-safe view of a record: the apiKey is NEVER included. Use this
// anywhere a record might reach a log line, an error message, or a metric
// label.
export const redactCredentialRecord = (
  record: CredentialRecord,
): { tailnet: string; allowedRisk: ToolRisk; expiresAt: number } => ({
  tailnet: record.tailnet,
  allowedRisk: record.allowedRisk,
  expiresAt: record.expiresAt,
});
