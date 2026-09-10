// Configuration for the outbound credential layer, parsed from the
// environment. Everything here is env-only (not CLI): argv is world-readable
// via `ps`, so secrets — the Redis URL, which may embed a password — must
// never pass through it.
//
// The layer is OFF by default (backend 'none'): with no configuration the
// server behaves exactly as before this feature existed. Ported from
// argocd-mcp-server's src/server/credentials/config.ts.

export type RedisStoreConfig = {
  backend: "redis";
  url: string;
  keyPrefix: string;
  operationTimeoutMs: number;
};

export type StoreConfig =
  | { backend: "none" }
  | { backend: "memory" }
  | RedisStoreConfig;

export type CredentialConfig = {
  store: StoreConfig;
  // Upper bound on how long an issued OAuth access token's credential is
  // cached.
  ttlMs: number;
};

const DEFAULT_TTL_MS = 2 * 60 * 60 * 1000; // 2h
const MIN_TTL_MS = 60 * 1000; // 1m
const MAX_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7d
const DEFAULT_REDIS_KEY_PREFIX = "tailscale-mcp:credentials:v1:";
const DEFAULT_REDIS_OPERATION_TIMEOUT_MS = 5000;

type Env = Record<string, string | undefined>;

const trimmed = (env: Env, key: string): string | undefined => {
  const value = env[key];
  if (value === undefined) {
    return undefined;
  }
  const t = value.trim();
  return t === "" ? undefined : t;
};

// Parse a positive-integer millisecond env var, throwing (fail closed) on a
// value that is present but not usable. An operator who set it meant
// something.
const positiveInt = (env: Env, key: string, fallback: number): number => {
  const raw = trimmed(env, key);
  if (raw === undefined) {
    return fallback;
  }
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(
      `${key} must be a positive integer (milliseconds); got "${raw}".`,
    );
  }
  return value;
};

const parseStore = (env: Env): StoreConfig => {
  const backend = (
    trimmed(env, "MCP_CREDENTIAL_STORE") ?? "none"
  ).toLowerCase();
  if (backend === "none") {
    return { backend: "none" };
  }
  if (backend === "memory") {
    return { backend: "memory" };
  }
  if (backend === "redis") {
    const url = trimmed(env, "MCP_REDIS_URL");
    // No fallback to memory: a redis backend that cannot find its URL is a
    // misconfiguration. Falling back would make credentials resolvable on
    // one replica and not another — the exact inconsistency the store
    // exists to avoid.
    if (!url) {
      throw new Error(
        "MCP_CREDENTIAL_STORE=redis requires MCP_REDIS_URL to be set.",
      );
    }
    return {
      backend: "redis",
      url,
      keyPrefix:
        trimmed(env, "MCP_REDIS_KEY_PREFIX") ?? DEFAULT_REDIS_KEY_PREFIX,
      operationTimeoutMs: positiveInt(
        env,
        "MCP_REDIS_OPERATION_TIMEOUT_MS",
        DEFAULT_REDIS_OPERATION_TIMEOUT_MS,
      ),
    };
  }
  throw new Error(
    `MCP_CREDENTIAL_STORE must be one of none|memory|redis; got "${backend}".`,
  );
};

export const credentialConfigFromEnv = (
  env: Env = process.env,
): CredentialConfig => {
  const ttlMs = positiveInt(env, "MCP_CREDENTIAL_TTL_MS", DEFAULT_TTL_MS);
  if (ttlMs < MIN_TTL_MS || ttlMs > MAX_TTL_MS) {
    throw new Error(
      `MCP_CREDENTIAL_TTL_MS must be between ${MIN_TTL_MS} and ${MAX_TTL_MS} ms; got ${ttlMs}.`,
    );
  }
  return {
    store: parseStore(env),
    ttlMs,
  };
};
