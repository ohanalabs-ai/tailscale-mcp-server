import { createClient } from "redis";
import type { AppLogger } from "../observability/logger.js";
import type { CredentialConfig, RedisStoreConfig } from "./config.js";
import { MemoryCredentialStore } from "./memoryStore.js";
import { RedisCredentialStore, type RedisLike } from "./redisStore.js";
import type { CredentialStore } from "./store.js";

// Adapted from argocd-mcp-server's src/server/credentials/factory.ts.
// Unlike that reference (which lazily `require()`s the optional `redis`
// package so memory/none deployments never need it installed), this repo
// adds `redis` as a normal dependency and imports it statically — simpler,
// at the cost of always installing it even when unused.
type NodeRedisClient = RedisLike & {
  connect(): Promise<unknown>;
  on(event: "error", listener: (err: unknown) => void): unknown;
};

const createRedisStore = async (
  config: RedisStoreConfig,
  logger: AppLogger,
): Promise<CredentialStore> => {
  const client = createClient({
    url: config.url,
    socket: { connectTimeout: config.operationTimeoutMs },
  }) as unknown as NodeRedisClient;

  // node-redis throws on an unhandled 'error' event; log without the URL,
  // which may embed a password.
  client.on("error", (err: unknown) => {
    logger.error(
      `Redis credential store error: ${err instanceof Error ? err.message : String(err)}`,
    );
  });

  // Fail closed at startup: a redis backend that cannot connect must not
  // silently degrade.
  try {
    await client.connect();
    await client.ping();
  } catch (err) {
    throw new Error(
      `Failed to connect to the Redis credential store: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  logger.info("Connected to Redis credential store");
  return new RedisCredentialStore({
    client,
    keyPrefix: config.keyPrefix,
    operationTimeoutMs: config.operationTimeoutMs,
  });
};

// Builds the configured CredentialStore, or undefined when the layer is off
// (MCP_CREDENTIAL_STORE=none, the default) — in which case OAuthStore falls
// back to its own private in-memory map (see src/oauth/store.ts).
export const createCredentialStore = async (
  config: CredentialConfig,
  logger: AppLogger,
): Promise<CredentialStore | undefined> => {
  switch (config.store.backend) {
    case "none":
      return undefined;
    case "memory":
      logger.info(
        "Using in-memory credential store (single-replica; not shared across processes)",
      );
      return new MemoryCredentialStore();
    case "redis":
      return createRedisStore(config.store, logger);
  }
};
