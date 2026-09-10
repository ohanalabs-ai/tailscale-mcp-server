import { describe, expect, test } from "bun:test";
import { credentialConfigFromEnv } from "../../credentials/config.js";

describe("credentialConfigFromEnv", () => {
  test("defaults to store 'none' and a 2h TTL with no env set", () => {
    const config = credentialConfigFromEnv({});
    expect(config.store).toEqual({ backend: "none" });
    expect(config.ttlMs).toBe(2 * 60 * 60 * 1000);
  });

  test("MCP_CREDENTIAL_STORE=memory", () => {
    const config = credentialConfigFromEnv({ MCP_CREDENTIAL_STORE: "memory" });
    expect(config.store).toEqual({ backend: "memory" });
  });

  test("MCP_CREDENTIAL_STORE=redis requires MCP_REDIS_URL", () => {
    expect(() =>
      credentialConfigFromEnv({ MCP_CREDENTIAL_STORE: "redis" }),
    ).toThrow("MCP_CREDENTIAL_STORE=redis requires MCP_REDIS_URL to be set.");
  });

  test("MCP_CREDENTIAL_STORE=redis with a URL parses defaults", () => {
    const config = credentialConfigFromEnv({
      MCP_CREDENTIAL_STORE: "redis",
      MCP_REDIS_URL: "redis://localhost:6379",
    });
    expect(config.store).toEqual({
      backend: "redis",
      url: "redis://localhost:6379",
      keyPrefix: "tailscale-mcp:credentials:v1:",
      operationTimeoutMs: 5000,
    });
  });

  test("MCP_REDIS_KEY_PREFIX and MCP_REDIS_OPERATION_TIMEOUT_MS override defaults", () => {
    const config = credentialConfigFromEnv({
      MCP_CREDENTIAL_STORE: "redis",
      MCP_REDIS_URL: "redis://localhost:6379",
      MCP_REDIS_KEY_PREFIX: "custom:",
      MCP_REDIS_OPERATION_TIMEOUT_MS: "1234",
    });
    expect(config.store).toMatchObject({
      keyPrefix: "custom:",
      operationTimeoutMs: 1234,
    });
  });

  test("rejects an unknown MCP_CREDENTIAL_STORE value", () => {
    expect(() =>
      credentialConfigFromEnv({ MCP_CREDENTIAL_STORE: "sqlite" }),
    ).toThrow(/must be one of none\|memory\|redis/);
  });

  test("MCP_CREDENTIAL_TTL_MS overrides the default within bounds", () => {
    const config = credentialConfigFromEnv({ MCP_CREDENTIAL_TTL_MS: "600000" });
    expect(config.ttlMs).toBe(600_000);
  });

  test("MCP_CREDENTIAL_TTL_MS below the 1-minute floor throws", () => {
    expect(() =>
      credentialConfigFromEnv({ MCP_CREDENTIAL_TTL_MS: "1000" }),
    ).toThrow(/must be between/);
  });

  test("MCP_CREDENTIAL_TTL_MS above the 7-day ceiling throws", () => {
    expect(() =>
      credentialConfigFromEnv({
        MCP_CREDENTIAL_TTL_MS: String(8 * 24 * 60 * 60 * 1000),
      }),
    ).toThrow(/must be between/);
  });

  test("a non-numeric MCP_CREDENTIAL_TTL_MS throws", () => {
    expect(() =>
      credentialConfigFromEnv({ MCP_CREDENTIAL_TTL_MS: "not-a-number" }),
    ).toThrow(/must be a positive integer/);
  });
});
