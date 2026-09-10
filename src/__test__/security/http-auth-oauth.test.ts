import { describe, expect, test } from "bun:test";
import express from "express";
import { MemoryCredentialStore } from "../../credentials/memoryStore.js";
import { OAuthStore } from "../../oauth/store.js";
import { createHttpAuthMiddleware } from "../../security/auth.js";
import { makeConfig } from "../mcp/helpers.js";

function startApp(store?: OAuthStore) {
  const app = express();
  app.use(express.json());
  const config = makeConfig({
    MCP_HTTP_BEARER_TOKEN: "static-token-12345678901234567890",
  });
  app.use("/mcp", createHttpAuthMiddleware(config, store));
  app.post("/mcp", (req, res) => {
    const credential = (req as unknown as { tailscaleCredential?: unknown })
      .tailscaleCredential;
    res.json({ ok: true, credential: credential ?? null });
  });
  const server = app.listen(0);
  const port = () => (server.address() as { port: number }).port;
  return {
    baseUrl: () => `http://127.0.0.1:${port()}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

describe("createHttpAuthMiddleware with an OAuthStore", () => {
  test("discovery methods still bypass auth entirely", async () => {
    const app = startApp();
    const res = await fetch(`${app.baseUrl()}/mcp`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Host: "localhost" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
    });
    expect(res.status).toBe(200);
    await app.close();
  });

  test("the static bearer token still works with no OAuthStore configured", async () => {
    const app = startApp();
    const res = await fetch(`${app.baseUrl()}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Host: "localhost",
        Authorization: "Bearer static-token-12345678901234567890",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call" }),
    });
    expect(res.status).toBe(200);
    await app.close();
  });

  test("a valid OAuth access token resolves the caller's credential", async () => {
    const store = new OAuthStore(
      new MemoryCredentialStore(),
      "https://api.tailscale.com",
      60_000,
    );
    const token = await store.issueToken({
      tailnet: "example.com",
      apiKey: "tskey-api-secret",
      allowedRisk: "write",
      clientId: "c1",
    });

    const app = startApp(store);
    const res = await fetch(`${app.baseUrl()}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Host: "localhost",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call" }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.credential).toEqual({
      tailnet: "example.com",
      apiKey: "tskey-api-secret",
      allowedRisk: "write",
    });
    await app.close();
  });

  test("an unknown or expired token is rejected", async () => {
    const store = new OAuthStore(
      new MemoryCredentialStore(),
      "https://api.tailscale.com",
      60_000,
    );
    const app = startApp(store);
    const res = await fetch(`${app.baseUrl()}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Host: "localhost",
        Authorization: "Bearer not-a-real-token",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call" }),
    });
    expect(res.status).toBe(401);
    const body = await res.json();
    expect(body.loginUrl).toContain("/authorize");
    await app.close();
  });

  test("no Authorization header at all is rejected for tools/call", async () => {
    const app = startApp();
    const res = await fetch(`${app.baseUrl()}/mcp`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Host: "localhost" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call" }),
    });
    expect(res.status).toBe(401);
    await app.close();
  });
});
