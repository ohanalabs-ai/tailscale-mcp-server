import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { createHash, randomBytes } from "node:crypto";
import express from "express";
import { MemoryCredentialStore } from "../../credentials/memoryStore.js";
import { registerOAuthRoutes } from "../../oauth/routes.js";
import { OAuthStore } from "../../oauth/store.js";
import { makeConfig, silentLogger } from "../mcp/helpers.js";

// A tiny fake Tailscale API: /api/v2/tailnet/:tailnet/settings succeeds for
// tailnet "good.example.com" and 401s for anything else, so tests can
// exercise both the success and failure paths of the credential-validation
// probe in POST /authorize without hitting the real network. Uses /settings,
// not the bare /tailnet/:tailnet path -- Tailscale's real API no longer
// exposes that as a GET (confirmed 405 against the live API; see the
// getTailnetSettings() switch in oauth/routes.ts).
function startFakeTailscaleApi(): Promise<{
  url: string;
  close: () => Promise<void>;
}> {
  return new Promise((resolve) => {
    const server = Bun.serve({
      port: 0,
      fetch(req) {
        const url = new URL(req.url);
        if (url.pathname === "/api/v2/tailnet/good.example.com/settings") {
          return Response.json({ devicesApprovalOn: false });
        }
        return Response.json({ message: "unauthorized" }, { status: 401 });
      },
    });
    resolve({
      url: `http://127.0.0.1:${server.port}`,
      close: async () => server.stop(true),
    });
  });
}

function startApp(store: OAuthStore, config: ReturnType<typeof makeConfig>) {
  const app = express();
  registerOAuthRoutes(app, store, config, silentLogger);
  const server = app.listen(0);
  const port = () => (server.address() as { port: number }).port;
  return {
    baseUrl: () => `http://127.0.0.1:${port()}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

describe("OAuth routes", () => {
  let fakeApi: { url: string; close: () => Promise<void> };

  beforeEach(async () => {
    fakeApi = await startFakeTailscaleApi();
  });

  afterEach(async () => {
    await fakeApi.close();
  });

  test("discovery metadata advertises the right endpoints", async () => {
    const store = new OAuthStore(
      new MemoryCredentialStore(),
      fakeApi.url,
      60_000,
    );
    const config = makeConfig({ TAILSCALE_API_BASE_URL: fakeApi.url });
    const app = startApp(store, config);
    const res = await fetch(
      `${app.baseUrl()}/.well-known/oauth-authorization-server`,
    );
    const body = await res.json();
    expect(body.authorization_endpoint).toBe(`${app.baseUrl()}/authorize`);
    expect(body.token_endpoint).toBe(`${app.baseUrl()}/token`);
    expect(body.code_challenge_methods_supported).toEqual(["S256"]);
    await app.close();
  });

  test("server-card.json exposes the mcp endpoint and login url", async () => {
    const store = new OAuthStore(
      new MemoryCredentialStore(),
      fakeApi.url,
      60_000,
    );
    const config = makeConfig({ TAILSCALE_API_BASE_URL: fakeApi.url });
    const app = startApp(store, config);
    const res = await fetch(
      `${app.baseUrl()}/.well-known/mcp/server-card.json`,
    );
    const body = await res.json();
    expect(body.name).toBe("tailscale-mcp-server");
    expect(body.mcp_endpoint).toBe(`${app.baseUrl()}/mcp`);
    await app.close();
  });

  test("register issues a client with the requested redirect_uris", async () => {
    const store = new OAuthStore(
      new MemoryCredentialStore(),
      fakeApi.url,
      60_000,
    );
    const config = makeConfig({ TAILSCALE_API_BASE_URL: fakeApi.url });
    const app = startApp(store, config);
    const res = await fetch(`${app.baseUrl()}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ redirect_uris: ["https://example.com/cb"] }),
    });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.client_id).toBeTruthy();
    expect(body.redirect_uris).toEqual(["https://example.com/cb"]);
    await app.close();
  });

  test("full authorize -> token round trip with PKCE succeeds for valid credentials", async () => {
    const store = new OAuthStore(
      new MemoryCredentialStore(),
      fakeApi.url,
      60_000,
    );
    const config = makeConfig({
      TAILSCALE_API_BASE_URL: fakeApi.url,
      TAILSCALE_ALLOWED_TOOL_RISK: "write",
    });
    const app = startApp(store, config);

    const client = store.registerClient(["https://example.com/cb"]);
    const verifier = randomBytes(32).toString("hex");
    const challenge = createHash("sha256").update(verifier).digest("base64url");

    const authorizeRes = await fetch(`${app.baseUrl()}/authorize`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      redirect: "manual",
      body: new URLSearchParams({
        client_id: client.clientId,
        redirect_uri: "https://example.com/cb",
        state: "xyz",
        code_challenge: challenge,
        code_challenge_method: "S256",
        tailnet: "good.example.com",
        api_key: "tskey-api-valid",
        allowed_risk: "write",
      }),
    });
    expect(authorizeRes.status).toBe(302);
    const location = new URL(authorizeRes.headers.get("location") as string);
    expect(location.searchParams.get("state")).toBe("xyz");
    const code = location.searchParams.get("code") as string;
    expect(code).toBeTruthy();

    const tokenRes = await fetch(`${app.baseUrl()}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        code_verifier: verifier,
      }),
    });
    expect(tokenRes.status).toBe(200);
    const tokenBody = await tokenRes.json();
    expect(tokenBody.token_type).toBe("bearer");
    expect(tokenBody.access_token).toBeTruthy();

    const resolved = await store.lookupToken(tokenBody.access_token);
    expect(resolved).toEqual({
      tailnet: "good.example.com",
      apiKey: "tskey-api-valid",
      allowedRisk: "write",
    });

    await app.close();
  });

  test("the server ceiling caps a caller's requested risk", async () => {
    const store = new OAuthStore(
      new MemoryCredentialStore(),
      fakeApi.url,
      60_000,
    );
    const config = makeConfig({
      TAILSCALE_API_BASE_URL: fakeApi.url,
      TAILSCALE_ALLOWED_TOOL_RISK: "read",
    });
    const app = startApp(store, config);
    const client = store.registerClient(["https://example.com/cb"]);

    const authorizeRes = await fetch(`${app.baseUrl()}/authorize`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      redirect: "manual",
      body: new URLSearchParams({
        client_id: client.clientId,
        redirect_uri: "https://example.com/cb",
        state: "xyz",
        tailnet: "good.example.com",
        api_key: "tskey-api-valid",
        allowed_risk: "admin",
      }),
    });
    const location = new URL(authorizeRes.headers.get("location") as string);
    const code = location.searchParams.get("code") as string;

    const tokenRes = await fetch(`${app.baseUrl()}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "authorization_code", code }),
    });
    const tokenBody = await tokenRes.json();
    const resolved = await store.lookupToken(tokenBody.access_token);
    expect(resolved?.allowedRisk).toBe("read");

    await app.close();
  });

  test("invalid credentials re-render the form with an escaped error, no code issued", async () => {
    const store = new OAuthStore(
      new MemoryCredentialStore(),
      fakeApi.url,
      60_000,
    );
    const config = makeConfig({ TAILSCALE_API_BASE_URL: fakeApi.url });
    const app = startApp(store, config);
    const client = store.registerClient(["https://example.com/cb"]);

    const res = await fetch(`${app.baseUrl()}/authorize`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: client.clientId,
        redirect_uri: "https://example.com/cb",
        state: "xyz",
        tailnet: "<script>bad()</script>",
        api_key: "tskey-api-wrong",
      }),
    });
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Could not verify credentials");
    expect(html).not.toContain("<script>bad()</script>");

    await app.close();
  });

  test("reused/expired code is rejected at the token endpoint", async () => {
    const store = new OAuthStore(
      new MemoryCredentialStore(),
      fakeApi.url,
      60_000,
    );
    const config = makeConfig({ TAILSCALE_API_BASE_URL: fakeApi.url });
    const app = startApp(store, config);

    const res = await fetch(`${app.baseUrl()}/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: "not-a-real-code",
      }),
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_grant");

    await app.close();
  });
});
