import { describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { MemoryCredentialStore } from "../../credentials/memoryStore.js";
import { OAuthStore } from "../../oauth/store.js";

function makeStore() {
  return new OAuthStore(
    new MemoryCredentialStore(),
    "https://api.tailscale.com",
    60_000,
  );
}

describe("OAuthStore", () => {
  test("registerClient mints a client with the given redirect URIs", () => {
    const store = makeStore();
    const client = store.registerClient(["https://example.com/callback"]);
    expect(client.clientId).toMatch(/^[a-f0-9]{32}$/);
    expect(client.clientSecret).toMatch(/^[a-f0-9]{64}$/);
    expect(client.redirectUris).toEqual(["https://example.com/callback"]);
    expect(store.getClient(client.clientId)).toEqual(client);
  });

  test("getClient returns undefined for an unknown id", () => {
    expect(makeStore().getClient("nope")).toBeUndefined();
  });

  test("issueCode/consumeCode round-trips without PKCE", () => {
    const store = makeStore();
    const code = store.issueCode({
      tailnet: "example.com",
      apiKey: "key",
      allowedRisk: "read",
      clientId: "c1",
      redirectUri: "https://example.com/cb",
    });
    const entry = store.consumeCode(code);
    expect(entry).toMatchObject({ tailnet: "example.com", apiKey: "key" });
  });

  test("a code can only be consumed once", () => {
    const store = makeStore();
    const code = store.issueCode({
      tailnet: "example.com",
      apiKey: "key",
      allowedRisk: "read",
      clientId: "c1",
      redirectUri: "https://example.com/cb",
    });
    expect(store.consumeCode(code)).not.toBeNull();
    expect(store.consumeCode(code)).toBeNull();
  });

  test("PKCE: a matching verifier succeeds", () => {
    const store = makeStore();
    const verifier = "a-verifier-string-that-is-long-enough";
    const challenge = createHash("sha256").update(verifier).digest("base64url");
    const code = store.issueCode({
      tailnet: "example.com",
      apiKey: "key",
      allowedRisk: "read",
      clientId: "c1",
      redirectUri: "https://example.com/cb",
      codeChallenge: challenge,
      codeChallengeMethod: "S256",
    });
    expect(store.consumeCode(code, verifier)).not.toBeNull();
  });

  test("PKCE: a wrong verifier is rejected", () => {
    const store = makeStore();
    const challenge = createHash("sha256")
      .update("correct")
      .digest("base64url");
    const code = store.issueCode({
      tailnet: "example.com",
      apiKey: "key",
      allowedRisk: "read",
      clientId: "c1",
      redirectUri: "https://example.com/cb",
      codeChallenge: challenge,
      codeChallengeMethod: "S256",
    });
    expect(store.consumeCode(code, "wrong")).toBeNull();
  });

  test("PKCE: a missing verifier is rejected when a challenge was issued", () => {
    const store = makeStore();
    const challenge = createHash("sha256")
      .update("correct")
      .digest("base64url");
    const code = store.issueCode({
      tailnet: "example.com",
      apiKey: "key",
      allowedRisk: "read",
      clientId: "c1",
      redirectUri: "https://example.com/cb",
      codeChallenge: challenge,
      codeChallengeMethod: "S256",
    });
    expect(store.consumeCode(code)).toBeNull();
  });

  test("issueToken/lookupToken round-trips via the credential store", async () => {
    const store = makeStore();
    const token = await store.issueToken({
      tailnet: "example.com",
      apiKey: "top-secret-key",
      allowedRisk: "write",
      clientId: "c1",
    });
    expect(await store.lookupToken(token)).toEqual({
      tailnet: "example.com",
      apiKey: "top-secret-key",
      allowedRisk: "write",
    });
  });

  test("lookupToken on an unknown token is a miss", async () => {
    expect(await makeStore().lookupToken("not-a-real-token")).toBeUndefined();
  });
});
