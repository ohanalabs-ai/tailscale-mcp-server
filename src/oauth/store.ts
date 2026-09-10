import { createHash, randomBytes } from "node:crypto";
import type { ToolRisk } from "../config/env.js";
import {
  CREDENTIAL_RECORD_VERSION,
  type CredentialRecord,
} from "../credentials/record.js";
import type { CredentialStore } from "../credentials/store.js";
import { credentialCacheKey, hashCacheKey } from "../credentials/store.js";

// Ported from argocd-mcp-server's src/server/oauth/store.ts, with one
// deliberate adaptation: issueToken/lookupToken write through a pluggable
// CredentialStore (memory or Redis, see src/credentials/) instead of a
// private in-memory Map, so the OAuth-login-collected credential survives
// across replicas when MCP_CREDENTIAL_STORE=redis is configured. The
// reference itself keeps this piece in-memory only; ephemeral client
// registrations and 60-second auth codes stay in-memory here too, matching
// both references (neither persists that bookkeeping to Redis).

export type OAuthClient = {
  clientId: string;
  clientSecret: string;
  redirectUris: string[];
};

type AuthCodeEntry = {
  tailnet: string;
  apiKey: string;
  allowedRisk: ToolRisk;
  clientId: string;
  redirectUri: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  expiresAt: number;
};

export type AccessTokenData = {
  tailnet: string;
  apiKey: string;
  allowedRisk: ToolRisk;
};

const AUTH_CODE_TTL_MS = 60_000;

export class OAuthStore {
  private readonly clients = new Map<string, OAuthClient>();
  private readonly codes = new Map<string, AuthCodeEntry>();

  constructor(
    private readonly credentialStore: CredentialStore,
    private readonly tailscaleApiBaseUrl: string,
    private readonly tokenTtlMs: number,
  ) {}

  registerClient(redirectUris: string[]): OAuthClient {
    const clientId = randomBytes(16).toString("hex");
    const clientSecret = randomBytes(32).toString("hex");
    const client: OAuthClient = { clientId, clientSecret, redirectUris };
    this.clients.set(clientId, client);
    return client;
  }

  getClient(clientId: string): OAuthClient | undefined {
    return this.clients.get(clientId);
  }

  issueCode(data: Omit<AuthCodeEntry, "expiresAt">): string {
    const code = randomBytes(32).toString("hex");
    this.codes.set(code, { ...data, expiresAt: Date.now() + AUTH_CODE_TTL_MS });
    return code;
  }

  consumeCode(code: string, codeVerifier?: string): AuthCodeEntry | null {
    const entry = this.codes.get(code);
    this.codes.delete(code);
    if (!entry || Date.now() > entry.expiresAt) {
      return null;
    }

    // PKCE S256 verification when the code was issued with a challenge.
    if (entry.codeChallenge) {
      if (!codeVerifier) {
        return null;
      }
      const digest = createHash("sha256")
        .update(codeVerifier)
        .digest("base64url");
      if (digest !== entry.codeChallenge) {
        return null;
      }
    }

    return entry;
  }

  async issueToken(
    data: Omit<AccessTokenData, never> & { clientId: string },
  ): Promise<string> {
    const token = randomBytes(32).toString("hex");
    const record: CredentialRecord = {
      version: CREDENTIAL_RECORD_VERSION,
      tailnet: data.tailnet,
      apiKey: data.apiKey,
      allowedRisk: data.allowedRisk,
      expiresAt: 0,
    };
    const key = hashCacheKey(
      credentialCacheKey(token, this.tailscaleApiBaseUrl),
    );
    await this.credentialStore.set(key, record, this.tokenTtlMs);
    return token;
  }

  async lookupToken(token: string): Promise<AccessTokenData | undefined> {
    const key = hashCacheKey(
      credentialCacheKey(token, this.tailscaleApiBaseUrl),
    );
    const record = await this.credentialStore.get(key);
    if (!record) {
      return undefined;
    }
    return {
      tailnet: record.tailnet,
      apiKey: record.apiKey,
      allowedRisk: record.allowedRisk,
    };
  }
}
