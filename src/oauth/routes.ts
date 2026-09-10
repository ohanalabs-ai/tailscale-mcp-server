import express from "express";
import type { AppConfig, ToolRisk } from "../config/env.js";
import type { AppLogger } from "../observability/logger.js";
import { TailscaleApiClient } from "../tailscale/api-client.js";
import type { OAuthStore } from "./store.js";

// Ported from argocd-mcp-server's src/server/oauth/routes.ts. The form
// fields (argocd_url/argocd_token there) are replaced with api_key/tailnet,
// plus a risk-tier radio group (read/write/admin) required by this server's
// per-caller advertisement gating (see src/security/scopes.ts). Also adds
// GET /.well-known/mcp/server-card.json, ported from kubernetes-mcp-server's
// handleServerCard -- argocd's own PR doesn't implement this one, but a
// third sibling (osv-mcp-server) independently confirms it's a required
// cross-server convention (its registry.json's mcpServerCardUrl points here).

const RISK_RANK: Record<ToolRisk, number> = { read: 0, write: 1, admin: 2 };

const cappedRisk = (requested: ToolRisk, ceiling: ToolRisk): ToolRisk =>
  RISK_RANK[requested] <= RISK_RANK[ceiling] ? requested : ceiling;

// Minimal HTML escaping for values embedded in attributes/text.
const esc = (s = ""): string =>
  s
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

function authorizeHtml(p: {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  error?: string;
}): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Tailscale MCP — Connect</title>
<style>
  *{box-sizing:border-box}
  body{font-family:system-ui,sans-serif;max-width:440px;margin:10vh auto;padding:0 1rem;color:#111}
  h1{font-size:1.2rem;margin-bottom:0}
  .sub{font-size:.85rem;color:#555;margin-top:.25rem}
  label{display:block;margin-top:1.25rem;font-size:.85rem;font-weight:600}
  input[type=text],input[type=password]{
    width:100%;padding:.5rem .625rem;margin-top:.3rem;
    border:1px solid #d1d5db;border-radius:4px;font-size:1rem;
  }
  input:focus{outline:2px solid #4f46e5;border-color:#4f46e5}
  .hint{font-size:.75rem;color:#6b7280;margin:.25rem 0 0}
  .error{background:#fef2f2;border:1px solid #fca5a5;border-radius:4px;
    padding:.5rem .75rem;margin-top:1rem;color:#991b1b;font-size:.85rem}
  .radio-group{margin-top:1.25rem}
  .radio-option{display:flex;align-items:baseline;gap:.5rem;margin-top:.5rem}
  .radio-option input{margin:0}
  button{display:block;width:100%;margin-top:1.5rem;padding:.65rem;
    background:#4f46e5;color:#fff;border:none;border-radius:4px;
    font-size:1rem;font-weight:600;cursor:pointer}
  button:hover{background:#4338ca}
  .logo{font-size:2rem;margin-bottom:.5rem}
</style>
</head>
<body>
  <div class="logo">🔒</div>
  <h1>Connect to Tailscale</h1>
  <p class="sub">Enter your Tailscale API key and Tailnet ID to authorize this MCP session.</p>
  ${p.error ? `<div class="error">${esc(p.error)}</div>` : ""}
  <form method="post" action="/authorize">
    <input type="hidden" name="client_id"             value="${esc(p.clientId)}">
    <input type="hidden" name="redirect_uri"          value="${esc(p.redirectUri)}">
    <input type="hidden" name="state"                 value="${esc(p.state)}">
    ${p.codeChallenge ? `<input type="hidden" name="code_challenge" value="${esc(p.codeChallenge)}">` : ""}
    ${p.codeChallengeMethod ? `<input type="hidden" name="code_challenge_method" value="${esc(p.codeChallengeMethod)}">` : ""}

    <label for="tailnet">Tailnet ID</label>
    <input id="tailnet" name="tailnet" type="text"
           placeholder="example.com" required autocomplete="off">
    <p class="hint">
      Find it at <a href="https://console.tailscale.com/admin/settings/general" target="_blank" rel="noopener">console.tailscale.com/admin/settings/general</a>.
    </p>

    <label for="api_key">API Key</label>
    <input id="api_key" name="api_key" type="password"
           placeholder="tskey-api-..." required autocomplete="off">
    <p class="hint">
      Generate at <a href="https://console.tailscale.com/admin/settings/keys" target="_blank" rel="noopener">console.tailscale.com/admin/settings/keys</a> ("API access tokens").
    </p>

    <div class="radio-group">
      <label>Access level</label>
      <div class="radio-option">
        <input type="radio" id="risk_read" name="allowed_risk" value="read" checked>
        <label for="risk_read" style="margin:0;font-weight:400">Read-Only — view devices, tailnet info, DNS/ACL settings</label>
      </div>
      <div class="radio-option">
        <input type="radio" id="risk_write" name="allowed_risk" value="write">
        <label for="risk_write" style="margin:0;font-weight:400">Read-Write — also change routes, tags, DNS/ACL settings</label>
      </div>
      <div class="radio-option">
        <input type="radio" id="risk_admin" name="allowed_risk" value="admin">
        <label for="risk_admin" style="margin:0;font-weight:400">Write-Admin — also connect/disconnect devices, manage keys</label>
      </div>
    </div>

    <button type="submit">Connect</button>
  </form>
</body>
</html>`;
}

export function registerOAuthRoutes(
  app: express.Express,
  store: OAuthStore,
  config: AppConfig,
  logger: AppLogger,
): void {
  // OAuth 2.0 Authorization Server Metadata (RFC 8414). The issuer is derived
  // from the incoming request so it works on any bind address/port without
  // configuration.
  app.get("/.well-known/oauth-authorization-server", (req, res) => {
    const issuer = `${req.protocol}://${req.headers.host}`;
    res.json({
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      registration_endpoint: `${issuer}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
    });
  });

  // Ported from kubernetes-mcp-server's handleServerCard -- independently
  // confirmed as a required cross-server convention via osv-mcp-server's
  // registry.json (mcpServerCardUrl points here).
  app.get("/.well-known/mcp/server-card.json", (req, res) => {
    const issuer = `${req.protocol}://${req.headers.host}`;
    res.json({
      name: "tailscale-mcp-server",
      mcp_endpoint: `${issuer}/mcp`,
      login_url: `${issuer}/authorize`,
    });
  });

  // Dynamic Client Registration (RFC 7591). An MCP client registers itself
  // here before opening the authorize URL.
  app.post("/register", express.json(), (req, res) => {
    const redirectUris: string[] = Array.isArray(req.body?.redirect_uris)
      ? (req.body.redirect_uris as string[])
      : [];
    const client = store.registerClient(redirectUris);
    res.status(201).json({
      client_id: client.clientId,
      client_secret: client.clientSecret,
      redirect_uris: client.redirectUris,
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code"],
      response_types: ["code"],
    });
  });

  // Authorization endpoint -- GET renders the Tailscale credential form.
  app.get("/authorize", (req, res) => {
    const q = req.query as Record<string, string>;
    if (!q.client_id || !q.redirect_uri || !q.state) {
      res
        .status(400)
        .send("Missing required parameters: client_id, redirect_uri, state");
      return;
    }
    if (!store.getClient(q.client_id)) {
      res.status(400).send("Unknown client_id — please reconnect.");
      return;
    }
    res.type("html").send(
      authorizeHtml({
        clientId: q.client_id,
        redirectUri: q.redirect_uri,
        state: q.state,
        codeChallenge: q.code_challenge,
        codeChallengeMethod: q.code_challenge_method,
      }),
    );
  });

  // Authorization endpoint -- POST handles the credential form submission.
  app.post(
    "/authorize",
    express.urlencoded({ extended: false }),
    async (req, res) => {
      const b = (req.body ?? {}) as Record<string, string>;
      const { client_id, redirect_uri, state, tailnet, api_key, allowed_risk } =
        b;

      if (!client_id || !redirect_uri || !state || !tailnet || !api_key) {
        res.status(400).send("Missing required fields");
        return;
      }
      if (!store.getClient(client_id)) {
        res.status(400).send("Unknown client");
        return;
      }

      const requestedRisk: ToolRisk =
        allowed_risk === "write" || allowed_risk === "admin"
          ? allowed_risk
          : "read";
      // The server operator's own ceiling is never exceeded, no matter what
      // the caller selects in the form.
      const effectiveRisk = cappedRisk(
        requestedRisk,
        config.TAILSCALE_ALLOWED_TOOL_RISK,
      );

      const probe = new TailscaleApiClient(
        {
          ...config,
          TAILSCALE_API_KEY: api_key,
          TAILSCALE_TAILNET: tailnet,
          TAILSCALE_OAUTH_CLIENT_ID: undefined,
          TAILSCALE_OAUTH_CLIENT_SECRET: undefined,
        },
        logger,
      );
      const validation = await probe.getTailnetInfo();
      if (!validation.success) {
        res.type("html").send(
          authorizeHtml({
            clientId: client_id,
            redirectUri: redirect_uri,
            state,
            codeChallenge: b.code_challenge,
            codeChallengeMethod: b.code_challenge_method,
            error: `Could not verify credentials: ${validation.error ?? "unknown error"}`,
          }),
        );
        return;
      }

      const code = store.issueCode({
        tailnet,
        apiKey: api_key,
        allowedRisk: effectiveRisk,
        clientId: client_id,
        redirectUri: redirect_uri,
        codeChallenge: b.code_challenge,
        codeChallengeMethod: b.code_challenge_method,
      });

      const dest = new URL(redirect_uri);
      dest.searchParams.set("code", code);
      dest.searchParams.set("state", state);
      res.redirect(dest.toString());
    },
  );

  // Token endpoint -- exchanges the authorization code for an opaque access
  // token that maps to the stored Tailscale credential in CredentialStore.
  app.post(
    "/token",
    express.urlencoded({ extended: false }),
    express.json(),
    async (req, res) => {
      const b = (req.body ?? {}) as Record<string, string>;

      if (b.grant_type !== "authorization_code") {
        res.status(400).json({ error: "unsupported_grant_type" });
        return;
      }

      const entry = store.consumeCode(b.code, b.code_verifier);
      if (!entry) {
        res.status(400).json({
          error: "invalid_grant",
          error_description:
            "Authorization code expired, invalid, or PKCE verification failed",
        });
        return;
      }

      const accessToken = await store.issueToken({
        tailnet: entry.tailnet,
        apiKey: entry.apiKey,
        allowedRisk: entry.allowedRisk,
        clientId: entry.clientId,
      });

      res.json({ access_token: accessToken, token_type: "bearer", scope: "" });
    },
  );
}
