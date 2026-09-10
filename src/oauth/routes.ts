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

// Visual language shared with kubernetes-mcp-server's bootstrap login page
// (pkg/bootstrap/server.go's kubeLoginTemplate) -- centered card on a
// light-gray page, boxed grouping, consistent error/hint color language --
// refined further (info callout, selectable option cards, footer trust
// note) for a genuinely pleasant first-run experience, not just a re-skin.
function authorizeHtml(p: {
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  error?: string;
}): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Tailscale MCP Server — Connect</title>
  <style>
    :root { color-scheme: light; }
    * { box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, Roboto, sans-serif;
      background: linear-gradient(180deg, #f7f8fb 0%, #eef1f6 100%);
      margin: 0; padding: 24px 16px; color: #1a1d24;
    }
    .card {
      max-width: 460px; margin: 4vh auto; background: #fff;
      padding: 32px; border-radius: 16px;
      border: 1px solid #e7e9ee;
      box-shadow: 0 1px 2px rgba(16,24,40,0.04), 0 8px 24px rgba(16,24,40,0.08);
    }
    .brand { display: flex; align-items: center; gap: 10px; margin-bottom: 20px; }
    .brand .logo {
      width: 36px; height: 36px; border-radius: 10px; flex-shrink: 0;
      background: #101828; color: #fff; display: flex; align-items: center;
      justify-content: center; font-size: 18px;
    }
    .brand .name { font-size: 13px; font-weight: 600; color: #667085; letter-spacing: .01em; }
    h1 { margin: 0 0 6px; font-size: 21px; font-weight: 650; letter-spacing: -0.01em; }
    p.lede { margin: 0 0 20px; color: #5b6472; font-size: 14.5px; line-height: 1.5; }
    .info {
      background: #eff6ff; border: 1px solid #dbeafe; color: #1e429f;
      padding: 12px 14px; border-radius: 10px; font-size: 13px; line-height: 1.5;
      margin-bottom: 20px;
    }
    .err {
      background: #fef2f2; border: 1px solid #fecaca; color: #991b1b;
      padding: 12px 14px; border-radius: 10px; font-size: 13px; line-height: 1.5;
      margin-bottom: 16px; white-space: pre-wrap;
    }
    label.field-label { display: block; font-weight: 600; font-size: 13px; margin: 18px 0 6px; color: #344054; }
    label.field-label:first-of-type { margin-top: 0; }
    input[type="text"], input[type="password"] {
      width: 100%; padding: 11px 13px; border: 1.5px solid #d7dbe3; border-radius: 9px;
      font-size: 14.5px; font-family: inherit; background: #fff; color: #101828;
      transition: border-color .15s, box-shadow .15s;
    }
    input[type="text"]:focus, input[type="password"]:focus {
      outline: none; border-color: #2970ff; box-shadow: 0 0 0 3px rgba(41,112,255,0.15);
    }
    .hint { color: #7c8393; font-size: 12.5px; margin: 6px 0 0; line-height: 1.4; }
    .hint a { color: #2970ff; text-decoration: none; font-weight: 500; }
    .hint a:hover { text-decoration: underline; }
    fieldset { border: none; margin: 20px 0 0; padding: 0; }
    fieldset > label.field-label { margin: 0 0 8px; }
    .options { display: flex; flex-direction: column; gap: 8px; }
    .option {
      display: flex; align-items: flex-start; gap: 10px; padding: 12px 14px;
      border: 1.5px solid #e4e7ec; border-radius: 10px; cursor: pointer;
      transition: border-color .15s, background .15s;
    }
    .option:hover { border-color: #b6c6ff; }
    .option:has(input:checked) { border-color: #2970ff; background: #f5f8ff; }
    .option input[type="radio"] { margin: 3px 0 0; accent-color: #2970ff; flex-shrink: 0; }
    .option .option-text { font-size: 13.5px; line-height: 1.4; }
    .option .option-title { font-weight: 600; color: #1a1d24; display: block; }
    .option .option-desc { color: #7c8393; }
    button {
      width: 100%; margin-top: 24px; padding: 12px 14px; border: 0; border-radius: 10px;
      background: #101828; color: #fff; font-weight: 600; font-size: 14.5px;
      cursor: pointer; transition: background .15s, transform .05s;
    }
    button:hover { background: #1d2939; }
    button:active { transform: scale(0.99); }
    .footer-note {
      display: flex; align-items: flex-start; gap: 8px; margin-top: 20px;
      color: #7c8393; font-size: 12px; line-height: 1.5;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="brand">
      <div class="logo">🔒</div>
      <div class="name">TAILSCALE MCP SERVER</div>
    </div>
    <h1>Connect your tailnet</h1>
    <p class="lede">Authorize this MCP client with your own Tailscale credentials — nothing here is shared with the server operator or other users.</p>
    <div class="info">
      This grants the connecting client access to <strong>one specific tailnet</strong>, at the access level you choose below. You can revoke it anytime by rotating the API key in the Tailscale console.
    </div>
    ${p.error ? `<div class="err">${esc(p.error)}</div>` : ""}
    <form method="post" action="/authorize">
      <input type="hidden" name="client_id"             value="${esc(p.clientId)}">
      <input type="hidden" name="redirect_uri"          value="${esc(p.redirectUri)}">
      <input type="hidden" name="state"                 value="${esc(p.state)}">
      ${p.codeChallenge ? `<input type="hidden" name="code_challenge" value="${esc(p.codeChallenge)}">` : ""}
      ${p.codeChallengeMethod ? `<input type="hidden" name="code_challenge_method" value="${esc(p.codeChallengeMethod)}">` : ""}

      <label class="field-label" for="tailnet">Tailnet ID</label>
      <input id="tailnet" name="tailnet" type="text"
             placeholder="example.com" required autocomplete="off">
      <p class="hint">
        Find it at <a href="https://console.tailscale.com/admin/settings/general" target="_blank" rel="noopener">console.tailscale.com/admin/settings/general</a>.
      </p>

      <label class="field-label" for="api_key">API Key</label>
      <input id="api_key" name="api_key" type="password"
             placeholder="tskey-api-..." required autocomplete="off">
      <p class="hint">
        Generate one at <a href="https://console.tailscale.com/admin/settings/keys" target="_blank" rel="noopener">console.tailscale.com/admin/settings/keys</a> under "API access tokens".
      </p>

      <fieldset>
        <label class="field-label">Access level</label>
        <div class="options">
          <label class="option">
            <input type="radio" name="allowed_risk" value="read" checked>
            <span class="option-text">
              <span class="option-title">Read-Only</span>
              <span class="option-desc">View devices, tailnet info, DNS and ACL settings.</span>
            </span>
          </label>
          <label class="option">
            <input type="radio" name="allowed_risk" value="write">
            <span class="option-text">
              <span class="option-title">Read-Write</span>
              <span class="option-desc">Everything above, plus routes, tags, DNS and ACL changes.</span>
            </span>
          </label>
          <label class="option">
            <input type="radio" name="allowed_risk" value="admin">
            <span class="option-text">
              <span class="option-title">Write-Admin</span>
              <span class="option-desc">Everything above, plus connect/disconnect devices and key management.</span>
            </span>
          </label>
        </div>
      </fieldset>

      <button type="submit">Connect Tailscale</button>
    </form>
    <div class="footer-note">
      <span>🔒</span>
      <span>Your API key is validated directly against the Tailscale API and stored only for this session's authorized access — it is never logged or shown to anyone else.</span>
    </div>
  </div>
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
