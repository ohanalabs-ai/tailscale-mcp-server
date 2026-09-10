# HTTP API reference

All endpoints below are served by the `http` transport (`MCP_TRANSPORT=http`).
See [MCP.md](MCP.md) for the auth model these `Auth` columns reference.

## Health

| Method | Path | Auth | Response |
|---|---|---|---|
| `GET` | `/health` | none | `200 {"status": "ok"}` |

## OAuth 2.1 (customer login flow)

| Method | Path | Auth | Response |
|---|---|---|---|
| `GET` | `/.well-known/oauth-authorization-server` | none | RFC 8414 AS metadata JSON |
| `GET` | `/.well-known/mcp/server-card.json` | none | `{name, mcp_endpoint, login_url}` |
| `POST` | `/register` | none | `201` `{client_id, client_secret, redirect_uris, ...}` |
| `GET` | `/authorize?client_id&redirect_uri&state&code_challenge&code_challenge_method` | none | `200` HTML credential form, or `400` on missing/unknown params |
| `POST` | `/authorize` (form: `client_id`, `redirect_uri`, `state`, `tailnet`, `api_key`, `allowed_risk`, `code_challenge`, `code_challenge_method`) | none | `302` redirect to `redirect_uri?code=...&state=...` on success; `200` re-rendered form with an error on invalid credentials; `400` on missing/unknown client |
| `POST` | `/token` (form/JSON: `grant_type=authorization_code`, `code`, `code_verifier`) | none | `200 {access_token, token_type: "bearer", scope: ""}`, or `400 {error: "invalid_grant"}` |

`code_challenge`/`code_challenge_method=S256` (PKCE) are required at
`/authorize` if the client sent them; verified at `/token` via
`code_verifier`.

## MCP (JSON-RPC 2.0)

| Method | Path | Auth | Response |
|---|---|---|---|
| `POST` | `/mcp` | Discovery methods: none. `tools/call` and all others: `Authorization: Bearer <token>` (static `MCP_HTTP_BEARER_TOKEN` or an OAuth-issued access token) | `200` JSON-RPC response, or `401 {error, loginUrl}` |
| `GET` | `/mcp` | — | `405` |
| `DELETE` | `/mcp` | — | `405` |

Discovery methods reachable with no header on `POST /mcp`: `initialize`,
`notifications/initialized`, `tools/list`, `prompts/list`,
`resources/list`, `resources/templates/list`, `ping`.
