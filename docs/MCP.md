# MCP transport, OAuth, and credential model

## Transport

Two transports, selected via `MCP_TRANSPORT`:

- `stdio` (default) — a single local caller, no auth concept needed. One
  `McpServer` instance for the process lifetime.
- `http` — `POST /mcp` (Streamable HTTP), a fresh `McpServer` +
  `StreamableHTTPServerTransport` per request. This is the transport the
  rest of this document describes.

## Endpoints

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /health` | none | Liveness check |
| `GET /.well-known/oauth-authorization-server` | none | RFC 8414 AS metadata |
| `GET /.well-known/mcp/server-card.json` | none | `{name, mcp_endpoint, login_url}` |
| `POST /register` | none | RFC 7591 Dynamic Client Registration |
| `GET /authorize` | none | Renders the credential form (PKCE required) |
| `POST /authorize` | none | Handles form submission, issues an auth code |
| `POST /token` | none | Exchanges a code (PKCE-verified) for an access token |
| `POST /mcp` | see below | JSON-RPC 2.0 (MCP) |

## Three accepted auth shapes

1. **Discovery, always unauthenticated.** `initialize`,
   `notifications/initialized`, `tools/list`, `prompts/list`,
   `resources/list`, `resources/templates/list`, and `ping` succeed with no
   `Authorization` header at all, on `POST /mcp`.
2. **Static bearer token** — the server operator's own `MCP_HTTP_BEARER_TOKEN`
   (constant-time compared). Unchanged from before the OAuth flow existed;
   uses the server-wide `TAILSCALE_ALLOWED_TOOL_RISK` directly.
3. **OAuth-issued access token** — from the login flow below. Resolves a
   per-caller Tailscale credential and risk tier from the credential store.

`tools/call` (and everything else on `POST /mcp`) requires one of shapes 2
or 3; anything else gets `401` with a `loginUrl` pointing at `/authorize`.

## Credential model (kubernetes-mcp-server pattern)

This server's OAuth implementation is a **direct TypeScript port of
`argocd-mcp-server`'s `src/server/oauth/{routes,store}.ts`** — plain random
opaque tokens (`randomBytes(32).toString('hex')`), not sealed/signed blobs
and not JWTs — following the credential-store abstraction and risk-profile
form pattern first established in `kubernetes-mcp-server` (Go): a login
form collects the credential, an authorization code is issued, and the
final access token maps to a stored record rather than encoding the
credential itself.

The login form (`GET /authorize`) collects:

- **Tailnet ID**
- **API Key**
- **Access level** — a radio choice of Read-Only / Read-Write / Write-Admin,
  mapped to `read`/`write`/`admin`. **The server operator's own
  `TAILSCALE_ALLOWED_TOOL_RISK` is a hard ceiling** — a caller's own
  selection is capped at, and can never exceed, that value.

Submitted credentials are validated against the real Tailscale API
(`GET /tailnet/{tailnet}`) before an authorization code is issued.

### Store backends

Selected via `MCP_CREDENTIAL_STORE` (`none` default / `memory` / `redis`),
see the README's Configuration table for the full env var list. Both
backends implement the same `CredentialStore` interface
(`src/credentials/store.ts`) — contract-identical, so switching backends
requires no code change. `none` and `memory` are single-process only;
`redis` shares issued credentials across replicas.

### Stateless tokens

Ephemeral OAuth bookkeeping — client registrations and 60-second
authorization codes — stays in an in-process `Map` (`src/oauth/store.ts`),
matching both reference implementations (neither persists that layer to
Redis either). Only the final issued access token's associated Tailscale
credential goes into the configured `CredentialStore`.

### Access-token TTL

Bounded by `MCP_CREDENTIAL_TTL_MS` (default 2h, 1m–7d bounds). There is no
refresh flow — a caller re-authenticates via `/authorize` once their token's
underlying record expires or is evicted.

## Security notes

- Discovery-without-auth is a deliberate, cross-server convention (also
  shipped in `kubernetes-mcp-server` and `vault-mcp-server`) — it lets
  registries/catalogs enumerate the toolset without a credential. Tool
  *execution* is never exempted.
- The `isAllowedHost` DNS-rebinding guard applies to every request,
  including discovery and the OAuth endpoints — this is orthogonal to the
  auth-token checks and has no bypass.
- `tools/list` respects the caller's own capped risk tier
  (`src/security/scopes.ts`'s `TOOL_RISK` table): an OAuth-authorized
  customer only ever sees the tools their chosen (and capped) access level
  permits.
