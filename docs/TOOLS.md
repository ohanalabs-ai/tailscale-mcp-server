# Tools & Prompts

## Tool catalog

Each tool's "floor risk" is the minimum `TAILSCALE_ALLOWED_TOOL_RISK` (or, for
an OAuth-authorized caller, their own risk selection capped at the server
operator's ceiling) at which it appears in `tools/list` at all — see
`src/security/scopes.ts`'s `TOOL_RISK` table. Individual operations within a
tool may still require a higher risk to *execute* (enforced by `requireRisk()`
in the handler); this table lists the floor, not every branch.

| Tool | Floor risk | Category |
|---|---|---|
| `list_devices` | `read` | Devices |
| `device_action` | `write` (delete/deauthorize require `admin`) | Devices |
| `manage_routes` | `write` | Devices |
| `get_network_status` | `read` | Network |
| `connect_network` | `admin` | Network |
| `disconnect_network` | `admin` | Network |
| `ping_peer` | `read` | Network |
| `get_version` | `read` | Network |
| `get_tailnet_info` | `read` | Administration |
| `manage_file_sharing` | `read` (enable/disable require `write`) | Administration |
| `manage_exit_nodes` | `read` (mutations require `admin`) | Administration |
| `manage_webhooks` | `read` (mutations require `write`) | Administration |
| `manage_device_tags` | `read` (mutations require `write`) | Administration |
| `get_version_info` | `read` | Administration |
| `manage_acl` | `read` (update/validate require `write`) | ACL and Policy |
| `manage_dns` | `read` (set operations require `write`) | ACL and Policy |
| `manage_keys` | `read` (create/delete require `admin`) | ACL and Policy |
| `manage_policy_file` | `read` (update requires `write`) | ACL and Policy |
| `manage_network_lock` | `read` (mutations require `admin`) | ACL and Policy |

19 tools total. At the default risk (`read`), 15 are advertised; at `write`,
17; at `admin`, all 19.

## Prompts

See the root [README.md](../README.md#resources-and-prompts) for the current
prompt catalog.

## Client configuration

### OAuth (recommended for customers)

Point your MCP client's OAuth discovery at this server's base URL — it
implements `/.well-known/oauth-authorization-server`, `/register`,
`/authorize`, and `/token`. See [MCP.md](MCP.md) for the full flow.

### Basic auth / static bearer token (server operator)

```
Authorization: Bearer <MCP_HTTP_BEARER_TOKEN>
```

## curl smoke tests

```bash
# Health (unauthenticated)
curl -s http://127.0.0.1:3000/health

# Discovery (unauthenticated) -- list tools
curl -s -X POST http://127.0.0.1:3000/mcp -H 'Content-Type: application/json' -H 'Host: localhost' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'

# tools/call with the static bearer token
curl -s -X POST http://127.0.0.1:3000/mcp -H 'Content-Type: application/json' -H 'Host: localhost' \
  -H "Authorization: Bearer $MCP_HTTP_BEARER_TOKEN" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_devices","arguments":{}}}'
```

See [MCP.md](MCP.md) for the full OAuth `/register` → `/authorize` →
`/token` curl sequence.
