import { timingSafeEqual } from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import type { AppConfig } from "../config/env.js";
import type { AccessTokenData, OAuthStore } from "../oauth/store.js";

// Attached to the request when the caller authenticated via an
// OAuth-issued access token (src/oauth/) rather than the static
// MCP_HTTP_BEARER_TOKEN. The POST /mcp handler uses this to build a
// per-request effective config (the caller's own Tailscale credential and
// capped risk tier) instead of the server-wide static one.
export type TailscaleRequestCredential = AccessTokenData;

export function validateBearerToken(
  authorization: string | undefined,
  expectedToken: string,
): boolean {
  if (!authorization?.startsWith("Bearer ")) {
    return false;
  }

  const received = authorization.slice("Bearer ".length);
  const receivedBuffer = Buffer.from(received);
  const expectedBuffer = Buffer.from(expectedToken);

  return (
    receivedBuffer.length === expectedBuffer.length &&
    timingSafeEqual(receivedBuffer, expectedBuffer)
  );
}

export function isAllowedHost(
  hostHeader: string | undefined,
  extraHosts: string[] = [],
): boolean {
  if (!hostHeader) {
    return false;
  }

  const host = hostHeader.split(":")[0]?.toLowerCase();
  if (!host) {
    return false;
  }

  return (
    host === "localhost" ||
    host === "127.0.0.1" ||
    host === "::1" ||
    host.endsWith(".ts.net") ||
    extraHosts.map((allowed) => allowed.toLowerCase()).includes(host)
  );
}

// JSON-RPC methods a client may call WITHOUT authentication so registries,
// catalogs, and agents can discover the toolset. Tool execution ("tools/call")
// and everything else still require a valid bearer token.
const PUBLIC_MCP_METHODS = new Set([
  "initialize",
  "notifications/initialized",
  "tools/list",
  "prompts/list",
  "resources/list",
  "resources/templates/list",
  "ping",
]);

export function isPublicMcpRequest(
  req: Pick<Request, "method" | "body">,
): boolean {
  if (req.method !== "POST") {
    return false;
  }

  const method = (req.body as { method?: unknown } | undefined)?.method;
  return typeof method === "string" && PUBLIC_MCP_METHODS.has(method);
}

function bearerToken(authorization: string | undefined): string | undefined {
  if (!authorization?.startsWith("Bearer ")) {
    return undefined;
  }
  return authorization.slice("Bearer ".length);
}

// oauthStore is optional: when omitted (or when MCP_CREDENTIAL_STORE is
// unset), only the static MCP_HTTP_BEARER_TOKEN path is available, exactly
// as before this feature existed.
export function createHttpAuthMiddleware(
  config: AppConfig,
  oauthStore?: OAuthStore,
) {
  const extraHosts = config.MCP_ALLOWED_HOSTS?.split(",")
    .map((host) => host.trim())
    .filter(Boolean);

  return async (req: Request, res: Response, next: NextFunction) => {
    if (!isAllowedHost(req.headers.host, extraHosts)) {
      res.status(403).json({ error: "Forbidden host" });
      return;
    }

    if (isPublicMcpRequest(req)) {
      next();
      return;
    }

    if (
      config.MCP_HTTP_BEARER_TOKEN &&
      validateBearerToken(
        req.headers.authorization,
        config.MCP_HTTP_BEARER_TOKEN,
      )
    ) {
      next();
      return;
    }

    const token = bearerToken(req.headers.authorization);
    if (token && oauthStore) {
      const credential = await oauthStore.lookupToken(token);
      if (credential) {
        (
          req as Request & { tailscaleCredential?: TailscaleRequestCredential }
        ).tailscaleCredential = credential;
        next();
        return;
      }
    }

    res.status(401).json({
      error: "Unauthorized",
      loginUrl: `${req.protocol}://${req.headers.host}/authorize`,
    });
  };
}
