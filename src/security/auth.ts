import { timingSafeEqual } from "node:crypto";
import type { NextFunction, Request, Response } from "express";
import type { AppConfig } from "../config/env.js";

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

export function createHttpAuthMiddleware(config: AppConfig) {
  const extraHosts = config.MCP_ALLOWED_HOSTS?.split(",")
    .map((host) => host.trim())
    .filter(Boolean);

  return (req: Request, res: Response, next: NextFunction) => {
    if (!isAllowedHost(req.headers.host, extraHosts)) {
      res.status(403).json({ error: "Forbidden host" });
      return;
    }

    if (isPublicMcpRequest(req)) {
      next();
      return;
    }

    if (
      !config.MCP_HTTP_BEARER_TOKEN ||
      !validateBearerToken(
        req.headers.authorization,
        config.MCP_HTTP_BEARER_TOKEN,
      )
    ) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    next();
  };
}
