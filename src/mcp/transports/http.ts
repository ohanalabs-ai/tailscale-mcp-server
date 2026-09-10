import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import type { Request } from "express";
import express from "express";
import { createMcpServer } from "../../app/create-server.js";
import type { AppConfig } from "../../config/env.js";
import { credentialConfigFromEnv } from "../../credentials/config.js";
import { createCredentialStore } from "../../credentials/factory.js";
import { MemoryCredentialStore } from "../../credentials/memoryStore.js";
import { registerOAuthRoutes } from "../../oauth/routes.js";
import { OAuthStore } from "../../oauth/store.js";
import type { AppLogger } from "../../observability/logger.js";
import {
  createHttpAuthMiddleware,
  type TailscaleRequestCredential,
} from "../../security/auth.js";
import { createRateLimitMiddleware } from "../../security/rate-limit.js";
import { TailscaleService } from "../../tailscale/service.js";

export async function startHttpTransport({
  config,
  logger,
}: {
  config: AppConfig;
  logger: AppLogger;
}): Promise<void> {
  const tailscale = await TailscaleService.create({ config, logger });

  const credentialConfig = credentialConfigFromEnv();
  const credentialStore =
    (await createCredentialStore(credentialConfig, logger)) ??
    new MemoryCredentialStore();
  const oauthStore = new OAuthStore(
    credentialStore,
    config.TAILSCALE_API_BASE_URL,
    credentialConfig.ttlMs,
  );

  const app = createMcpExpressApp();

  app.disable("x-powered-by");
  app.use(express.json({ limit: "1mb" }));
  app.use(createRateLimitMiddleware());

  app.get("/health", (_req, res) => {
    res.json({ status: "ok" });
  });

  // Public OAuth 2.1 login flow -- lets a customer authorize this MCP
  // session with their own Tailscale API key + tailnet instead of the
  // server operator's static MCP_HTTP_BEARER_TOKEN. See src/oauth/.
  registerOAuthRoutes(app, oauthStore, config, logger);

  app.use("/mcp", createHttpAuthMiddleware(config, oauthStore));

  app.post("/mcp", async (req, res) => {
    const credential = (
      req as Request & { tailscaleCredential?: TailscaleRequestCredential }
    ).tailscaleCredential;

    const effectiveConfig: AppConfig = credential
      ? {
          ...config,
          TAILSCALE_API_KEY: credential.apiKey,
          TAILSCALE_TAILNET: credential.tailnet,
          TAILSCALE_ALLOWED_TOOL_RISK: credential.allowedRisk,
          TAILSCALE_OAUTH_CLIENT_ID: undefined,
          TAILSCALE_OAUTH_CLIENT_SECRET: undefined,
        }
      : config;
    const effectiveTailscale = credential
      ? await TailscaleService.create({ config: effectiveConfig, logger })
      : tailscale;

    const server = await createMcpServer({
      config: effectiveConfig,
      logger,
      tailscale: effectiveTailscale,
    });
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
    });

    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (error) {
      logger.error("HTTP MCP request failed", error);
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: "2.0",
          error: { code: -32603, message: "Internal server error" },
          id: null,
        });
      }
    } finally {
      await transport.close();
      await server.close();
    }
  });

  app.get("/mcp", (_req, res) => {
    res.status(405).json({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Method not allowed" },
      id: null,
    });
  });

  app.delete("/mcp", (_req, res) => {
    res.status(405).json({
      jsonrpc: "2.0",
      error: { code: -32000, message: "Method not allowed" },
      id: null,
    });
  });

  await new Promise<void>((resolve, reject) => {
    const server = app.listen(
      config.MCP_HTTP_PORT,
      config.MCP_HTTP_BIND_HOST,
      () => {
        logger.info("HTTP transport listening", {
          host: config.MCP_HTTP_BIND_HOST,
          port: config.MCP_HTTP_PORT,
        });
        resolve();
      },
    );
    server.on("error", reject);
  });
}
