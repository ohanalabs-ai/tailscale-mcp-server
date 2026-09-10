import { isToolAdvertised } from "../../security/scopes.js";
import { registerAclTools } from "./acl.js";
import { registerAdminTools } from "./admin.js";
import { registerDeviceTools } from "./devices.js";
import { registerNetworkTools } from "./network.js";
import type { ServerWithTools, ToolContext } from "./types.js";

// Wraps `server` so that `registerTool` silently skips any tool whose floor
// risk exceeds `allowedRisk` — i.e. tools/list only advertises what the
// caller is actually allowed to invoke, instead of advertising everything and
// relying solely on requireRisk() to reject the call afterwards. Every other
// method (registerResource, registerPrompt, etc.) passes through unchanged
// via Reflect, so this works transparently against both the real McpServer
// and the CapturingServer test double.
function createRiskGatedServer(
  server: ServerWithTools,
  allowedRisk: ToolContext["config"]["TAILSCALE_ALLOWED_TOOL_RISK"],
): ServerWithTools {
  return new Proxy(server, {
    get(target, prop, receiver) {
      if (prop !== "registerTool") {
        return Reflect.get(target, prop, receiver);
      }
      return (
        name: string,
        def: unknown,
        handler: (...args: never[]) => unknown,
      ) => {
        if (!isToolAdvertised(allowedRisk, name)) {
          return undefined;
        }
        // biome-ignore lint/suspicious/noExplicitAny: forwarding a variadic call through Reflect requires a loosely-typed args tuple.
        return (target as any).registerTool(name, def, handler);
      };
    },
  });
}

export function registerTools(
  server: ServerWithTools,
  context: ToolContext,
): void {
  const gated = createRiskGatedServer(
    server,
    context.config.TAILSCALE_ALLOWED_TOOL_RISK,
  );
  registerDeviceTools(gated, context);
  registerNetworkTools(gated, context);
  registerAclTools(gated, context);
  registerAdminTools(gated, context);
}

export type { ToolContext };
