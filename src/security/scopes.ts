import type { ToolRisk } from "../config/env.js";
import { AppError } from "../observability/errors.js";

const rank: Record<ToolRisk, number> = {
  read: 0,
  write: 1,
  admin: 2,
};

export function requireRisk(
  config: { TAILSCALE_ALLOWED_TOOL_RISK: ToolRisk },
  required: ToolRisk,
): void {
  if (rank[config.TAILSCALE_ALLOWED_TOOL_RISK] < rank[required]) {
    throw new AppError(
      `Tool requires ${required} risk level`,
      "risk_level_denied",
      403,
      `Tool requires ${required} risk level`,
    );
  }
}

// The floor risk of each tool: the minimum TAILSCALE_ALLOWED_TOOL_RISK at
// which the tool becomes reachable at all (some tools require a higher risk
// only for certain input-dependent branches — this is the lowest one). Used
// to gate ADVERTISEMENT (tools/list) in addition to execution (requireRisk
// above, still called inside every handler as defense-in-depth).
export const TOOL_RISK: Record<string, ToolRisk> = {
  // devices.ts
  list_devices: "read",
  device_action: "write",
  manage_routes: "write",
  // network.ts
  get_network_status: "read",
  connect_network: "admin",
  disconnect_network: "admin",
  ping_peer: "read",
  get_version: "read",
  // admin.ts
  get_tailnet_info: "read",
  manage_file_sharing: "read",
  manage_exit_nodes: "read",
  manage_webhooks: "read",
  manage_device_tags: "read",
  get_version_info: "read",
  // acl.ts
  manage_acl: "read",
  manage_dns: "read",
  manage_keys: "read",
  manage_policy_file: "read",
  manage_network_lock: "read",
};

// Whether a tool should be advertised (appear in tools/list) at the given
// allowed risk level. Fails closed: a tool name absent from TOOL_RISK (e.g. a
// new tool that forgot to register its risk) is NOT advertised, rather than
// defaulting to visible.
export function isToolAdvertised(
  allowedRisk: ToolRisk,
  toolName: string,
): boolean {
  const floor = TOOL_RISK[toolName];
  if (floor === undefined) {
    return false;
  }
  return rank[allowedRisk] >= rank[floor];
}
