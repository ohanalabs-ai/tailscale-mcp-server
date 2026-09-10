/**
 * Tool registration tests — verifies the per-category tool names, and that
 * registerTools() advertises only the tools whose floor risk is at or below
 * TAILSCALE_ALLOWED_TOOL_RISK (15/17/19 tools at read/write/admin).
 *
 * Importers: none — new test file
 * Affected surface: new tests only
 * Data files: none
 * User instruction: "Execute all"
 */
import { describe, expect, test } from "bun:test";
import { registerAclTools } from "../../mcp/tools/acl.js";
import { registerAdminTools } from "../../mcp/tools/admin.js";
import { registerDeviceTools } from "../../mcp/tools/devices.js";
import { registerTools } from "../../mcp/tools/index.js";
import { registerNetworkTools } from "../../mcp/tools/network.js";
import {
  CapturingServer,
  makeConfig,
  makeFakeService,
  silentLogger,
} from "./helpers.js";

function makeContext(riskOverride?: "read" | "write" | "admin") {
  return {
    config: makeConfig(
      riskOverride ? { TAILSCALE_ALLOWED_TOOL_RISK: riskOverride } : {},
    ),
    logger: silentLogger,
    tailscale: makeFakeService(),
  };
}

const DEVICE_TOOL_NAMES = ["list_devices", "device_action", "manage_routes"];

const NETWORK_TOOL_NAMES = [
  "get_network_status",
  "connect_network",
  "disconnect_network",
  "ping_peer",
  "get_version",
];

const ADMIN_TOOL_NAMES = [
  "get_tailnet_info",
  "manage_file_sharing",
  "manage_exit_nodes",
  "manage_webhooks",
  "manage_device_tags",
  "get_version_info",
];

const ACL_TOOL_NAMES = [
  "manage_acl",
  "manage_dns",
  "manage_keys",
  "manage_policy_file",
  "manage_network_lock",
];

const ALL_TOOL_NAMES = [
  ...DEVICE_TOOL_NAMES,
  ...NETWORK_TOOL_NAMES,
  ...ADMIN_TOOL_NAMES,
  ...ACL_TOOL_NAMES,
];

describe("Tool registration", () => {
  test("registerDeviceTools registers expected tool names", () => {
    const server = new CapturingServer();
    registerDeviceTools(server as never, makeContext());
    expect(server.toolNames).toEqual(DEVICE_TOOL_NAMES);
  });

  test("registerNetworkTools registers expected tool names", () => {
    const server = new CapturingServer();
    registerNetworkTools(server as never, makeContext());
    expect(server.toolNames).toEqual(NETWORK_TOOL_NAMES);
  });

  test("registerAdminTools registers expected tool names", () => {
    const server = new CapturingServer();
    registerAdminTools(server as never, makeContext());
    expect(server.toolNames).toEqual(ADMIN_TOOL_NAMES);
  });

  test("registerAclTools registers expected tool names", () => {
    const server = new CapturingServer();
    registerAclTools(server as never, makeContext());
    expect(server.toolNames).toEqual(ACL_TOOL_NAMES);
  });

  test("registerTools registers all 19 tools at admin risk", () => {
    const server = new CapturingServer();
    registerTools(server as never, makeContext("admin"));
    expect(server.toolNames).toHaveLength(ALL_TOOL_NAMES.length);
    for (const name of ALL_TOOL_NAMES) {
      expect(server.toolNames).toContain(name);
    }
  });
});

describe("Risk-gated advertisement (tools/list)", () => {
  const READ_ONLY_NAMES = [
    "list_devices",
    "get_network_status",
    "ping_peer",
    "get_version",
    "manage_acl",
    "manage_dns",
    "manage_keys",
    "manage_policy_file",
    "manage_network_lock",
    "get_tailnet_info",
    "manage_file_sharing",
    "manage_exit_nodes",
    "manage_webhooks",
    "manage_device_tags",
    "get_version_info",
  ];
  const WRITE_ADDITIONAL_NAMES = ["device_action", "manage_routes"];
  const ADMIN_ADDITIONAL_NAMES = ["connect_network", "disconnect_network"];

  test("default risk (read) advertises only the 15 read-floor tools", () => {
    const server = new CapturingServer();
    registerTools(server as never, makeContext());
    expect(server.toolNames).toHaveLength(READ_ONLY_NAMES.length);
    for (const name of READ_ONLY_NAMES) {
      expect(server.toolNames).toContain(name);
    }
  });

  test("write risk advertises read + write-floor tools (17)", () => {
    const server = new CapturingServer();
    registerTools(server as never, makeContext("write"));
    const expected = [...READ_ONLY_NAMES, ...WRITE_ADDITIONAL_NAMES];
    expect(server.toolNames).toHaveLength(expected.length);
    for (const name of expected) {
      expect(server.toolNames).toContain(name);
    }
  });

  test("admin risk advertises all 19 tools", () => {
    const server = new CapturingServer();
    registerTools(server as never, makeContext("admin"));
    const expected = [
      ...READ_ONLY_NAMES,
      ...WRITE_ADDITIONAL_NAMES,
      ...ADMIN_ADDITIONAL_NAMES,
    ];
    expect(server.toolNames).toHaveLength(expected.length);
    for (const name of expected) {
      expect(server.toolNames).toContain(name);
    }
  });
});
