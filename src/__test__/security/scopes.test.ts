import { describe, expect, test } from "bun:test";
import {
  isToolAdvertised,
  requireRisk,
  TOOL_RISK,
} from "../../security/scopes.js";

describe("requireRisk", () => {
  test("allows equal or lower risk operations", () => {
    expect(() =>
      requireRisk({ TAILSCALE_ALLOWED_TOOL_RISK: "write" }, "read"),
    ).not.toThrow();
    expect(() =>
      requireRisk({ TAILSCALE_ALLOWED_TOOL_RISK: "write" }, "write"),
    ).not.toThrow();
  });

  test("rejects higher risk operations", () => {
    expect(() =>
      requireRisk({ TAILSCALE_ALLOWED_TOOL_RISK: "read" }, "write"),
    ).toThrow("Tool requires write risk level");
  });
});

describe("isToolAdvertised", () => {
  test("a read-floor tool is advertised at every risk level", () => {
    expect(isToolAdvertised("read", "list_devices")).toBe(true);
    expect(isToolAdvertised("write", "list_devices")).toBe(true);
    expect(isToolAdvertised("admin", "list_devices")).toBe(true);
  });

  test("a write-floor tool is hidden at read, visible at write/admin", () => {
    expect(isToolAdvertised("read", "device_action")).toBe(false);
    expect(isToolAdvertised("write", "device_action")).toBe(true);
    expect(isToolAdvertised("admin", "device_action")).toBe(true);
  });

  test("an admin-floor tool is only visible at admin", () => {
    expect(isToolAdvertised("read", "connect_network")).toBe(false);
    expect(isToolAdvertised("write", "connect_network")).toBe(false);
    expect(isToolAdvertised("admin", "connect_network")).toBe(true);
  });

  test("fails closed on an unknown tool name", () => {
    expect(isToolAdvertised("admin", "not_a_real_tool")).toBe(false);
  });

  test("every tool has a TOOL_RISK entry (fails loudly on a forgotten tool)", () => {
    const expectedNames = [
      "list_devices",
      "device_action",
      "manage_routes",
      "get_network_status",
      "connect_network",
      "disconnect_network",
      "ping_peer",
      "get_version",
      "get_tailnet_info",
      "manage_file_sharing",
      "manage_exit_nodes",
      "manage_webhooks",
      "manage_device_tags",
      "get_version_info",
      "manage_acl",
      "manage_dns",
      "manage_keys",
      "manage_policy_file",
      "manage_network_lock",
    ];
    expect(Object.keys(TOOL_RISK).sort()).toEqual(expectedNames.sort());
  });
});
