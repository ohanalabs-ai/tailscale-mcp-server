import { describe, expect, test } from "bun:test";
import {
  isAllowedHost,
  isPublicMcpRequest,
  validateBearerToken,
} from "../../security/auth.js";

describe("HTTP security", () => {
  test("validates bearer token exactly", () => {
    expect(validateBearerToken("Bearer abc123", "abc123")).toBe(true);
    expect(validateBearerToken("Bearer wrong", "abc123")).toBe(false);
    expect(validateBearerToken(undefined, "abc123")).toBe(false);
  });

  test("allows localhost and tailnet hosts only", () => {
    expect(isAllowedHost("localhost:3000")).toBe(true);
    expect(isAllowedHost("127.0.0.1:3000")).toBe(true);
    expect(isAllowedHost("mcp.tailnet-name.ts.net")).toBe(true);
    expect(isAllowedHost("evil.example.com")).toBe(false);
  });
});

describe("isPublicMcpRequest", () => {
  test.each([
    ["tools/list", true],
    ["initialize", true],
    ["notifications/initialized", true],
    ["prompts/list", true],
    ["resources/list", true],
    ["resources/templates/list", true],
    ["ping", true],
    ["tools/call", false],
    ["resources/read", false],
    ["", false],
  ] as const)("method %p -> %p", (method, expected) => {
    expect(isPublicMcpRequest({ method: "POST", body: { method } })).toBe(
      expected,
    );
  });

  test("non-POST requests are never public", () => {
    expect(
      isPublicMcpRequest({ method: "GET", body: { method: "tools/list" } }),
    ).toBe(false);
  });

  test("missing or malformed body is not public", () => {
    expect(isPublicMcpRequest({ method: "POST", body: undefined })).toBe(false);
    expect(isPublicMcpRequest({ method: "POST", body: {} })).toBe(false);
    expect(isPublicMcpRequest({ method: "POST", body: { method: 42 } })).toBe(
      false,
    );
  });
});
