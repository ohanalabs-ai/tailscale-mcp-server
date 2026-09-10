import { describe, expect, test } from "bun:test";
import {
  CREDENTIAL_RECORD_VERSION,
  type CredentialRecord,
  isExpired,
  parseCredentialRecord,
  redactCredentialRecord,
  serializeCredentialRecord,
} from "../../credentials/record.js";

const record = (
  overrides: Partial<CredentialRecord> = {},
): CredentialRecord => ({
  version: CREDENTIAL_RECORD_VERSION,
  tailnet: "example.com",
  apiKey: "tskey-api-secret",
  allowedRisk: "read",
  expiresAt: 0,
  ...overrides,
});

describe("CredentialRecord", () => {
  test("serialize/parse round-trips", () => {
    const r = record();
    expect(parseCredentialRecord(serializeCredentialRecord(r))).toEqual(r);
  });

  test("isExpired: zero expiresAt never expires", () => {
    expect(isExpired(record({ expiresAt: 0 }), Date.now() + 1_000_000)).toBe(
      false,
    );
  });

  test("isExpired: non-zero expiresAt in the past is expired", () => {
    const now = 1_000_000;
    expect(isExpired(record({ expiresAt: now - 1 }), now)).toBe(true);
    expect(isExpired(record({ expiresAt: now }), now)).toBe(true);
    expect(isExpired(record({ expiresAt: now + 1 }), now)).toBe(false);
  });

  test("parseCredentialRecord fails closed on garbage JSON", () => {
    expect(parseCredentialRecord("not json")).toBeUndefined();
  });

  test("parseCredentialRecord fails closed on a non-object", () => {
    expect(parseCredentialRecord("42")).toBeUndefined();
    expect(parseCredentialRecord("null")).toBeUndefined();
  });

  test("parseCredentialRecord fails closed on a version mismatch", () => {
    expect(
      parseCredentialRecord(JSON.stringify({ ...record(), version: 2 })),
    ).toBeUndefined();
  });

  test("parseCredentialRecord fails closed on wrong field types", () => {
    expect(
      parseCredentialRecord(JSON.stringify({ ...record(), apiKey: 42 })),
    ).toBeUndefined();
    expect(
      parseCredentialRecord(
        JSON.stringify({ ...record(), allowedRisk: "superadmin" }),
      ),
    ).toBeUndefined();
  });

  test("redactCredentialRecord never includes apiKey", () => {
    const redacted = redactCredentialRecord(record({ apiKey: "top-secret" }));
    expect(JSON.stringify(redacted)).not.toContain("top-secret");
    expect(redacted).toEqual({
      tailnet: "example.com",
      allowedRisk: "read",
      expiresAt: 0,
    });
  });
});
