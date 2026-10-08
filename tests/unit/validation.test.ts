import test from "node:test";
import assert from "node:assert/strict";

import { validateIdentity } from "../../src/identity/service.js";
import { validateAuthority } from "../../src/authority/service.js";
import {
  evaluateGovernance,
  validateGovernanceRule,
} from "../../src/governance/service.js";

test("identity rejects invalid timestamp", () => {
  assert.throws(
    () =>
      validateIdentity({
        id: "identity-001",
        kind: "human",
        status: "active",
        provenance: "test",
        createdAt: "not-a-date",
      }),
    /Identity creation time must be a valid timestamp/,
  );
});

test("authority rejects empty trust credential", () => {
  assert.throws(
    () =>
      validateAuthority({
        id: "authority-validation",
        holderIdentityId: "identity-validation",
        trustCredentialId: "",
        scope: ["TEST:resource"],
        issuedAt: "2026-09-21T12:00:00.000Z",
        status: "active",
        issuer: "test-issuer",
        provenance: "test",
      }),
    /Authority trust credential is required/,
  );
});

test("authority rejects empty scope entry", () => {
  assert.throws(
    () =>
      validateAuthority({
        id: "authority-001",
        holderIdentityId: "identity-001",
        trustCredentialId: "credential-001",
        scope: ["read:resource", "   "],
        issuedAt: "2026-01-01T00:00:00.000Z",
        status: "active",
        issuer: "issuer-001",
        provenance: "test",
      }),
    /Authority scope entries cannot be empty/,
  );
});

test("authority rejects invalid expiry", () => {
  assert.throws(
    () =>
      validateAuthority({
        id: "authority-001",
        holderIdentityId: "identity-001",
        trustCredentialId: "credential-001",
        scope: ["read:resource"],
        issuedAt: "2026-01-02T00:00:00.000Z",
        expiresAt: "2026-01-01T00:00:00.000Z",
        status: "active",
        issuer: "issuer-001",
        provenance: "test",
      }),
    /Authority expiry must be after issuance/,
  );
});

test("governance rejects invalid effective window", () => {
  assert.throws(
    () =>
      validateGovernanceRule({
        id: "rule-001",
        version: "1.0.0",
        name: "Test",
        status: "active",
        issuer: "issuer-001",
        precedence: 1,
        effectiveFrom: "2026-01-02T00:00:00.000Z",
        effectiveUntil: "2026-01-01T00:00:00.000Z",
        appliesToActions: ["read"],
        prohibitedActions: [],
        requiredConditions: [],
        provenance: "test",
      }),
    /Governance effectiveUntil must be after effectiveFrom/,
  );
});

test("governance tie ordering is deterministic", () => {
  const base = {
    version: "1.0.0",
    name: "Test",
    status: "active" as const,
    issuer: "issuer-001",
    precedence: 10,
    effectiveFrom: "2026-01-01T00:00:00.000Z",
    appliesToActions: ["read"],
    prohibitedActions: [],
    requiredConditions: [],
    provenance: "test",
  };

  const result = evaluateGovernance(
    {
      id: "request-001",
      subject: "identity-001",
      action: "read",
      resource: "resource-001",
      requestedAt: "2026-01-02T00:00:00.000Z",
      satisfiedConditions: [],
    },
    [
      { ...base, id: "rule-b" },
      { ...base, id: "rule-a", version: "2.0.0" },
    ],
  );

  assert.equal(result.governanceVersion, "2.0.0");
  assert.deepEqual(result.ruleIds, ["rule-a", "rule-b"]);
});
