import test from "node:test";
import assert from "node:assert/strict";

import { evaluateCoreRequest } from "../../src/core/integration.js";
import type { Identity } from "../../src/identity/types.js";
import type { Authority } from "../../src/authority/types.js";
import type { AuthorizationRequest } from "../../src/authorization/types.js";
import type { GovernanceRule } from "../../src/governance/types.js";

const identity: Identity = {
  id: "identity-001",
  kind: "human",
  status: "active",
  provenance: "test",
  createdAt: "2026-01-01T00:00:00.000Z",
};

const authority: Authority = {
  id: "authority-001",
  holderIdentityId: "identity-001",
  trustCredentialId: "credential-001",
  scope: ["read:resource-001"],
  issuedAt: "2026-01-01T00:00:00.000Z",
  status: "active",
  issuer: "root-001",
  provenance: "test",
};

const request: AuthorizationRequest = {
  id: "request-001",
  subjectIdentityId: "identity-001",
  authorityId: "authority-001",
  action: "read",
  resource: "resource-001",
  requestedAt: "2026-01-02T00:00:00.000Z",
};

const allowRule: GovernanceRule = {
  id: "rule-allow-001",
  version: "1.0.0",
  name: "Allow read",
  status: "active",
  issuer: "governance-001",
  precedence: 10,
  effectiveFrom: "2026-01-01T00:00:00.000Z",
  appliesToActions: ["read"],
  prohibitedActions: [],
  requiredConditions: [],
  provenance: "test",
};

test("core integration allows governed in-scope request", () => {
  const result = evaluateCoreRequest(
    identity,
    authority,
    request,
    [allowRule],
  );

  assert.equal(result.governance.decision, "ALLOW");
  assert.equal(result.authorization?.decision, "ALLOW");
  assert.equal(result.finalDecision, "ALLOW");
});

test("governance prohibition denies before authorization", () => {
  const prohibited: GovernanceRule = {
    ...allowRule,
    id: "rule-deny-001",
    version: "2.0.0",
    precedence: 100,
    prohibitedActions: ["read"],
  };

  const result = evaluateCoreRequest(
    identity,
    authority,
    request,
    [allowRule, prohibited],
  );

  assert.equal(result.governance.decision, "DENY");
  assert.equal(result.authorization, null);
  assert.equal(result.finalDecision, "DENY");
  assert.equal(result.reason, "ACTION_PROHIBITED");
});

test("missing governance remains DEFER", () => {
  const result = evaluateCoreRequest(
    identity,
    authority,
    request,
    [],
  );

  assert.equal(result.governance.decision, "DEFER");
  assert.equal(result.authorization, null);
  assert.equal(result.finalDecision, "DEFER");
});

test("subject mismatch is denied", () => {
  const result = evaluateCoreRequest(
    identity,
    authority,
    {
      ...request,
      subjectIdentityId: "identity-attacker",
    },
    [allowRule],
  );

  assert.equal(result.governance.decision, "ALLOW");
  assert.equal(result.authorization?.decision, "DENY");
  assert.equal(result.finalDecision, "DENY");
  assert.equal(result.reason, "SUBJECT_IDENTITY_MISMATCH");
});

test("authority mismatch is denied", () => {
  const result = evaluateCoreRequest(
    identity,
    authority,
    {
      ...request,
      authorityId: "authority-attacker",
    },
    [allowRule],
  );

  assert.equal(result.authorization?.decision, "DENY");
  assert.equal(result.finalDecision, "DENY");
  assert.equal(result.reason, "AUTHORITY_ID_MISMATCH");
});

test("revoked identity cannot authorize", () => {
  const result = evaluateCoreRequest(
    {
      ...identity,
      status: "revoked",
    },
    authority,
    request,
    [allowRule],
  );

  assert.equal(result.authorization?.decision, "DENY");
  assert.equal(result.reason, "IDENTITY_NOT_USABLE");
});

test("expired authority cannot authorize", () => {
  const result = evaluateCoreRequest(
    identity,
    {
      ...authority,
      expiresAt: "2026-01-02T00:00:00.000Z",
    },
    request,
    [allowRule],
  );

  assert.equal(result.authorization?.decision, "DENY");
  assert.equal(result.reason, "AUTHORITY_NOT_USABLE");
});

test("request outside authority scope is denied", () => {
  const result = evaluateCoreRequest(
    identity,
    authority,
    {
      ...request,
      action: "write",
    },
    [{
      ...allowRule,
      appliesToActions: ["write"],
    }],
  );

  assert.equal(result.authorization?.decision, "DENY");
  assert.equal(result.finalDecision, "DENY");
  assert.equal(result.reason, "ACTION_OUTSIDE_SCOPE");
});
