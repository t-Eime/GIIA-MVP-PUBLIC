import { test } from "node:test";
import assert from "node:assert/strict";

import {
  generateEd25519KeyPair,
  signCanonical,
} from "../../src/trust/crypto.js";

import {
  evaluateConstitution,
  isConstitutionalRuleAuthorized,
  isConstitutionalRuleVerified,
  resolveConstitutionalConflict,
} from "../../src/constitution/service.js";

import {
  signConstitutionalRule,
} from "../../src/constitution/crypto.js";

import {
  ConstitutionalRegistry,
} from "../../src/constitution/registry.js";

import type {
  ConstitutionalRequest,
  ConstitutionalRule,
} from "../../src/constitution/types.js";

const NOW = "2026-01-01T00:00:00.000Z";

function makeRule(
  overrides: Partial<ConstitutionalRule> = {},
): ConstitutionalRule {
  const base: Omit<ConstitutionalRule, "signature"> = {
    id: "rule-1",
    version: "1.0.0",
    name: "Base rule",
    scope: "global",
    issuer: "constitutional-authority",
    precedence: 100,
    effectiveFrom: NOW,
    appliesToActions: ["read"],
    prohibitedActions: [],
    requiredConditions: [],
    immutablePrinciples: [
      "HUMAN_SAFETY_FIRST",
      "EVIDENCE_BEFORE_ACTION",
      "HUMAN_ACCOUNTABILITY",
    ],
    provenance: "test",
    status: "active",
    ...overrides,
  };

  const pair = generateEd25519KeyPair();

  return {
    ...base,
    signature: signConstitutionalRule(
      base,
      pair.privateKeyPem,
    ),
  };
}

function verified(...rules: ConstitutionalRule[]): Set<string> {
  return new Set(rules.map((rule) => rule.id));
}

function request(
  overrides: Partial<ConstitutionalRequest> = {},
): ConstitutionalRequest {
  return {
    id: "request-1",
    subject: "subject-1",
    action: "read",
    resource: "resource-1",
    requestedAt: NOW,
    satisfiedConditions: [],
    ...overrides,
  };
}

test("global constitutional rule allows compliant request", () => {
  const rule = makeRule();

  const result = evaluateConstitution(
    request(),
    [rule],
    verified(rule),
  );

  assert.equal(result.decision, "ALLOW");
  assert.equal(
    result.reason,
    "CONSTITUTIONALLY_ALLOWED",
  );
});

test("no applicable constitution produces DEFER", () => {
  const rule = makeRule({
    appliesToActions: ["write"],
  });

  const result = evaluateConstitution(
    request(),
    [rule],
    verified(rule),
  );

  assert.equal(result.decision, "DEFER");
  assert.equal(
    result.reason,
    "NO_VERIFIED_APPLICABLE_CONSTITUTION",
  );
});

test("prohibited action produces DENY", () => {
  const rule = makeRule({
    prohibitedActions: ["read"],
  });

  const result = evaluateConstitution(
    request(),
    [rule],
    verified(rule),
  );

  assert.equal(result.decision, "DENY");
  assert.equal(
    result.reason,
    "CONSTITUTIONALLY_PROHIBITED",
  );
});

test("missing constitutional condition produces DEFER", () => {
  const rule = makeRule({
    requiredConditions: ["human_verification"],
  });

  const result = evaluateConstitution(
    request(),
    [rule],
    verified(rule),
  );

  assert.equal(result.decision, "DEFER");
  assert.equal(
    result.reason,
    "CONSTITUTIONAL_CONDITION_UNSATISFIED",
  );
});

test("satisfied constitutional condition allows", () => {
  const rule = makeRule({
    requiredConditions: ["human_verification"],
  });

  const result = evaluateConstitution(
    request({
      satisfiedConditions: ["human_verification"],
    }),
    [rule],
    verified(rule),
  );

  assert.equal(result.decision, "ALLOW");
});

test("jurisdictional rule applies only to matching jurisdiction", () => {
  const rule = makeRule({
    id: "jurisdiction-rule",
    scope: "jurisdiction",
    jurisdiction: "JUR-A",
    prohibitedActions: ["read"],
  });

  const matching = evaluateConstitution(
    request({ jurisdiction: "JUR-A" }),
    [rule],
    verified(rule),
  );

  const nonMatching = evaluateConstitution(
    request({ jurisdiction: "JUR-B" }),
    [rule],
    verified(rule),
  );

  assert.equal(matching.decision, "DENY");
  assert.equal(nonMatching.decision, "DEFER");
});

test("global core remains jurisdiction-neutral", () => {
  const rule = makeRule();

  const resultA = evaluateConstitution(
    request({ jurisdiction: "COUNTRY-A" }),
    [rule],
    verified(rule),
  );

  const resultB = evaluateConstitution(
    request({ jurisdiction: "COUNTRY-B" }),
    [rule],
    verified(rule),
  );

  assert.equal(resultA.decision, "ALLOW");
  assert.equal(resultB.decision, "ALLOW");
});

test("higher precedence rule wins deterministically", () => {
  const low = makeRule({
    id: "low",
    precedence: 10,
    prohibitedActions: [],
  });

  const high = makeRule({
    id: "high",
    precedence: 20,
    prohibitedActions: ["read"],
  });

  const result = evaluateConstitution(
    request(),
    [low, high],
    verified(low, high),
  );

  assert.equal(result.decision, "DENY");
  assert.deepEqual(result.ruleIds, ["high"]);
});

test("specific jurisdiction rule outranks equal-precedence global rule", () => {
  const global = makeRule({
    id: "global",
    precedence: 50,
    prohibitedActions: [],
  });

  const jurisdiction = makeRule({
    id: "jurisdiction",
    scope: "jurisdiction",
    jurisdiction: "JUR-A",
    precedence: 50,
    prohibitedActions: ["read"],
  });

  const result = evaluateConstitution(
    request({ jurisdiction: "JUR-A" }),
    [global, jurisdiction],
    verified(global, jurisdiction),
  );

  assert.equal(result.decision, "DENY");
  assert.deepEqual(result.ruleIds, ["jurisdiction"]);
});

test("equal precedence and specificity conflict produces DEFER", () => {
  const allow = makeRule({
    id: "allow-rule",
    precedence: 50,
    prohibitedActions: [],
  });

  const deny = makeRule({
    id: "deny-rule",
    precedence: 50,
    prohibitedActions: ["read"],
  });

  const conflict = resolveConstitutionalConflict(
    [allow, deny],
    "read",
  );

  assert.notEqual(conflict, null);

  const result = evaluateConstitution(
    request(),
    [allow, deny],
    verified(allow, deny),
  );

  assert.equal(result.decision, "DEFER");
  assert.equal(
    result.reason,
    "CONSTITUTIONAL_POLICY_CONFLICT",
  );
});

test("expired rule is not applicable", () => {
  const rule = makeRule({
    effectiveFrom: "2025-01-01T00:00:00.000Z",
    effectiveUntil: "2025-12-31T00:00:00.000Z",
  });

  const result = evaluateConstitution(
    request(),
    [rule],
    verified(rule),
  );

  assert.equal(result.decision, "DEFER");
});

test("revoked rule is not applicable", () => {
  const rule = makeRule({
    status: "revoked",
  });

  const result = evaluateConstitution(
    request(),
    [rule],
    verified(rule),
  );

  assert.equal(result.decision, "DEFER");
});

test("unknown rule status is rejected", () => {
  const rule = makeRule({
    status: "unknown",
  });

  assert.throws(
    () => evaluateConstitution(request(), [rule]),
    (error: unknown) =>
      error instanceof Error &&
      "code" in error &&
      (error as { code?: unknown }).code ===
        "CONSTITUTION_RULE_STATUS_UNKNOWN",
  );
});

test("forged constitutional signature is rejected", () => {
  const pair = generateEd25519KeyPair();

  const base: Omit<ConstitutionalRule, "signature"> = {
    id: "signed-rule",
    version: "1.0.0",
    name: "Signed rule",
    scope: "global",
    issuer: "issuer",
    precedence: 10,
    effectiveFrom: NOW,
    appliesToActions: ["read"],
    prohibitedActions: [],
    requiredConditions: [],
    immutablePrinciples: [],
    provenance: "test",
    status: "active",
  };

  const signed: ConstitutionalRule = {
    ...base,
    signature: signConstitutionalRule(
      base,
      pair.privateKeyPem,
    ),
  };

  const forged = {
    ...signed,
    name: "ATTACKER-MODIFIED",
  };

  assert.equal(
    isConstitutionalRuleVerified(
      forged,
      pair.publicKeyPem,
    ),
    false,
  );
});

test("verified-rule allowlist can fail closed", () => {
  const rule = makeRule();

  const result = evaluateConstitution(
    request(),
    [rule],
    new Set(["different-rule"]),
  );

  assert.equal(result.decision, "DEFER");
  assert.equal(
    result.reason,
    "NO_VERIFIED_APPLICABLE_CONSTITUTION",
  );
});

test("constitutional registry persists rules and revocations", () => {
  const registry = new ConstitutionalRegistry();
  const rule = makeRule();

  registry.putRule(rule);

  assert.deepEqual(
    registry.getRule(rule.id),
    rule,
  );

  assert.equal(registry.listRules().length, 1);

  registry.revoke({
    ruleId: rule.id,
    revokedAt: NOW,
    reason: "test revocation",
    authority: "authority-1",
    provenance: "test",
  });

  assert.equal(
    registry.isRevoked(rule.id),
    true,
  );

  registry.close();
});

test("constitutional replay protection is one-time", () => {
  const registry = new ConstitutionalRegistry();

  assert.equal(
    registry.consumeReplay("request-1", NOW),
    true,
  );

  assert.equal(
    registry.consumeReplay(
      "request-1",
      "2026-01-01T00:00:01.000Z",
    ),
    false,
  );

  registry.close();
});

test("unverified constitutional rule injection fails closed", () => {
  const trusted = makeRule({
    id: "trusted-rule",
    prohibitedActions: [],
  });

  const injected = makeRule({
    id: "injected-rule",
    prohibitedActions: ["read"],
  });

  const result = evaluateConstitution(
    request(),
    [trusted, injected],
    verified(trusted),
  );

  assert.equal(result.decision, "ALLOW");
  assert.deepEqual(result.ruleIds, ["trusted-rule"]);
});

test("revoked constitutional rule cannot authorize", () => {
  const rule = makeRule({
    id: "revoked-rule",
    status: "revoked",
  });

  const result = evaluateConstitution(
    request(),
    [rule],
    verified(rule),
  );

  assert.equal(result.decision, "DEFER");
  assert.equal(result.ruleIds.length, 0);
});

test("issuer substitution invalidates constitutional signature", () => {
  const pair = generateEd25519KeyPair();

  const base: Omit<ConstitutionalRule, "signature"> = {
    id: "issuer-bound-rule",
    version: "1.0.0",
    name: "Issuer-bound rule",
    scope: "global",
    issuer: "issuer-A",
    precedence: 10,
    effectiveFrom: NOW,
    appliesToActions: ["read"],
    prohibitedActions: [],
    requiredConditions: [],
    immutablePrinciples: [],
    provenance: "test",
    status: "active",
  };

  const signed: ConstitutionalRule = {
    ...base,
    signature: signConstitutionalRule(
      base,
      pair.privateKeyPem,
    ),
  };

  const substituted = {
    ...signed,
    issuer: "attacker-issuer",
  };

  assert.equal(
    isConstitutionalRuleVerified(
      substituted,
      pair.publicKeyPem,
    ),
    false,
  );
});

test("global immutable principles cannot be overridden by jurisdictional rule", () => {
  const global = makeRule({
    id: "global-safety",
    scope: "global",
    precedence: 50,
    immutablePrinciples: ["HUMAN_SAFETY_FIRST"],
    prohibitedActions: [],
  });

  const jurisdiction = makeRule({
    id: "jurisdiction-override",
    scope: "jurisdiction",
    jurisdiction: "JUR-A",
    precedence: 100,
    immutablePrinciples: [],
    prohibitedActions: [],
  });

  const result = evaluateConstitution(
    request({ jurisdiction: "JUR-A" }),
    [global, jurisdiction],
    verified(global, jurisdiction),
  );

  assert.equal(result.decision, "DEFER");
  assert.equal(result.reason, "GLOBAL_IMMUTABLE_PRINCIPLE_CONFLICT");
});

test("constitutional conflict is action-specific", () => {
  const allow = makeRule({
    id: "allow-read",
    appliesToActions: ["read"],
    prohibitedActions: [],
  });

  const denyRead = makeRule({
    id: "deny-read",
    appliesToActions: ["read"],
    prohibitedActions: ["read"],
  });

  const denyWrite = makeRule({
    id: "deny-write",
    appliesToActions: ["write"],
    prohibitedActions: ["write"],
  });

  const readConflict = resolveConstitutionalConflict(
    [allow, denyRead],
    "read",
  );

  assert.notEqual(readConflict, null);

  const writeConflict = resolveConstitutionalConflict(
    [allow, denyRead],
    "write",
  );

  assert.equal(writeConflict, null);

  const unrelatedConflict = resolveConstitutionalConflict(
    [allow, denyWrite],
    "read",
  );

  assert.equal(unrelatedConflict, null);
});

test("ambiguous active constitutional rules fail closed", () => {
  const ruleA = makeRule({
    id: "ambiguous-a",
    version: "1.0.0",
    precedence: 50,
    prohibitedActions: [],
  });

  const ruleB = makeRule({
    id: "ambiguous-b",
    version: "1.0.0",
    precedence: 50,
    prohibitedActions: ["read"],
  });

  const result = evaluateConstitution(
    request(),
    [ruleA, ruleB],
    verified(ruleA, ruleB),
  );

  assert.equal(result.decision, "DEFER");
  assert.equal(result.reason, "CONSTITUTIONAL_POLICY_CONFLICT");
});

test("missing verification evidence fails closed even for otherwise valid rules", () => {
  const rule = makeRule({
    id: "unverified-valid-rule",
    prohibitedActions: [],
  });

  const result = evaluateConstitution(
    request(),
    [rule],
  );

  assert.equal(result.decision, "DEFER");
  assert.equal(
    result.reason,
    "NO_VERIFIED_CONSTITUTIONAL_RULES",
  );
});

test("registry retrieval exposes persisted revocation as revoked status", () => {
  const registry = new ConstitutionalRegistry();
  const rule = makeRule({
    id: "persisted-revoked-rule",
    status: "active",
  });

  registry.putRule(rule);

  registry.revoke({
    ruleId: rule.id,
    revokedAt: NOW,
    reason: "security revocation",
    authority: "authority-1",
    provenance: "test",
  });

  const retrieved = registry.getRule(rule.id);

  assert.ok(retrieved);
  assert.equal(retrieved.status, "revoked");
  assert.equal(registry.isRevoked(rule.id), true);

  registry.close();
});

test("registry listRules enforces persisted revocation before constitutional evaluation", () => {
  const registry = new ConstitutionalRegistry();
  const rule = makeRule({
    id: "enforced-revoked-rule",
    status: "active",
  });

  registry.putRule(rule);

  registry.revoke({
    ruleId: rule.id,
    revokedAt: NOW,
    reason: "security revocation",
    authority: "authority-1",
    provenance: "test",
  });

  const loadedRules = registry.listRules();

  assert.equal(loadedRules.length, 1);
  assert.equal(loadedRules[0]!.status, "revoked");

  const result = evaluateConstitution(
    request(),
    loadedRules,
    verified(...loadedRules),
  );

  assert.equal(result.decision, "DEFER");
  assert.equal(
    result.reason,
    "NO_VERIFIED_APPLICABLE_CONSTITUTION",
  );

  registry.close();
});

test("registry revocation remains enforced after reopening durable database", () => {
  const dbPath = ".test-constitutional-revocation.sqlite";

  {
    const registry = new ConstitutionalRegistry(dbPath);
    const rule = makeRule({
      id: "durable-revoked-rule",
      status: "active",
    });

    registry.putRule(rule);

    registry.revoke({
      ruleId: rule.id,
      revokedAt: NOW,
      reason: "durable security revocation",
      authority: "authority-1",
      provenance: "test",
    });

    registry.close();
  }

  {
    const registry = new ConstitutionalRegistry(dbPath);
    const retrieved = registry.getRule("durable-revoked-rule");

    assert.ok(retrieved);
    assert.equal(retrieved.status, "revoked");

    const result = evaluateConstitution(
      request(),
      [retrieved],
      verified(retrieved),
    );

    assert.equal(result.decision, "DEFER");
    assert.equal(
      result.reason,
      "NO_VERIFIED_APPLICABLE_CONSTITUTION",
    );

    registry.close();
  }
});

test("constitutional authority requires a valid GIIA trust chain", () => {
  const root = generateEd25519KeyPair();
  const anchor = generateEd25519KeyPair();
  const delegation = generateEd25519KeyPair();

  const ruleBase: Omit<ConstitutionalRule, "signature"> = {
    id: "trusted-constitutional-rule",
    version: "1.0.0",
    name: "Trusted constitutional rule",
    scope: "global",
    issuer: "constitutional-authority",
    precedence: 100,
    effectiveFrom: NOW,
    appliesToActions: ["read"],
    prohibitedActions: [],
    requiredConditions: [],
    immutablePrinciples: ["HUMAN_SAFETY_FIRST"],
    provenance: "test",
    status: "active",
  };

  const rule = {
    ...ruleBase,
    signature: signConstitutionalRule(
      ruleBase,
      delegation.privateKeyPem,
    ),
  };

  const trust = {
    root: {
      id: "root-1",
      subject: "root-authority",
      signingKeyId: "root-key",
      issuedAt: NOW,
      status: "active" as const,
      provenance: "test",
    },
    rootKey: {
      id: "root-key",
      algorithm: "Ed25519" as const,
      purpose: "root" as const,
      publicKeyPem: root.publicKeyPem,
      createdAt: NOW,
      notBefore: NOW,
      status: "active" as const,
      provenance: "test",
    },
    anchor: {
      id: "anchor-1",
      subject: "constitutional-anchor",
      rootId: "root-1",
      signingKeyId: "root-key",
      constraints: [],
      issuedAt: NOW,
      status: "active" as const,
      provenance: "test",
      signature: "",
    },
    anchorKey: {
      id: "anchor-key",
      algorithm: "Ed25519" as const,
      purpose: "anchor" as const,
      publicKeyPem: anchor.publicKeyPem,
      createdAt: NOW,
      notBefore: NOW,
      status: "active" as const,
      provenance: "test",
    },
    delegation: {
      id: "delegation-1",
      issuerAnchorId: "anchor-1",
      delegateeId: "constitutional-authority",
      signingKeyId: "anchor-key",
      constraints: ["constitutional-governance"],
      issuedAt: NOW,
      status: "active" as const,
      provenance: "test",
      signature: "",
    },
    delegationKey: {
      id: "delegation-key",
      algorithm: "Ed25519" as const,
      purpose: "delegation" as const,
      publicKeyPem: delegation.publicKeyPem,
      createdAt: NOW,
      notBefore: NOW,
      status: "active" as const,
      provenance: "test",
    },
    credential: {
      id: "credential-1",
      subject: "constitutional-authority",
      issuerDelegationId: "delegation-1",
      claims: {
        "governance:constitutional": "true",
      },
      issuedAt: NOW,
      status: "active" as const,
      provenance: "test",
      signature: "",
    },
    at: NOW,
  };

  trust.anchor.signature = signCanonical(
    { ...trust.anchor, signature: undefined },
    root.privateKeyPem,
  );

  trust.delegation.signature = signCanonical(
    { ...trust.delegation, signature: undefined },
    anchor.privateKeyPem,
  );

  trust.credential.signature = signCanonical(
    { ...trust.credential, signature: undefined },
    delegation.privateKeyPem,
  );

  assert.equal(
    isConstitutionalRuleAuthorized(rule, trust),
    true,
  );
});
