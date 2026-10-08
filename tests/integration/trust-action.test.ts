import { EvidenceAuditRegistry } from "../../src/evidence-audit/registry.js";
import { DatabaseSync } from "node:sqlite";
import { unlinkSync } from "node:fs";
import test from "node:test";
import assert from "node:assert/strict";

import {
  createAnchorWithSecureKey,
  createCredentialWithSecureKey,
  createDelegationWithSecureKey,
  createRoot,
  createTrustKey,
  type TrustChainInput,
} from "../../src/trust/service.js";
import { KeySecurityBoundary } from "../../src/security/key-boundary.js";
import { TrustRegistry } from "../../src/trust/registry.js";
import { evaluateTrustToAction } from "../../src/trust-action/service.js";
import { evaluateGovernedPipeline } from "../../src/trust-action/pipeline.js";

import { generateEd25519KeyPair } from "../../src/trust/crypto.js";
import { signConstitutionalRule } from "../../src/constitution/crypto.js";

import type { TrustToActionRequest, ActionRecord } from "../../src/trust-action/types.js";
import type { Identity } from "../../src/identity/types.js";
import type { Authority } from "../../src/authority/types.js";
import type { AuthorizationRequest } from "../../src/authorization/types.js";
import type { GovernanceRule } from "../../src/governance/types.js";
import { signGovernanceRule } from "../../src/governance/crypto.js";
import type { ConstitutionalRule } from "../../src/constitution/types.js";
import type { Evidence } from "../../src/evidence/types.js";
import type { AuditEvent } from "../../src/audit/types.js";

import { createEvidenceHash } from "../../src/evidence/service.js";
import { createAuditHash } from "../../src/audit/service.js";

const NOW = "2026-01-01T00:00:00.000Z";

function createIdentity(id = "identity-001"): Identity {
  return {
    id,
    kind: "human",
    status: "active",
    provenance: "test",
    createdAt: NOW,
  };
}

function createAuthority(
  identityId: string,
  id = "authority-001",
): Authority {
  return {
    id,
    holderIdentityId: identityId,
    trustCredentialId: "gate-credential",
    scope: ["read:resource-001"],
    issuedAt: NOW,
    status: "active",
    issuer: "test-issuer",
    provenance: "test",
  };
}

function createAuthorization(
  identityId: string,
  authorityId: string,
): AuthorizationRequest {
  return {
    id: "request-001",
    subjectIdentityId: identityId,
    authorityId,
    action: "read",
    resource: "resource-001",
    requestedAt: NOW,
  };
}

type TestTrustChain = TrustChainInput & {
  delegationPrivateKeyPem: string;
};

function createChain(
  subjectId: string,
  authorityId: string,
  prefix = "gate",
): TestTrustChain {
  const rootGenerated = createTrustKey(
    `${prefix}-root-key`,
    "root",
    "test",
    NOW,
  );

  const anchorGenerated = createTrustKey(
    `${prefix}-anchor-key`,
    "anchor",
    "test",
    NOW,
  );

  const delegationGenerated = createTrustKey(
    `${prefix}-delegation-key`,
    "delegation",
    "test",
    NOW,
  );

  const rootBoundary = new KeySecurityBoundary();
  const anchorBoundary = new KeySecurityBoundary();
  const delegationBoundary = new KeySecurityBoundary();

  rootBoundary.register(
    rootGenerated.key,
    rootGenerated.privateKeyPem,
    NOW,
  );

  anchorBoundary.register(
    anchorGenerated.key,
    anchorGenerated.privateKeyPem,
    NOW,
  );

  delegationBoundary.register(
    delegationGenerated.key,
    delegationGenerated.privateKeyPem,
    NOW,
  );

  const root = createRoot(
    `${prefix}-root`,
    `${prefix}-root-subject`,
    rootGenerated.key.id,
    NOW,
    "test",
  );

  const anchor = createAnchorWithSecureKey(
    {
      id: `${prefix}-anchor`,
      subject: `${prefix}-anchor-subject`,
      rootId: root.id,
      signingKeyId: rootGenerated.key.id,
      constraints: ["issue:credential"],
      issuedAt: NOW,
      status: "active",
      provenance: "test",
    },
    {
      boundary: rootBoundary,
      keyId: rootGenerated.key.id,
      purpose: "root",
      at: NOW,
    },
  );

  const delegation = createDelegationWithSecureKey(
    {
      id: `${prefix}-delegation`,
      issuerAnchorId: anchor.id,
      delegateeId: subjectId,
      signingKeyId: anchorGenerated.key.id,
      constraints: ["credential:issue"],
      issuedAt: NOW,
      status: "active",
      provenance: "test",
    },
    {
      boundary: anchorBoundary,
      keyId: anchorGenerated.key.id,
      purpose: "anchor",
      at: NOW,
    },
  );

  const credential = createCredentialWithSecureKey(
    {
      id: `${prefix}-credential`,
      subject: subjectId,
      issuerDelegationId: delegation.id,
      claims: {
        authorityId,
        "governance:constitutional": "true",
        "governance:policy": "true",
      },
      issuedAt: NOW,
      status: "active",
      provenance: "test",
    },
    {
      boundary: delegationBoundary,
      keyId: delegationGenerated.key.id,
      purpose: "delegation",
      at: NOW,
    },
  );

  return {
    root,
    rootKey: rootGenerated.key,
    anchor,
    anchorKey: anchorGenerated.key,
    delegation,
    delegationKey: delegationGenerated.key,
    credential,
    at: NOW,
    delegationPrivateKeyPem: delegationGenerated.privateKeyPem,
  };
}

function createEvidence(
  identityId: string,
  requestId: string,
  action: string,
): Evidence {
  const evidence: Omit<Evidence, "recordHash"> = {
    id: "evidence-001",
    kind: "event",
    subject: identityId,
    authorizationRequestId: requestId,
    action,
    occurredAt: NOW,
    recordedAt: NOW,
    source: "test",
    contentHash: "content-hash",
    provenance: "test",
  };

  return {
    ...evidence,
    recordHash: createEvidenceHash(evidence),
  };
}

function createAudit(
  identityId: string,
  requestId: string,
  evidenceId: string,
  action: string,
  resource: string,
): AuditEvent {
  const audit: Omit<AuditEvent, "recordHash"> = {
    id: "audit-001",
    actor: identityId,
    authorizationRequestId: requestId,
    evidenceId,
    action,
    resource,
    outcome: "EXECUTED",
    occurredAt: NOW,
    recordedAt: NOW,
    reason: "test",
    provenance: "test",
  };

  return {
    ...audit,
    recordHash: createAuditHash(audit),
  };
}

function createAction(
  identityId: string,
  request: AuthorizationRequest,
): ActionRecord {
  return {
    id: "action-001",
    authorizationRequestId: request.id,
    actor: identityId,
    action: request.action,
    resource: request.resource,
    executedAt: NOW,
    outcome: "SUCCESS",
    provenance: "test",
  };
}

function createAllowRule(
  delegationPrivateKeyPem?: string,
  issuer = "governance-001",
): GovernanceRule {
  const base: Omit<GovernanceRule, "signature"> = {
    id: "rule-allow-001",
    version: "1.0.0",
    name: "Allow read",
    status: "active",
    issuer,
    precedence: 10,
    effectiveFrom: NOW,
    appliesToActions: ["read"],
    prohibitedActions: [],
    requiredConditions: [],
    provenance: "test",
  };

  return delegationPrivateKeyPem
    ? {
        ...base,
        signature: signGovernanceRule(base, delegationPrivateKeyPem),
      }
    : base;
}

function createConstitutionalRule(
  delegationPrivateKeyPem: string,
  issuer: string,
  overrides: Partial<ConstitutionalRule> = {},
): ConstitutionalRule {
  const base: Omit<ConstitutionalRule, "signature"> = {
    id: "constitution-allow-001",
    version: "1.0.0",
    name: "Constitutional read rule",
    scope: "global",
    issuer,
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

  return {
    ...base,
    signature: signConstitutionalRule(
      base,
      delegationPrivateKeyPem,
    ),
  };
}

function fixture(): {
  request: TrustToActionRequest;
  registry: TrustRegistry;
  constitutionalRule: ConstitutionalRule;
  delegationPrivateKeyPem: string;
} {
  const identity = createIdentity();
  const authority = createAuthority(identity.id);
  const authorizationRequest = createAuthorization(
    identity.id,
    authority.id,
  );

  const trustChain = createChain(
    identity.id,
    authority.id,
  );

  const registry = new TrustRegistry(":memory:");

  for (const key of [
    trustChain.rootKey,
    trustChain.anchorKey,
    trustChain.delegationKey,
  ]) {
    registry.putKey(key);
  }

  registry.putRoot(trustChain.root);
  registry.putAnchor(trustChain.anchor);
  registry.putDelegation(trustChain.delegation);
  registry.putCredential(trustChain.credential);

  const action = createAction(
    identity.id,
    authorizationRequest,
  );

  const evidence = createEvidence(
    identity.id,
    authorizationRequest.id,
    action.action,
  );

  const audit = createAudit(
    identity.id,
    authorizationRequest.id,
    evidence.id,
    action.action,
    action.resource,
  );

  const constitutionalRule = createConstitutionalRule(
    trustChain.delegationPrivateKeyPem,
    trustChain.delegation.delegateeId,
  );

  return {
    registry,
    constitutionalRule,
    delegationPrivateKeyPem: trustChain.delegationPrivateKeyPem,
    request: {
      identity,
      authority,
      trustChain,
      trustRegistry: registry,
      evidenceAuditRegistry: new EvidenceAuditRegistry(":memory:"),
      binding: {
        credentialId: trustChain.credential.id,
        authorityId: authority.id,
      },
      authorizationRequest,
      governanceRules: [createAllowRule(trustChain.delegationPrivateKeyPem, trustChain.delegation.delegateeId)],
      constitutionalRules: [constitutionalRule],
      action,
      evidence,
      audit,
    },
  };
}

function pipelineInput(
  request: TrustToActionRequest,
) {
  return {
    request: {
      id: request.authorizationRequest.id,
      subjectIdentityId: request.authorizationRequest.subjectIdentityId,
      action: request.authorizationRequest.action,
      resource: request.authorizationRequest.resource,
      requestedAt: request.authorizationRequest.requestedAt,
      provenance: "integration-test",
    },
    identity: request.identity,
    authority: request.authority,
    trustChain: request.trustChain,
    trustRegistry: request.trustRegistry,
    evidenceAuditRegistry: new EvidenceAuditRegistry(":memory:"),
    authorizationRequest: request.authorizationRequest,
    binding: request.binding,
    governanceRules: request.governanceRules,
    constitutionalRules: request.constitutionalRules,
    ...(request.jurisdiction !== undefined
      ? { jurisdiction: request.jurisdiction }
      : {}),
    action: request.action,
    evidence: request.evidence,
    audit: request.audit,
  };
}

test("complete governed chain produces authoritative ALLOW", () => {
  const f = fixture();

  const result = evaluateGovernedPipeline(
    pipelineInput(f.request),
  );

  assert.equal(result.outcome, "SUCCESS");

  if (result.outcome !== "SUCCESS") {
    throw new Error("Expected successful governed pipeline");
  }

  assert.equal(result.decision.decision, "ALLOW");
  assert.equal(result.decision.authoritative, true);
  assert.equal(
    result.decision.reason,
    "CONSTITUTIONAL_GATE_PASSED",
  );
  assert.equal(
    result.decision.provenance,
    "giia-authoritative-pipeline",
  );

  assert.equal(result.trust.valid, true);
  assert.ok(result.policy.governance);
  assert.equal(result.policy.governance.decision, "ALLOW");
  assert.equal(result.policy.governance.authoritative, false);
  assert.equal(result.authorization.decision, "ALLOW");
  assert.equal(result.authorization.authoritative, false);

  f.registry.close();
});

test("public trust-to-action boundary maps authoritative pipeline ALLOW", () => {
  const f = fixture();

  const result = evaluateTrustToAction({
    ...f.request,
    evidenceAuditRegistry: new EvidenceAuditRegistry(":memory:"),
  });

  assert.equal(result.decision, "ALLOW");
  assert.equal(result.reason, "CONSTITUTIONAL_GATE_PASSED");
  assert.equal(result.trust.valid, true);
  assert.equal(result.governance?.decision, "ALLOW");
  assert.equal(result.governance?.authoritative, false);
  assert.equal(result.authorization?.decision, "ALLOW");
  assert.equal(result.authorization?.authoritative, false);

  f.registry.close();
});

test("forged trust chain is denied before authorization", () => {
  const f = fixture();

  const result = evaluateTrustToAction({
    ...f.request,
    trustChain: {
      ...f.request.trustChain,
      credential: {
        ...f.request.trustChain.credential,
        signature: "FORGED",
      },
    },
  });

  assert.equal(result.decision, "DENY");
  assert.equal(result.authorization, null);
  assert.match(result.reason, /^TRUST_/);

  f.registry.close();
});

test("persisted trust-object substitution cannot alter authoritative decision", () => {
  const f = fixture();
  const original = f.request.trustChain;

  f.registry.putRoot(original.root);
  f.registry.putAnchor(original.anchor);
  f.registry.putDelegation(original.delegation);
  f.registry.putCredential(original.credential);

  f.registry.putRoot({
    ...original.root,
    subject: "ATTACKER-ROOT-SUBJECT",
  });

  f.registry.putAnchor({
    ...original.anchor,
    rootId: "ATTACKER-ROOT",
  });

  f.registry.putDelegation({
    ...original.delegation,
    delegateeId: "ATTACKER-DELEGATEE",
  });

  f.registry.putCredential({
    ...original.credential,
    subject: "ATTACKER-SUBJECT",
  });

  const result = evaluateGovernedPipeline(pipelineInput(f.request));

  assert.equal(result.outcome, "SUCCESS");
  if (result.outcome === "SUCCESS") {
    assert.equal(result.decision.decision, "ALLOW");
    assert.equal(result.decision.authoritative, true);
  }

  f.registry.close();
});

test("revoked credential is denied", () => {
  const f = fixture();

  f.registry.revoke({
    objectType: "credential",
    objectId: f.request.trustChain.credential.id,
    revokedAt: NOW,
    reason: "test revocation",
    authority: "test-authority",
    provenance: "test",
  });

  const result = evaluateTrustToAction(f.request);

  assert.equal(result.decision, "DENY");
  assert.equal(
    result.reason,
    `TRUST_REVOKED:credential:${f.request.trustChain.credential.id}`,
  );

  f.registry.close();
});

test("authority trust credential mismatch is denied", () => {
  const f = fixture();

  const result = evaluateTrustToAction({
    ...f.request,
    authority: {
      ...f.request.authority,
      trustCredentialId: "different-credential",
    },
  });

  assert.equal(result.decision, "DENY");
  assert.equal(
    result.reason,
    "AUTHORITY_TRUST_CREDENTIAL_MISMATCH",
  );

  f.registry.close();
});

test("credential bound to another authority is denied", () => {
  const f = fixture();

  const result = evaluateTrustToAction({
    ...f.request,
    authority: {
      ...f.request.authority,
      id: "authority-attacker",
    },
  });

  assert.equal(result.decision, "DENY");
  assert.equal(
    result.reason,
    "CREDENTIAL_DOES_NOT_ASSERT_AUTHORITY",
  );

  f.registry.close();
});

test("credential subject mismatch is denied", () => {
  const f = fixture();

  const result = evaluateTrustToAction({
    ...f.request,
    authority: {
      ...f.request.authority,
      holderIdentityId: "identity-attacker",
    },
  });

  assert.equal(result.decision, "DENY");
  assert.equal(
    result.reason,
    "CREDENTIAL_AUTHORITY_SUBJECT_MISMATCH",
  );

  f.registry.close();
});

test("governance prohibition denies the action", () => {
  const f = fixture();

  const base = {
    ...createAllowRule(
      undefined,
      f.request.trustChain.delegation.delegateeId,
    ),
    id: "rule-deny",
    precedence: 100,
    prohibitedActions: ["read"],
  };

  const { signature: _unusedSignature, ...unsignedRule } = base;

  const governanceRule: GovernanceRule = {
    ...unsignedRule,
    signature: signGovernanceRule(
      unsignedRule,
      f.delegationPrivateKeyPem,
    ),
  };

  const result = evaluateTrustToAction({
    ...f.request,
    governanceRules: [governanceRule],
  });

  assert.equal(result.decision, "DENY");
  assert.equal(result.reason, "ACTION_PROHIBITED");
  assert.equal(result.authorization, null);

  f.registry.close();
});

test("missing governance defers the action", () => {
  const f = fixture();

  const result = evaluateTrustToAction({
    ...f.request,
    governanceRules: [],
  });

  assert.equal(result.decision, "DEFER");
  assert.equal(result.authorization, null);

  f.registry.close();
});

test("constitutional prohibition denies the action", () => {
  const f = fixture();

  const rule = createConstitutionalRule(
    f.delegationPrivateKeyPem,
    f.constitutionalRule.issuer,
    {
      id: "constitution-deny-001",
      prohibitedActions: ["read"],
    },
  );

  const result = evaluateTrustToAction({
    ...f.request,
    constitutionalRules: [rule],
  });

  assert.equal(result.decision, "DENY");
  assert.equal(result.reason, "CONSTITUTIONALLY_PROHIBITED");
  assert.equal(result.authorization, null);

  f.registry.close();
});

test("authorization subject mismatch denies the action", () => {
  const f = fixture();

  const result = evaluateTrustToAction({
    ...f.request,
    authorizationRequest: {
      ...f.request.authorizationRequest,
      subjectIdentityId: "identity-attacker",
    },
  });

  assert.equal(result.decision, "DENY");
  assert.equal(result.reason, "SUBJECT_IDENTITY_MISMATCH");

  f.registry.close();
});

test("action binding mismatch denies the action record", () => {
  const f = fixture();

  const result = evaluateTrustToAction({
    ...f.request,
    action: {
      ...f.request.action,
      resource: "resource-attacker",
    },
  });

  assert.equal(result.decision, "DENY");
  assert.equal(
    result.reason,
    "ACTION_AUTHORIZATION_BINDING_INVALID",
  );

  f.registry.close();
});

test("tampered evidence is denied", () => {
  const f = fixture();

  const result = evaluateTrustToAction({
    ...f.request,
    evidence: {
      ...f.request.evidence,
      contentHash: "ATTACKER-CONTENT",
    },
  });

  assert.equal(result.decision, "DENY");
  assert.equal(
    result.reason,
    "EVIDENCE_BINDING_OR_INTEGRITY_INVALID",
  );

  f.registry.close();
});

test("tampered audit is denied", () => {
  const f = fixture();

  const result = evaluateTrustToAction({
    ...f.request,
    audit: {
      ...f.request.audit,
      reason: "ATTACKER-CHANGED",
    },
  });

  assert.equal(result.decision, "DENY");
  assert.equal(
    result.reason,
    "AUDIT_BINDING_OR_INTEGRITY_INVALID",
  );

  f.registry.close();
});

test("evidence for another subject is denied", () => {
  const f = fixture();

  const result = evaluateTrustToAction({
    ...f.request,
    evidence: {
      ...f.request.evidence,
      subject: "identity-attacker",
    },
  });

  assert.equal(result.decision, "DENY");
  assert.equal(
    result.reason,
    "EVIDENCE_BINDING_OR_INTEGRITY_INVALID",
  );

  f.registry.close();
});

test("audit for another actor is denied", () => {
  const f = fixture();

  const result = evaluateTrustToAction({
    ...f.request,
    audit: {
      ...f.request.audit,
      actor: "identity-attacker",
    },
  });

  assert.equal(result.decision, "DENY");
  assert.equal(
    result.reason,
    "AUDIT_BINDING_OR_INTEGRITY_INVALID",
  );

  f.registry.close();
});

test("evidence and audit commit is atomic on second-record failure", () => {
  const dbPath = ".test-evidence-audit-atomic.sqlite";

  for (const suffix of ["", "-wal", "-shm"]) {
    try {
      unlinkSync(`${dbPath}${suffix}`);
    } catch {}
  }

  const registry = new EvidenceAuditRegistry(dbPath);

  const identityId = "identity-001";
  const requestId = "request-001";
  const action = "read";
  const resource = "resource-001";

  const evidence1 = createEvidence(identityId, requestId, action);
  const audit1 = createAudit(
    identityId,
    requestId,
    evidence1.id,
    action,
    resource,
  );

  registry.commitEvidenceAndAudit(evidence1, audit1);

  const evidence2: Evidence = {
    ...evidence1,
    id: "evidence-002",
    recordHash: createEvidenceHash({
      ...evidence1,
      id: "evidence-002",
    }),
  };

  const audit2: AuditEvent = {
    ...audit1,
    id: "audit-002",
  };

  assert.throws(
    () => registry.commitEvidenceAndAudit(evidence2, audit2),
  );

  assert.equal(registry.countEvidence(), 1);
  assert.equal(registry.countAudit(), 1);
  assert.equal(registry.getEvidence("evidence-002"), undefined);
  assert.equal(registry.getAudit("audit-002"), undefined);

  registry.close();

  for (const suffix of ["", "-wal", "-shm"]) {
    try {
      unlinkSync(`${dbPath}${suffix}`);
    } catch {}
  }
});

test("evidence and audit records are append-only at the SQLite boundary", () => {
  const dbPath = ".test-evidence-audit-immutable.sqlite";

  for (const suffix of ["", "-wal", "-shm"]) {
    try {
      unlinkSync(`${dbPath}${suffix}`);
    } catch {}
  }

  const registry = new EvidenceAuditRegistry(dbPath);

  const identityId = "identity-001";
  const requestId = "request-001";
  const action = "read";
  const resource = "resource-001";

  const evidence = createEvidence(identityId, requestId, action);
  const audit = createAudit(
    identityId,
    requestId,
    evidence.id,
    action,
    resource,
  );

  registry.commitEvidenceAndAudit(evidence, audit);
  registry.close();

  const db = new DatabaseSync(dbPath);

  assert.throws(
    () =>
      db
        .prepare(
          "UPDATE evidence_records SET subject = ? WHERE evidence_id = ?",
        )
        .run("tampered", evidence.id),
    /EVIDENCE_RECORD_IMMUTABLE/,
  );

  assert.throws(
    () =>
      db
        .prepare("DELETE FROM evidence_records WHERE evidence_id = ?")
        .run(evidence.id),
    /EVIDENCE_RECORD_APPEND_ONLY/,
  );

  assert.throws(
    () =>
      db
        .prepare(
          "UPDATE audit_records SET resource = ? WHERE audit_id = ?",
        )
        .run("tampered", audit.id),
    /AUDIT_RECORD_IMMUTABLE/,
  );

  assert.throws(
    () =>
      db
        .prepare("DELETE FROM audit_records WHERE audit_id = ?")
        .run(audit.id),
    /AUDIT_RECORD_APPEND_ONLY/,
  );

  db.close();

  for (const suffix of ["", "-wal", "-shm"]) {
    try {
      unlinkSync(`${dbPath}${suffix}`);
    } catch {}
  }
});


test("governance jurisdiction mismatch cannot authoritatively ALLOW", () => {
  const f = fixture();
  const baseRule = createAllowRule(
    f.delegationPrivateKeyPem,
    f.request.trustChain.delegation.delegateeId,
  );
  const { signature: _oldSignature, ...unsignedRule } = baseRule;
  const mismatchedRule = {
    ...unsignedRule,
    id: "jurisdiction-mismatch-rule",
    jurisdiction: "JURISDICTION-A",
    signature: signGovernanceRule(
      {
        ...unsignedRule,
        id: "jurisdiction-mismatch-rule",
        jurisdiction: "JURISDICTION-A",
      },
      f.delegationPrivateKeyPem,
    ),
  };

  const request = {
    ...f.request,
    jurisdiction: "JURISDICTION-B",
    governanceRules: [mismatchedRule],
  };

  const result = evaluateGovernedPipeline(pipelineInput(request));

  assert.equal(result.outcome, "FAILURE");
  if (result.outcome === "FAILURE") {
    assert.equal(result.decision.decision, "DEFER");
    assert.equal(result.decision.reason, "NO_APPLICABLE_GOVERNANCE_RULE");
  }

  f.registry.close();
});

test("unverified governance rule from another jurisdiction cannot poison a valid request", () => {
  const f = fixture();
  const globalRule = createAllowRule(
    f.delegationPrivateKeyPem,
    f.request.trustChain.delegation.delegateeId,
  );

  const { signature: _signature, ...unsignedRule } = globalRule;
  const unrelatedUnverifiedRule = {
    ...unsignedRule,
    id: "unrelated-unverified-jurisdiction-rule",
    jurisdiction: "JURISDICTION-A",
    signature: "invalid-signature",
  };

  const request = {
    ...f.request,
    jurisdiction: "JURISDICTION-B",
    governanceRules: [unrelatedUnverifiedRule, globalRule],
  };

  const result = evaluateGovernedPipeline(pipelineInput(request));

  assert.equal(result.outcome, "SUCCESS");
  if (result.outcome === "SUCCESS") {
    assert.equal(result.decision.decision, "ALLOW");
    assert.equal(result.decision.authoritative, true);
    assert.ok(result.policy.governance);
    assert.deepEqual(result.policy.governance.ruleIds, [globalRule.id]);
  }

  f.registry.close();
});

test("matching governance jurisdiction remains applicable", () => {
  const f = fixture();
  const baseRule = createAllowRule(
    f.delegationPrivateKeyPem,
    f.request.trustChain.delegation.delegateeId,
  );
  const { signature: _oldSignature, ...unsignedRule } = baseRule;
  const matchingRule = {
    ...unsignedRule,
    id: "jurisdiction-matching-rule",
    jurisdiction: "JURISDICTION-A",
    signature: signGovernanceRule(
      {
        ...unsignedRule,
        id: "jurisdiction-matching-rule",
        jurisdiction: "JURISDICTION-A",
      },
      f.delegationPrivateKeyPem,
    ),
  };

  const request = {
    ...f.request,
    jurisdiction: "JURISDICTION-A",
    governanceRules: [matchingRule],
  };

  const result = evaluateGovernedPipeline(pipelineInput(request));

  assert.equal(result.outcome, "SUCCESS");
  if (result.outcome === "SUCCESS") {
    assert.equal(result.decision.decision, "ALLOW");
    assert.equal(result.decision.authoritative, true);
    assert.ok(result.policy.governance);
    assert.deepEqual(result.policy.governance.ruleIds, [
      "jurisdiction-matching-rule",
    ]);
  }

  f.registry.close();
});

test("global governance rule remains jurisdiction-neutral", () => {
  const f = fixture();
  const globalRule = createAllowRule(
    f.delegationPrivateKeyPem,
    f.request.trustChain.delegation.delegateeId,
  );

  const request = {
    ...f.request,
    jurisdiction: "JURISDICTION-B",
    governanceRules: [globalRule],
  };

  const result = evaluateGovernedPipeline(pipelineInput(request));

  assert.equal(result.outcome, "SUCCESS");
  if (result.outcome === "SUCCESS") {
    assert.equal(result.decision.decision, "ALLOW");
    assert.equal(result.decision.authoritative, true);
    assert.ok(result.policy.governance);
    assert.deepEqual(result.policy.governance.ruleIds, [globalRule.id]);
  }

  f.registry.close();
});
