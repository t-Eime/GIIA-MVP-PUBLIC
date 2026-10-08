import { EvidenceAuditRegistry } from "../../src/evidence-audit/registry.js";
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
import { evaluateGovernedPipeline } from "../../src/trust-action/pipeline.js";
import { signConstitutionalRule } from "../../src/constitution/crypto.js";
import { signGovernanceRule } from "../../src/governance/crypto.js";
import { createEvidenceHash } from "../../src/evidence/service.js";
import { createAuditHash } from "../../src/audit/service.js";

import type { TrustToActionRequest, ActionRecord } from "../../src/trust-action/types.js";
import type { Identity } from "../../src/identity/types.js";
import type { Authority } from "../../src/authority/types.js";
import type { AuthorizationRequest } from "../../src/authorization/types.js";
import type { GovernanceRule } from "../../src/governance/types.js";
import type { ConstitutionalRule } from "../../src/constitution/types.js";
import type { Evidence } from "../../src/evidence/types.js";
import type { AuditEvent } from "../../src/audit/types.js";

export const NOW = "2026-01-01T00:00:00.000Z";

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
  requestId = "request-001",
): AuthorizationRequest {
  return {
    id: requestId,
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
  id = "evidence-001",
): Evidence {
  const evidence: Omit<Evidence, "recordHash"> = {
    id,
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
  id = "audit-001",
): AuditEvent {
  const audit: Omit<AuditEvent, "recordHash"> = {
    id,
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
  id = "action-001",
): ActionRecord {
  return {
    id,
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
  delegationPrivateKeyPem: string,
  issuer: string,
  id = "rule-allow-001",
): GovernanceRule {
  const base: Omit<GovernanceRule, "signature"> = {
    id,
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

  return {
    ...base,
    signature: signGovernanceRule(
      base,
      delegationPrivateKeyPem,
    ),
  };
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

export function createGovernedFixture(
  suffix = "",
): {
  request: TrustToActionRequest;
  registry: TrustRegistry;
} {
  const identityId = suffix ? `identity-${suffix}` : "identity-001";
  const authorityId = suffix ? `authority-${suffix}` : "authority-001";
  const requestId = suffix ? `request-${suffix}` : "request-001";
  const evidenceId = suffix ? `evidence-${suffix}` : "evidence-001";
  const auditId = suffix ? `audit-${suffix}` : "audit-001";
  const actionId = suffix ? `action-${suffix}` : "action-001";
  const governanceRuleId = suffix
    ? `rule-allow-${suffix}`
    : "rule-allow-001";
  const constitutionalRuleId = suffix
    ? `constitution-allow-${suffix}`
    : "constitution-allow-001";

  const identity = createIdentity(identityId);
  const authority = createAuthority(identity.id, authorityId);

  const authorizationRequest = createAuthorization(
    identity.id,
    authority.id,
    requestId,
  );

  const trustChain = createChain(
    identity.id,
    authority.id,
    suffix ? `gate-${suffix}` : "gate",
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
    actionId,
  );

  const evidence = createEvidence(
    identity.id,
    authorizationRequest.id,
    action.action,
    evidenceId,
  );

  const audit = createAudit(
    identity.id,
    authorizationRequest.id,
    evidence.id,
    action.action,
    action.resource,
    auditId,
  );

  const constitutionalRule = createConstitutionalRule(
    trustChain.delegationPrivateKeyPem,
    trustChain.delegation.delegateeId,
    {
      id: constitutionalRuleId,
    },
  );

  return {
    registry,
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
      governanceRules: [
        createAllowRule(
          trustChain.delegationPrivateKeyPem,
          trustChain.delegation.delegateeId,
          governanceRuleId,
        ),
      ],
      constitutionalRules: [constitutionalRule],
      action,
      evidence,
      audit,
    },
  };
}

export function evaluateFixture(
  request: TrustToActionRequest,
) {
  const input = {
    request: {
      id: request.authorizationRequest.id,
      subjectIdentityId: request.authorizationRequest.subjectIdentityId,
      action: request.authorizationRequest.action,
      resource: request.authorizationRequest.resource,
      requestedAt: request.authorizationRequest.requestedAt,
      provenance: "test-fixture",
    },
    identity: request.identity,
    authority: request.authority,
    trustChain: request.trustChain,
    trustRegistry: request.trustRegistry,
    evidenceAuditRegistry: request.evidenceAuditRegistry,
    authorizationRequest: request.authorizationRequest,
    binding: request.binding,
    governanceRules: request.governanceRules,
    constitutionalRules: request.constitutionalRules,
    action: request.action,
    evidence: request.evidence,
    audit: request.audit,
    ...(request.jurisdiction !== undefined
      ? { jurisdiction: request.jurisdiction }
      : {}),
  };

  return evaluateGovernedPipeline(input);
}
