import { randomUUID } from "node:crypto";
import { readFileSync, writeFileSync, existsSync, chmodSync } from "node:fs";

import {
  createAnchorWithSecureKey,
  createCredentialWithSecureKey,
  createDelegationWithSecureKey,
  createRoot,
  createTrustKey,
} from "../../dist/src/trust/service.js";

import { EvidenceAuditRegistry } from "../../dist/src/evidence-audit/registry.js";
import { TrustRegistry } from "../../dist/src/trust/registry.js";
import { KeySecurityBoundary } from "../../dist/src/security/key-boundary.js";
import { signGovernanceRule } from "../../dist/src/governance/crypto.js";
import { signConstitutionalRule } from "../../dist/src/constitution/crypto.js";
import { createEvidenceHash } from "../../dist/src/evidence/service.js";
import { createAuditHash } from "../../dist/src/audit/service.js";
import { evaluateTrustToAction } from "../../dist/src/trust-action/service.js";

const STATE_FILE = "runtime-data/governed-state.json";
const IDENTITY_ID = "runtime-observer";
const AUTHORITY_ID = "runtime-observer-authority";
const RESOURCE = "runtime:observation";
const ACTION = "read";

function now() {
  return new Date().toISOString();
}

function saveState(state) {
  writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), { mode: 0o600 });
  chmodSync(STATE_FILE, 0o600);
}

function loadState() {
  if (!existsSync(STATE_FILE)) return null;
  return JSON.parse(readFileSync(STATE_FILE, "utf8"));
}

function createTrustMaterial() {
  const at = now();

  const rootGenerated = createTrustKey(
    "runtime-root-key",
    "root",
    "giia-runtime",
    at,
  );

  const anchorGenerated = createTrustKey(
    "runtime-anchor-key",
    "anchor",
    "giia-runtime",
    at,
  );

  const delegationGenerated = createTrustKey(
    "runtime-delegation-key",
    "delegation",
    "giia-runtime",
    at,
  );

  const rootBoundary = new KeySecurityBoundary();
  const anchorBoundary = new KeySecurityBoundary();
  const delegationBoundary = new KeySecurityBoundary();

  rootBoundary.register(
    rootGenerated.key,
    rootGenerated.privateKeyPem,
    at,
  );

  anchorBoundary.register(
    anchorGenerated.key,
    anchorGenerated.privateKeyPem,
    at,
  );

  delegationBoundary.register(
    delegationGenerated.key,
    delegationGenerated.privateKeyPem,
    at,
  );

  const root = createRoot(
    "runtime-root",
    "runtime-governance",
    rootGenerated.key.id,
    at,
    "giia-runtime",
  );

  const anchor = createAnchorWithSecureKey(
    {
      id: "runtime-anchor",
      subject: "runtime-governance-anchor",
      rootId: root.id,
      signingKeyId: rootGenerated.key.id,
      constraints: ["issue:credential"],
      issuedAt: at,
      status: "active",
      provenance: "giia-runtime",
    },
    {
      boundary: rootBoundary,
      keyId: rootGenerated.key.id,
      purpose: "root",
      at,
    },
  );

  const delegation = createDelegationWithSecureKey(
    {
      id: "runtime-delegation",
      issuerAnchorId: anchor.id,
      delegateeId: IDENTITY_ID,
      signingKeyId: anchorGenerated.key.id,
      constraints: ["credential:issue"],
      issuedAt: at,
      status: "active",
      provenance: "giia-runtime",
    },
    {
      boundary: anchorBoundary,
      keyId: anchorGenerated.key.id,
      purpose: "anchor",
      at,
    },
  );

  const credential = createCredentialWithSecureKey(
    {
      id: "runtime-credential",
      subject: IDENTITY_ID,
      issuerDelegationId: delegation.id,
      claims: {
        authorityId: AUTHORITY_ID,
        "governance:constitutional": "true",
        "governance:policy": "true",
      },
      issuedAt: at,
      status: "active",
      provenance: "giia-runtime",
    },
    {
      boundary: delegationBoundary,
      keyId: delegationGenerated.key.id,
      purpose: "delegation",
      at,
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
    delegationPrivateKeyPem: delegationGenerated.privateKeyPem,
    at,
  };
}

function initializeState() {
  const existing = loadState();
  if (existing) return existing;

  const material = createTrustMaterial();

  const state = {
    version: "1.0.0",
    createdAt: material.at,
    identityId: IDENTITY_ID,
    authorityId: AUTHORITY_ID,
    trust: material,
  };

  saveState(state);
  return state;
}

function buildRegistry(trust) {
  const registry = new TrustRegistry(":memory:");

  for (const key of [
    trust.rootKey,
    trust.anchorKey,
    trust.delegationKey,
  ]) {
    registry.putKey(key);
  }

  registry.putRoot(trust.root);
  registry.putAnchor(trust.anchor);
  registry.putDelegation(trust.delegation);
  registry.putCredential(trust.credential);

  return registry;
}

function createRules(privateKey, issuer) {
  const baseGovernance = {
    id: "runtime-governance-read",
    version: "1.0.0",
    name: "Runtime observation read",
    status: "active",
    issuer,
    precedence: 10,
    effectiveFrom: "2026-01-01T00:00:00.000Z",
    appliesToActions: ["read"],
    prohibitedActions: [],
    requiredConditions: [],
    provenance: "giia-runtime",
  };

  const governanceRule = {
    ...baseGovernance,
    signature: signGovernanceRule(
      baseGovernance,
      privateKey,
    ),
  };

  const baseConstitution = {
    id: "runtime-constitution-read",
    version: "1.0.0",
    name: "Runtime observation constitutional rule",
    scope: "global",
    issuer,
    precedence: 100,
    effectiveFrom: "2026-01-01T00:00:00.000Z",
    appliesToActions: ["read"],
    prohibitedActions: [],
    requiredConditions: [],
    immutablePrinciples: [
      "HUMAN_SAFETY_FIRST",
      "EVIDENCE_BEFORE_ACTION",
      "HUMAN_ACCOUNTABILITY",
    ],
    provenance: "giia-runtime",
    status: "active",
  };

  const constitutionalRule = {
    ...baseConstitution,
    signature: signConstitutionalRule(
      baseConstitution,
      privateKey,
    ),
  };

  return {
    governanceRule,
    constitutionalRule,
  };
}

function createObservationEvidence(observation, requestId) {
  const recordedAt = now();

  const contentHash = observation.observationHash;

  const base = {
    id: `runtime-evidence-${randomUUID()}`,
    kind: "observation",
    subject: IDENTITY_ID,
    authorizationRequestId: requestId,
    action: ACTION,
    occurredAt: observation.observedAt,
    recordedAt,
    source: "giia-runtime-observer",
    contentHash,
    provenance: "giia-runtime",
  };

  return {
    ...base,
    recordHash: createEvidenceHash(base),
  };
}

function createObservationAudit(
  observation,
  requestId,
  evidenceId,
  decision,
  reason,
) {
  const recordedAt = now();

  const base = {
    id: `runtime-audit-${randomUUID()}`,
    actor: IDENTITY_ID,
    authorizationRequestId: requestId,
    evidenceId,
    action: ACTION,
    resource: RESOURCE,
    outcome: decision,
    occurredAt: observation.observedAt,
    recordedAt,
    reason,
    provenance: "giia-runtime",
  };

  return {
    ...base,
    recordHash: createAuditHash(base),
  };
}

export function governObservation(
  observation,
  executionIntent = null,
) {
  const state = initializeState();
  const trust = state.trust;

  const registry = buildRegistry(trust);
  const evidenceAuditRegistry = new EvidenceAuditRegistry(":memory:");

  const requestId = `runtime-request-${randomUUID()}`;
  const requestedAt = now();

  const identity = {
    id: IDENTITY_ID,
    kind: "service",
    status: "active",
    provenance: "giia-runtime",
    createdAt: state.createdAt,
  };

  const authority = {
    id: AUTHORITY_ID,
    holderIdentityId: IDENTITY_ID,
    trustCredentialId: trust.credential.id,
    scope: [`${ACTION}:${RESOURCE}`],
    issuedAt: state.createdAt,
    status: "active",
    issuer: trust.delegation.delegateeId,
    provenance: "giia-runtime",
  };

  const authorizationRequest = {
    id: requestId,
    subjectIdentityId: IDENTITY_ID,
    authorityId: AUTHORITY_ID,
    action: ACTION,
    resource: RESOURCE,
    requestedAt,
  };

  const evidence = createObservationEvidence(
    observation,
    requestId,
  );

  const audit = createObservationAudit(
    observation,
    requestId,
    evidence.id,
    "DENY",
    "PENDING_GOVERNED_DECISION",
  );

  const rules = createRules(
    trust.delegationPrivateKeyPem,
    trust.delegation.delegateeId,
  );

  const action = {
    id: `runtime-action-${randomUUID()}`,
    authorizationRequestId: requestId,
    actor: IDENTITY_ID,
    action: ACTION,
    resource: RESOURCE,
    provenance: "giia-runtime",
  };

  const result = evaluateTrustToAction({
    identity,
    authority,
    trustChain: {
      root: trust.root,
      rootKey: trust.rootKey,
      anchor: trust.anchor,
      anchorKey: trust.anchorKey,
      delegation: trust.delegation,
      delegationKey: trust.delegationKey,
      credential: trust.credential,
      at: trust.at,
    },
    trustRegistry: registry,
    evidenceAuditRegistry,
    binding: {
      credentialId: trust.credential.id,
      authorityId: AUTHORITY_ID,
    },
    authorizationRequest,
    governanceRules: [rules.governanceRule],
    constitutionalRules: [rules.constitutionalRule],
    action,
    evidence,
    audit,
  });

  registry.close();

  const authoritative =
    result.reason === "CONSTITUTIONAL_GATE_PASSED";

  const governedDecision = {
    requestId,
    observationId: observation.id,
    decision: result.decision,
    reason: result.reason,
    authoritative,
    trustValid: result.trust.valid,
    governanceDecision: result.governance?.decision ?? null,
    authorizationDecision: result.authorization?.decision ?? null,
    evidence: result.evidence,
    audit: result.audit,
    evidenceHash: createEvidenceHash(result.evidence),
    auditHash: createAuditHash(result.audit),
  };

  /*
   * GIIA is a governance authority, not an execution authority.
   *
   * Constitutional ALLOW authorizes the governed decision only.
   * GIIA MUST NOT mint an execution capability for itself or for
   * an agent merely because governance returned ALLOW.
   *
   * Execution requires an independent external enforcement boundary.
   */
  return {
    ...governedDecision,
    executionCapability: null,
  };
}
