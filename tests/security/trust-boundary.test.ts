import test from "node:test";
import assert from "node:assert/strict";

import {
  assessTrustBoundary,
  assertConsequentialAuthority,
  createVerificationCheckEvidence,
} from "../../src/security/trust-boundary.js";

import {
  createAuthenticatedVerification,
} from "../../src/trust/verification.js";

import {
  createAnchorWithSecureKey,
  createCredentialWithSecureKey,
  createDelegationWithSecureKey,
  createRoot,
  createTrustKey,
  type TrustChainInput,
} from "../../src/trust/service.js";

import { KeySecurityBoundary } from "../../src/security/key-boundary.js";
import { canonicalize } from "../../src/core/canonical.js";
import { sha256 } from "../../src/core/security.js";
import type { Identity } from "../../src/identity/types.js";
import type { Authority } from "../../src/authority/types.js";
import type { AuthorizationRequest } from "../../src/authorization/types.js";

import {
  authenticateVerifier,
  VERIFIER_AUTHORITY_CLAIM,
  VERIFIER_AUTHORITY_HASH_CLAIM,
} from "../../src/trust/verifier.js";

const ASSESSED_AT = "2026-09-21T12:00:00.000Z";

function createIdentity(id: string): Identity {
  return {
    id,
    kind: "service",
    status: "active",
    provenance: "test",
    createdAt: ASSESSED_AT,
  };
}

function createAuthority(identityId: string): Authority {
  return {
    id: "verifier-authority",
    holderIdentityId: identityId,
    trustCredentialId: "verifier-credential",
    scope: ["VERIFY:trust-subject"],
    issuedAt: ASSESSED_AT,
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
    id: `authorization-${identityId}`,
    subjectIdentityId: identityId,
    authorityId,
    action: "VERIFY",
    resource: "trust-subject",
    requestedAt: ASSESSED_AT,
  };
}

function createChain(
  subjectId: string,
  prefix: string,
  claims: Record<string, string> = {},
): TrustChainInput {
  const rootGenerated = createTrustKey(
    `${prefix}-root-key`,
    "root",
    "test",
    ASSESSED_AT,
  );

  const anchorGenerated = createTrustKey(
    `${prefix}-anchor-key`,
    "anchor",
    "test",
    ASSESSED_AT,
  );

  const delegationGenerated = createTrustKey(
    `${prefix}-delegation-key`,
    "delegation",
    "test",
    ASSESSED_AT,
  );

  const rootBoundary = new KeySecurityBoundary();
  const anchorBoundary = new KeySecurityBoundary();
  const delegationBoundary = new KeySecurityBoundary();

  rootBoundary.register(
    rootGenerated.key,
    rootGenerated.privateKeyPem,
    ASSESSED_AT,
  );

  anchorBoundary.register(
    anchorGenerated.key,
    anchorGenerated.privateKeyPem,
    ASSESSED_AT,
  );

  delegationBoundary.register(
    delegationGenerated.key,
    delegationGenerated.privateKeyPem,
    ASSESSED_AT,
  );

  const root = createRoot(
    `${prefix}-root`,
    `${prefix}-root-subject`,
    rootGenerated.key.id,
    ASSESSED_AT,
    "test",
  );

  const anchor = createAnchorWithSecureKey(
    {
      id: `${prefix}-anchor`,
      subject: `${prefix}-anchor-subject`,
      rootId: root.id,
      signingKeyId: rootGenerated.key.id,
      constraints: ["issue:credential"],
      issuedAt: ASSESSED_AT,
      status: "active",
      provenance: "test",
    },
    {
      boundary: rootBoundary,
      keyId: rootGenerated.key.id,
      purpose: "root",
      at: ASSESSED_AT,
    },
  );

  const delegation = createDelegationWithSecureKey(
    {
      id: `${prefix}-delegation`,
      issuerAnchorId: anchor.id,
      delegateeId: subjectId,
      signingKeyId: anchorGenerated.key.id,
      constraints: ["credential:issue"],
      issuedAt: ASSESSED_AT,
      status: "active",
      provenance: "test",
    },
    {
      boundary: anchorBoundary,
      keyId: anchorGenerated.key.id,
      purpose: "anchor",
      at: ASSESSED_AT,
    },
  );

  const credential = createCredentialWithSecureKey(
    {
      id: `${prefix}-credential`,
      subject: subjectId,
      issuerDelegationId: delegation.id,
      claims,
      issuedAt: ASSESSED_AT,
      status: "active",
      provenance: "test",
    },
    {
      boundary: delegationBoundary,
      keyId: delegationGenerated.key.id,
      purpose: "delegation",
      at: ASSESSED_AT,
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
    at: ASSESSED_AT,
  };
}

function createAuthenticatedEvidence(
  id: string,
  subjectId: string,
) {
  const verifierIdentity = createIdentity("verifier-001");
  const verifierAuthority = createAuthority(verifierIdentity.id);
  const authorityHash = sha256(canonicalize(verifierAuthority));

  const verifierChain = createChain(
    verifierIdentity.id,
    "verifier",
    {
      [VERIFIER_AUTHORITY_CLAIM]: verifierAuthority.id,
      [VERIFIER_AUTHORITY_HASH_CLAIM]: authorityHash,
    },
  );

  const authorizationRequest = createAuthorization(
    verifierIdentity.id,
    verifierAuthority.id,
  );

  const verifier = authenticateVerifier({
    identity: verifierIdentity,
    authority: verifierAuthority,
    chain: verifierChain,
    authorizationRequest,
  });

  const subjectChain = createChain(
    subjectId,
    "subject",
  );

  return createAuthenticatedVerification({
    id,
    subjectId,
    verifier,
    verifiedAt: ASSESSED_AT,
    chain: subjectChain,
  });
}

test("missing evidence fails closed and isolates subject", () => {
  const assessment = assessTrustBoundary({
    subjectId: "subject-001",
    evidence: {},
    assessedAt: ASSESSED_AT,
  });

  assert.equal(assessment.trusted, false);
  assert.equal(assessment.disposition, "ISOLATED");
  assert.equal(assessment.consequentialAuthorityAllowed, false);

  assert.deepEqual(assessment.failedChecks, [
    "IDENTITY",
    "AUTHENTICITY",
    "INTEGRITY",
    "PROVENANCE",
    "AUTHORITY",
    "AUTHORIZATION",
    "VERIFICATION",
  ]);

  assert.throws(
    () => assertConsequentialAuthority(assessment),
    (error: unknown) =>
      error instanceof Error &&
      "code" in error &&
      (error as { code?: unknown }).code ===
        "TRUST_BOUNDARY_AUTHORITY_DENIED",
  );
});

test("previously trusted subject with missing evidence is quarantined", () => {
  const assessment = assessTrustBoundary({
    subjectId: "device-001",
    previouslyTrusted: true,
    evidence: {},
    assessedAt: ASSESSED_AT,
  });

  assert.equal(assessment.trusted, false);
  assert.equal(assessment.disposition, "QUARANTINED");
  assert.equal(assessment.consequentialAuthorityAllowed, false);
});

test("caller cannot grant trust by supplying legacy boolean checks", () => {
  const assessment = assessTrustBoundary({
    subjectId: "subject-002",
    evidence: {},
    assessedAt: ASSESSED_AT,
  });

  assert.equal(assessment.trusted, false);
  assert.equal(assessment.consequentialAuthorityAllowed, false);
  assert.equal(
    assessment.reason,
    "TRUST_VERIFICATION_INCOMPLETE_OR_FAILED",
  );
});

test("verification evidence cannot establish unrelated trust checks", () => {
  const authenticatedVerification = createAuthenticatedEvidence(
    "verification-001",
    "subject-003",
  );

  const verificationEvidence =
    createVerificationCheckEvidence(authenticatedVerification);

  const assessment = assessTrustBoundary({
    subjectId: "subject-003",
    evidence: {
      VERIFICATION: verificationEvidence,
    },
    assessedAt: ASSESSED_AT,
  });

  assert.equal(assessment.trusted, false);
  assert.equal(assessment.consequentialAuthorityAllowed, false);

  assert.deepEqual(assessment.failedChecks, [
    "IDENTITY",
    "AUTHENTICITY",
    "INTEGRITY",
    "PROVENANCE",
    "AUTHORITY",
    "AUTHORIZATION",
  ]);
});

test("forged verification evidence is rejected", () => {
  const authenticatedVerification = createAuthenticatedEvidence(
    "verification-002",
    "subject-004",
  );

  const validEvidence =
    createVerificationCheckEvidence(authenticatedVerification);

  const forgedEvidence = {
    ...validEvidence,
    evidenceRef: "forged-reference",
  };

  const assessment = assessTrustBoundary({
    subjectId: "subject-004",
    evidence: {
      VERIFICATION: forgedEvidence,
    },
    assessedAt: ASSESSED_AT,
  });

  assert.equal(assessment.trusted, false);
  assert.equal(assessment.consequentialAuthorityAllowed, false);
  assert.ok(assessment.failedChecks.includes("VERIFICATION"));
});

test("verification evidence bound to another subject is rejected", () => {
  const authenticatedVerification = createAuthenticatedEvidence(
    "verification-003",
    "subject-005",
  );

  const evidence =
    createVerificationCheckEvidence(authenticatedVerification);

  const assessment = assessTrustBoundary({
    subjectId: "different-subject",
    evidence: {
      VERIFICATION: evidence,
    },
    assessedAt: ASSESSED_AT,
  });

  assert.equal(assessment.trusted, false);
  assert.equal(assessment.consequentialAuthorityAllowed, false);
  assert.ok(assessment.failedChecks.includes("VERIFICATION"));
});

test("repair or restart does not itself create trust", () => {
  const assessment = assessTrustBoundary({
    subjectId: "recovered-001",
    previouslyTrusted: true,
    evidence: {},
    assessedAt: ASSESSED_AT,
  });

  assert.equal(assessment.disposition, "QUARANTINED");
  assert.equal(assessment.consequentialAuthorityAllowed, false);

  assert.throws(
    () => assertConsequentialAuthority(assessment),
    (error: unknown) =>
      error instanceof Error &&
      "code" in error &&
      (error as { code?: unknown }).code ===
        "TRUST_BOUNDARY_AUTHORITY_DENIED",
  );
});

test("lower-level ALLOW cannot be treated as an authoritative consequential decision", async () => {
  const { evaluateCoreRequest } = await import("../../src/core/integration.js");

  const identity = createIdentity("core-subject-001");
  const authority = createAuthority(identity.id);

  const authorizationRequest = createAuthorization(
    identity.id,
    authority.id,
  );

  const allowRule = {
    id: "core-allow-rule",
    version: "1",
    name: "Core test allow rule",
    status: "active" as const,
    issuer: "test-issuer",
    precedence: 1,
    effect: "ALLOW" as const,
    action: authorizationRequest.action,
    resource: authorizationRequest.resource,
    conditions: [],
    effectiveFrom: ASSESSED_AT,
    appliesToActions: [authorizationRequest.action],
    prohibitedActions: [],
    requiredConditions: [],
    provenance: "test",
  };

  const result = evaluateCoreRequest(
    identity,
    authority,
    authorizationRequest,
    [allowRule],
  );

  assert.equal(result.governance.decision, "ALLOW");
  assert.equal(result.authorization?.decision, "ALLOW");
  assert.equal(result.finalDecision, "ALLOW");

  // Lower-level stage results can never become authoritative consequential authority.
  assert.equal(result.authoritative, false);
  assert.equal(result.governance.authoritative, false);
  assert.equal(result.authorization?.authoritative, false);
});
