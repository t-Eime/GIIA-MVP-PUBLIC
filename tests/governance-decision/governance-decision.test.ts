import assert from "node:assert/strict";
import test from "node:test";

import {
  createGovernanceKeyAuthorization,
} from "../../src/governance-decision/authorization.js";

import {
  createSignedGovernanceDecision,
  verifySignedGovernanceDecision,
  type GovernanceDecisionAuthorization,
} from "../../src/governance-decision/crypto.js";

import {
  createTrustKey,
  createRoot,
  createAnchorWithSecureKey,
  createDelegationWithSecureKey,
  createCredentialWithSecureKey,
  verifyTrustChain,
} from "../../src/trust/service.js";

import { KeySecurityBoundary } from "../../src/security/key-boundary.js";

const AT = "2026-10-02T12:00:00.000Z";
const EXPIRES = "2026-10-02T13:00:00.000Z";

function fixture() {
  const boundary = new KeySecurityBoundary();

  const root = createTrustKey(
    "root-key",
    "root",
    "test-root",
    AT,
  );

  const anchor = createTrustKey(
    "anchor-key",
    "anchor",
    "test-anchor",
    AT,
  );

  const delegation = createTrustKey(
    "delegation-key",
    "delegation",
    "test-delegation",
    AT,
  );

  const governance = createTrustKey(
    "governance-key",
    "governance",
    "test-governance",
    AT,
  );

  boundary.register(root.key, root.privateKeyPem, AT);
  boundary.register(anchor.key, anchor.privateKeyPem, AT);
  boundary.register(delegation.key, delegation.privateKeyPem, AT);
  boundary.register(governance.key, governance.privateKeyPem, AT);

  const trustRoot = createRoot(
    "root-1",
    "GIIA Test Root",
    root.key.id,
    AT,
    "test-root",
  );

  const trustAnchor = createAnchorWithSecureKey(
    {
      id: "anchor-1",
      subject: "GIIA Test Anchor",
      rootId: trustRoot.id,
      signingKeyId: root.key.id,
      constraints: ["GOVERNANCE"],
      issuedAt: AT,
      status: "active",
      provenance: "test-anchor",
    },
    {
      boundary,
      keyId: root.key.id,
      purpose: "root",
      at: AT,
    },
  );

  const trustDelegation = createDelegationWithSecureKey(
    {
      id: "delegation-1",
      issuerAnchorId: trustAnchor.id,
      delegateeId: "governance-authority",
      signingKeyId: anchor.key.id,
      constraints: ["DECISION_SIGNING"],
      issuedAt: AT,
      status: "active",
      provenance: "test-delegation",
    },
    {
      boundary,
      keyId: anchor.key.id,
      purpose: "anchor",
      at: AT,
    },
  );

  const credential = createCredentialWithSecureKey(
    {
      id: "credential-1",
      subject: "governance-authority",
      issuerDelegationId: trustDelegation.id,
      claims: {
        "governance:policy": "true",
      },
      issuedAt: AT,
      expiresAt: EXPIRES,
      status: "active",
      provenance: "test-credential",
    },
    {
      boundary,
      keyId: delegation.key.id,
      purpose: "delegation",
      at: AT,
    },
  );

  const trustChain = {
    root: trustRoot,
    rootKey: root.key,
    anchor: trustAnchor,
    anchorKey: anchor.key,
    delegation: trustDelegation,
    delegationKey: delegation.key,
    credential,
    at: AT,
  };

  const chainResult = verifyTrustChain(trustChain);
  assert.equal(chainResult.valid, true, chainResult.reason);

  const governanceAuthorization = createGovernanceKeyAuthorization({
    authorizationId: "governance-auth-1",
    governanceKey: governance.key,
    credential,
    signingAuthorityId: "governance-authority",
    issuerDelegationKey: delegation.key,
    trustChain,
    boundary,
    issuedAt: AT,
    expiresAt: EXPIRES,
  });

  const authorization: GovernanceDecisionAuthorization = {
    authorization: governanceAuthorization,
    credential,
    governanceKey: governance.key,
    trustChain,
    signingAuthorityId: "governance-authority",
  };

  const decision = createSignedGovernanceDecision({
    requestId: "request-1",
    actorId: "actor-1",
    passportId: "passport-1",
    action: "TEST_ACTION",
    target: "TEST_TARGET",
    payloadHash: "test-payload-hash",
    constitutionVersion: "GIIA-CONSTITUTION-1.0",
    governanceContext: "test-governance-context",
    issuedAt: AT,
    expiresAt: EXPIRES,
    nonce: "decision-nonce-1",
    authorization,
    boundary,
  });

  return {
    boundary,
    root,
    anchor,
    delegation,
    governance,
    trustRoot,
    trustAnchor,
    trustDelegation,
    credential,
    trustChain,
    governanceAuthorization,
    authorization,
    decision,
  };
}

test("trust-authorized governance key can sign an authoritative ALLOW", () => {
  const f = fixture();

  const result = verifySignedGovernanceDecision({
    decision: f.decision,
    authorization: f.governanceAuthorization,
    governanceKey: f.governance.key,
    credential: f.credential,
    trustChain: f.trustChain,
    at: AT,
  });

  assert.equal(result.valid, true, result.reason);
});

test("decision signature tampering is rejected", () => {
  const f = fixture();

  const tampered = {
    ...f.decision,
    signatureBase64: f.decision.signatureBase64.slice(0, -2) + "AA",
  };

  const result = verifySignedGovernanceDecision({
    decision: tampered,
    authorization: f.governanceAuthorization,
    governanceKey: f.governance.key,
    credential: f.credential,
    trustChain: f.trustChain,
    at: AT,
  });

  assert.equal(result.valid, false);
});

test("governance public-key substitution is rejected", () => {
  const f = fixture();

  const replacement = createTrustKey(
    "replacement-governance-key",
    "governance",
    "replacement",
    AT,
  );

  const result = verifySignedGovernanceDecision({
    decision: f.decision,
    authorization: f.governanceAuthorization,
    governanceKey: replacement.key,
    credential: f.credential,
    trustChain: f.trustChain,
    at: AT,
  });

  assert.equal(result.valid, false);
});

test("governance key identity substitution is rejected", () => {
  const f = fixture();

  const replacement = createTrustKey(
    "replacement-governance-key",
    "governance",
    "replacement",
    AT,
  );

  const result = verifySignedGovernanceDecision({
    decision: f.decision,
    authorization: f.governanceAuthorization,
    governanceKey: {
      ...replacement.key,
      id: f.governance.key.id,
    },
    credential: f.credential,
    trustChain: f.trustChain,
    at: AT,
  });

  assert.equal(result.valid, false);
});

test("governance authorization substitution is rejected", () => {
  const f = fixture();

  const replacement = createGovernanceKeyAuthorization({
    authorizationId: "governance-auth-replacement",
    governanceKey: f.governance.key,
    credential: f.credential,
    signingAuthorityId: "governance-authority",
    issuerDelegationKey: f.delegation.key,
    trustChain: f.trustChain,
    boundary: f.boundary,
    issuedAt: AT,
    expiresAt: EXPIRES,
  });

  const result = verifySignedGovernanceDecision({
    decision: f.decision,
    authorization: replacement,
    governanceKey: f.governance.key,
    credential: f.credential,
    trustChain: f.trustChain,
    at: AT,
  });

  assert.equal(result.valid, false);
});

test("governance authorization mutation after signing is rejected", () => {
  const f = fixture();

  const mutatedAuthorization = {
    ...f.governanceAuthorization,
    payload: {
      ...f.governanceAuthorization.payload,
      signingAuthorityId: "attacker-authority",
    },
  };

  const result = verifySignedGovernanceDecision({
    decision: f.decision,
    authorization: mutatedAuthorization,
    governanceKey: f.governance.key,
    credential: f.credential,
    trustChain: f.trustChain,
    at: AT,
  });

  assert.equal(result.valid, false);
});

test("revoked governance key cannot verify a governance decision", () => {
  const f = fixture();

  f.boundary.revoke(
    f.governance.key.id,
    AT,
    "test revocation",
  );

  const revokedKey = {
    ...f.governance.key,
    status: "revoked" as const,
  };

  const result = verifySignedGovernanceDecision({
    decision: f.decision,
    authorization: f.governanceAuthorization,
    governanceKey: revokedKey,
    credential: f.credential,
    trustChain: f.trustChain,
    at: AT,
  });

  assert.equal(result.valid, false);
});

test("revoked delegation key invalidates governance authorization", () => {
  const f = fixture();

  const revokedDelegationKey = {
    ...f.delegation.key,
    status: "revoked" as const,
  };

  const revokedTrustChain = {
    ...f.trustChain,
    delegationKey: revokedDelegationKey,
  };

  const result = verifySignedGovernanceDecision({
    decision: f.decision,
    authorization: f.governanceAuthorization,
    governanceKey: f.governance.key,
    credential: f.credential,
    trustChain: revokedTrustChain,
    at: AT,
  });

  assert.equal(result.valid, false);
});

test("credential without governance authority cannot authorize signing", () => {
  const f = fixture();

  const unauthorizedCredential = createCredentialWithSecureKey(
    {
      id: "credential-no-governance",
      subject: "governance-authority",
      issuerDelegationId: f.trustDelegation.id,
      claims: {
        ordinaryCredential: "true",
      },
      issuedAt: AT,
      expiresAt: EXPIRES,
      status: "active",
      provenance: "test-credential",
    },
    {
      boundary: f.boundary,
      keyId: f.delegation.key.id,
      purpose: "delegation",
      at: AT,
    },
  );

  assert.throws(() =>
    createGovernanceKeyAuthorization({
      authorizationId: "governance-auth-invalid",
      governanceKey: f.governance.key,
      credential: unauthorizedCredential,
      signingAuthorityId: "governance-authority",
      issuerDelegationKey: f.delegation.key,
      trustChain: {
        ...f.trustChain,
        credential: unauthorizedCredential,
      },
      boundary: f.boundary,
      issuedAt: AT,
      expiresAt: EXPIRES,
    }),
  );
});

test("expired governance decision is rejected", () => {
  const f = fixture();

  const result = verifySignedGovernanceDecision({
    decision: f.decision,
    authorization: f.governanceAuthorization,
    governanceKey: f.governance.key,
    credential: f.credential,
    trustChain: f.trustChain,
    at: "2026-10-02T14:00:00.000Z",
  });

  assert.equal(result.valid, false);
});

test("expired governance authorization is rejected", () => {
  const f = fixture();

  const expiredAuthorization = {
    ...f.governanceAuthorization,
    payload: {
      ...f.governanceAuthorization.payload,
      expiresAt: "2026-10-02T11:00:00.000Z",
    },
  };

  const result = verifySignedGovernanceDecision({
    decision: f.decision,
    authorization: expiredAuthorization,
    governanceKey: f.governance.key,
    credential: f.credential,
    trustChain: f.trustChain,
    at: AT,
  });

  assert.equal(result.valid, false);
});

test("raw private key material is not present in the signed governance decision", () => {
  const f = fixture();

  const serialized = JSON.stringify(f.decision);

  assert.equal(serialized.includes(f.governance.privateKeyPem), false);
  assert.equal("privateKeyPem" in f.decision, false);
});
