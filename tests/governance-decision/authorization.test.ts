import test from "node:test";
import assert from "node:assert/strict";

import {
  createGovernanceKeyAuthorization,
  verifyGovernanceKeyAuthorization,
} from "../../src/governance-decision/authorization.js";

import {
  createTrustKey,
  createRoot,
  createAnchorWithSecureKey,
  createDelegationWithSecureKey,
  createCredentialWithSecureKey,
} from "../../src/trust/service.js";

import { KeySecurityBoundary } from "../../src/security/key-boundary.js";

const at = "2026-10-04T12:00:00.000Z";

function fixture() {
  const boundary = new KeySecurityBoundary();

  const root = createTrustKey(
    "root-key-1",
    "root",
    "test-root",
    at,
  );

  const anchor = createTrustKey(
    "anchor-key-1",
    "anchor",
    "test-anchor",
    at,
  );

  const delegation = createTrustKey(
    "delegation-key-1",
    "delegation",
    "test-delegation",
    at,
  );

  const governance = createTrustKey(
    "governance-key-1",
    "governance",
    "test-governance",
    at,
  );

  boundary.register(root.key, root.privateKeyPem, at);
  boundary.register(anchor.key, anchor.privateKeyPem, at);
  boundary.register(delegation.key, delegation.privateKeyPem, at);
  boundary.register(governance.key, governance.privateKeyPem, at);

  const rootObject = createRoot(
    "root-1",
    "giia-root",
    root.key.id,
    at,
    "test-root",
  );

  const anchorObject = createAnchorWithSecureKey(
    {
      id: "anchor-1",
      subject: "giia-anchor",
      rootId: rootObject.id,
      signingKeyId: root.key.id,
      constraints: ["governance"],
      issuedAt: at,
      status: "active",
      provenance: "test-anchor",
    },
    {
      boundary,
      keyId: root.key.id,
      purpose: "root",
      at,
    },
  );

  const delegationObject = createDelegationWithSecureKey(
    {
      id: "delegation-1",
      issuerAnchorId: anchorObject.id,
      delegateeId: "authority-1",
      signingKeyId: anchor.key.id,
      constraints: ["governance"],
      issuedAt: at,
      status: "active",
      provenance: "test-delegation",
    },
    {
      boundary,
      keyId: anchor.key.id,
      purpose: "anchor",
      at,
    },
  );

  const credential = createCredentialWithSecureKey(
    {
      id: "credential-1",
      subject: "authority-1",
      issuerDelegationId: delegationObject.id,
      claims: {
        "governance:policy": "true",
      },
      issuedAt: at,
      expiresAt: "2027-01-01T00:00:00.000Z",
      status: "active",
      provenance: "test-credential",
    },
    {
      boundary,
      keyId: delegation.key.id,
      purpose: "delegation",
      at,
    },
  );

  const trustChain = {
    root: rootObject,
    rootKey: root.key,
    anchor: anchorObject,
    anchorKey: anchor.key,
    delegation: delegationObject,
    delegationKey: delegation.key,
    credential,
    at,
  };

  const authorization = createGovernanceKeyAuthorization({
    authorizationId: "gka-1",
    governanceKey: governance.key,
    credential,
    signingAuthorityId: "authority-1",
    issuerDelegationKey: delegation.key,
    trustChain,
    boundary,
    issuedAt: at,
    expiresAt: "2026-12-31T00:00:00.000Z",
  });

  return {
    boundary,
    root,
    anchor,
    delegation,
    governance,
    rootObject,
    anchorObject,
    delegationObject,
    credential,
    trustChain,
    authorization,
  };
}

test("trust-chain-backed governance key authorization verifies", () => {
  const f = fixture();

  assert.equal(
    verifyGovernanceKeyAuthorization({
      authorization: f.authorization,
      governanceKey: f.governance.key,
      credential: f.credential,
      trustChain: f.trustChain,
      at,
    }),
    true,
  );
});

test("governance public-key substitution fails", () => {
  const f = fixture();
  const attacker = createTrustKey(
    "attacker-governance",
    "governance",
    "attacker",
    at,
  );

  assert.equal(
    verifyGovernanceKeyAuthorization({
      authorization: f.authorization,
      governanceKey: attacker.key,
      credential: f.credential,
      trustChain: f.trustChain,
      at,
    }),
    false,
  );
});

test("governance key identity substitution fails", () => {
  const f = fixture();

  const substituted = {
    ...f.governance.key,
    id: "attacker-governance-key",
  };

  assert.equal(
    verifyGovernanceKeyAuthorization({
      authorization: f.authorization,
      governanceKey: substituted,
      credential: f.credential,
      trustChain: f.trustChain,
      at,
    }),
    false,
  );
});

test("authorization signature tampering fails", () => {
  const f = fixture();

  const tampered = {
    ...f.authorization,
    payload: {
      ...f.authorization.payload,
      signingAuthorityId: "attacker",
    },
  };

  assert.equal(
    verifyGovernanceKeyAuthorization({
      authorization: tampered,
      governanceKey: f.governance.key,
      credential: f.credential,
      trustChain: f.trustChain,
      at,
    }),
    false,
  );
});

test("authorization expiry fails closed", () => {
  const f = fixture();

  assert.equal(
    verifyGovernanceKeyAuthorization({
      authorization: f.authorization,
      governanceKey: f.governance.key,
      credential: f.credential,
      trustChain: f.trustChain,
      at: "2027-01-01T00:00:00.000Z",
    }),
    false,
  );
});

test("revoked delegation key cannot authorize governance decisions", () => {
  const f = fixture();

  f.delegation.key.status = "revoked";

  const revokedChain = {
    ...f.trustChain,
    delegationKey: f.delegation.key,
  };

  assert.equal(
    verifyGovernanceKeyAuthorization({
      authorization: f.authorization,
      governanceKey: f.governance.key,
      credential: f.credential,
      trustChain: revokedChain,
      at,
    }),
    false,
  );
});

test("substituted delegation key cannot authorize governance decisions", () => {
  const f = fixture();

  const attacker = createTrustKey(
    "attacker-delegation",
    "delegation",
    "attacker",
    at,
  );

  const substitutedChain = {
    ...f.trustChain,
    delegationKey: attacker.key,
  };

  assert.equal(
    verifyGovernanceKeyAuthorization({
      authorization: f.authorization,
      governanceKey: f.governance.key,
      credential: f.credential,
      trustChain: substitutedChain,
      at,
    }),
    false,
  );
});

test("credential without governance authority cannot authorize key", () => {
  const f = fixture();

  const invalidCredential = {
    ...f.credential,
    claims: {},
  };

  assert.throws(() =>
    createGovernanceKeyAuthorization({
      authorizationId: "gka-invalid",
      governanceKey: f.governance.key,
      credential: invalidCredential,
      signingAuthorityId: "authority-1",
      issuerDelegationKey: f.delegation.key,
      trustChain: {
        ...f.trustChain,
        credential: invalidCredential,
      },
      boundary: f.boundary,
      issuedAt: at,
      expiresAt: "2026-12-31T00:00:00.000Z",
    }),
  );
});

test("non-governance key cannot receive governance authorization", () => {
  const f = fixture();

  const invalidKey = {
    ...f.governance.key,
    purpose: "execution" as const,
  };

  assert.throws(() =>
    createGovernanceKeyAuthorization({
      authorizationId: "gka-invalid",
      governanceKey: invalidKey,
      credential: f.credential,
      signingAuthorityId: "authority-1",
      issuerDelegationKey: f.delegation.key,
      trustChain: f.trustChain,
      boundary: f.boundary,
      issuedAt: at,
      expiresAt: "2026-12-31T00:00:00.000Z",
    }),
  );
});
