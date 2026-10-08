import test from "node:test";
import assert from "node:assert/strict";

import {
  verifyAgentTrustBoundary,
} from "../../src/identity/agent-trust-boundary.js";

import {
  createAgentPassportKeyPair,
  createAgentPassport,
} from "../../src/identity/agent-passport.js";

import type {
  TrustChainInput,
} from "../../src/trust/service.js";

function baseFixture() {
  const keys = createAgentPassportKeyPair();

  const passport = createAgentPassport({
    passportId: "passport-agent-001",
    agentId: "agent-001",
    issuerId: "issuer-001",
    origin: "test",
    jurisdiction: "TEST",
    operatorId: "operator-001",
    ownerId: "owner-001",
    agentType: "test-agent",
    modelType: "test-model",
    lifecycle: "production",
    deploymentEnvironment: "test",
    declaredCapabilities: ["read:test"],
    permittedCapabilities: ["read:test"],
    credentialIds: ["credential-001"],
    delegationIds: ["delegation-001"],
    issuedAt: "2026-09-29T10:00:00.000Z",
    expiresAt: "2027-09-29T10:00:00.000Z",
    publicKeyPem: keys.publicKey.export({
      type: "spki",
      format: "pem",
    }).toString(),
  }, keys.privateKey);

  const trustChain: TrustChainInput = {
    root: {
      id: "root-001",
      subject: "issuer-001",
      signingKeyId: "root-key",
      issuedAt: "2026-09-29T09:00:00.000Z",
      status: "active",
      provenance: "test",
    },
    rootKey: {
      id: "root-key",
      algorithm: "Ed25519",
      purpose: "root",
      publicKeyPem: passport.publicKeyPem,
      createdAt: "2026-09-29T09:00:00.000Z",
      notBefore: "2026-09-29T09:00:00.000Z",
      status: "active",
      provenance: "test",
    },
    anchor: {
      id: "anchor-001",
      subject: "issuer-001",
      rootId: "root-001",
      signingKeyId: "root-key",
      constraints: [],
      issuedAt: "2026-09-29T09:00:00.000Z",
      status: "active",
      provenance: "test",
      signature: "invalid-fixture",
    },
    anchorKey: {
      id: "root-key",
      algorithm: "Ed25519",
      purpose: "root",
      publicKeyPem: passport.publicKeyPem,
      createdAt: "2026-09-29T09:00:00.000Z",
      notBefore: "2026-09-29T09:00:00.000Z",
      status: "active",
      provenance: "test",
    },
    delegation: {
      id: "delegation-001",
      issuerAnchorId: "anchor-001",
      delegateeId: "agent-001",
      signingKeyId: "root-key",
      constraints: ["read:test"],
      issuedAt: "2026-09-29T09:00:00.000Z",
      status: "active",
      provenance: "test",
      signature: "invalid-fixture",
    },
    delegationKey: {
      id: "root-key",
      algorithm: "Ed25519",
      purpose: "root",
      publicKeyPem: passport.publicKeyPem,
      createdAt: "2026-09-29T09:00:00.000Z",
      notBefore: "2026-09-29T09:00:00.000Z",
      status: "active",
      provenance: "test",
    },
    credential: {
      id: "credential-001",
      subject: "agent-001",
      issuerDelegationId: "delegation-001",
      claims: {},
      issuedAt: "2026-09-29T09:00:00.000Z",
      status: "active",
      provenance: "test",
      signature: "invalid-fixture",
    },
    at: "2026-09-29T10:30:00.000Z",
  };

  return {
    passport,
    passportPrivateKey: keys.privateKey,
    trustChain,
    requiredCapability: "read:test",
  };
}

test("agent trust boundary exists and fails closed on invalid trust", () => {
  const f = baseFixture();

  const result = verifyAgentTrustBoundary({
    passport: f.passport,
    trustChain: f.trustChain,
    requiredCapability: f.requiredCapability,
    expectedAgentId: "agent-001",
    expectedIssuerId: "issuer-001",
    expectedOperatorId: "operator-001",
    expectedOwnerId: "owner-001",
    at: "2026-09-29T10:30:00.000Z",
  });

  assert.equal(result.decision, "BLOCKED");
  assert.equal(result.reason, "TRUST_CHAIN_INVALID");
});

test("agent substitution is blocked", () => {
  const f = baseFixture();

  const result = verifyAgentTrustBoundary({
    passport: f.passport,
    trustChain: f.trustChain,
    requiredCapability: f.requiredCapability,
    expectedAgentId: "different-agent",
    expectedIssuerId: "issuer-001",
    at: "2026-09-29T10:30:00.000Z",
  });

  assert.equal(result.decision, "BLOCKED");
  assert.equal(result.reason, "AGENT_ID_MISMATCH");
});

test("issuer substitution is blocked", () => {
  const f = baseFixture();

  const result = verifyAgentTrustBoundary({
    passport: f.passport,
    trustChain: f.trustChain,
    requiredCapability: f.requiredCapability,
    expectedAgentId: "agent-001",
    expectedIssuerId: "different-issuer",
    at: "2026-09-29T10:30:00.000Z",
  });

  assert.equal(result.decision, "BLOCKED");
  assert.equal(result.reason, "ISSUER_MISMATCH");
});

test("capability escalation is blocked", () => {
  const f = baseFixture();

  const result = verifyAgentTrustBoundary({
    passport: f.passport,
    trustChain: f.trustChain,
    requiredCapability: "write:production",
    expectedAgentId: "agent-001",
    expectedIssuerId: "issuer-001",
    at: "2026-09-29T10:30:00.000Z",
  });

  assert.equal(result.decision, "BLOCKED");
  assert.equal(result.reason, "CAPABILITY_NOT_PERMITTED");
});

test("expired passport is blocked", () => {
  const f = baseFixture();

  const result = verifyAgentTrustBoundary({
    passport: f.passport,
    trustChain: f.trustChain,
    requiredCapability: f.requiredCapability,
    expectedAgentId: "agent-001",
    expectedIssuerId: "issuer-001",
    at: "2028-01-01T00:00:00.000Z",
  });

  assert.equal(result.decision, "BLOCKED");
  assert.equal(result.reason, "PASSPORT_INVALID");
});

test("revoked passport is blocked", () => {
  const f = baseFixture();

  const passport = {
    ...f.passport,
    lifecycle: "revoked" as const,
  };

  const result = verifyAgentTrustBoundary({
    passport,
    trustChain: f.trustChain,
    requiredCapability: f.requiredCapability,
    expectedAgentId: "agent-001",
    expectedIssuerId: "issuer-001",
    at: "2026-09-29T10:30:00.000Z",
  });

  assert.equal(result.decision, "BLOCKED");
  assert.equal(result.reason, "PASSPORT_INVALID");
});

test("operator substitution is blocked", () => {
  const f = baseFixture();

  const result = verifyAgentTrustBoundary({
    passport: f.passport,
    trustChain: f.trustChain,
    requiredCapability: f.requiredCapability,
    expectedAgentId: "agent-001",
    expectedIssuerId: "issuer-001",
    expectedOperatorId: "different-operator",
    at: "2026-09-29T10:30:00.000Z",
  });

  assert.equal(result.decision, "BLOCKED");
  assert.equal(result.reason, "OPERATOR_MISMATCH");
});

test("owner substitution is blocked", () => {
  const f = baseFixture();

  const result = verifyAgentTrustBoundary({
    passport: f.passport,
    trustChain: f.trustChain,
    requiredCapability: f.requiredCapability,
    expectedAgentId: "agent-001",
    expectedIssuerId: "issuer-001",
    expectedOwnerId: "different-owner",
    at: "2026-09-29T10:30:00.000Z",
  });

  assert.equal(result.decision, "BLOCKED");
  assert.equal(result.reason, "OWNER_MISMATCH");
});

test("declared capability alone cannot create permission", () => {
  const f = baseFixture();

  const {
    signatureBase64: _signature,
    ...unsignedPassport
  } = f.passport;

  const passport = createAgentPassport({
    ...unsignedPassport,
    permittedCapabilities: [],
  }, f.passportPrivateKey);

  const result = verifyAgentTrustBoundary({
    passport,
    trustChain: f.trustChain,
    requiredCapability: f.requiredCapability,
    expectedAgentId: "agent-001",
    expectedIssuerId: "issuer-001",
    at: "2026-09-29T10:30:00.000Z",
  });

  assert.equal(result.decision, "BLOCKED");
  assert.equal(result.reason, "CAPABILITY_NOT_PERMITTED");
});
