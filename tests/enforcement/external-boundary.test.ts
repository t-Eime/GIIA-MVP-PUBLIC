import test from "node:test";
import assert from "node:assert/strict";
import {
  createHash,
  generateKeyPairSync,
  sign,
} from "node:crypto";

import {
  verifyExternalEnforcement,
  type ExternalEnforcementAuthorization,
  type GovernanceDecisionReference,
} from "../../src/enforcement/external-boundary.js";

import {
  createAgentPassport,
  type AgentPassport,
} from "../../src/identity/agent-passport.js";

function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(canonical).join(",")}]`;
  }

  const record = value as Record<string, unknown>;

  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`)
    .join(",")}}`;
}

function hash(value: unknown): string {
  return createHash("sha256")
    .update(canonical(value), "utf8")
    .digest("hex");
}

function fixture() {
  const passportKeys = generateKeyPairSync("ed25519");
  const executorKeys = generateKeyPairSync("ed25519");

  const passportBase = {
    passportId: "passport-agent-001",
    agentId: "external-executor-001",
    issuerId: "issuer-001",
    origin: "lab.example/agent-001",
    jurisdiction: "NG",
    operatorId: "operator-001",
    ownerId: "owner-001",
    agentType: "governed-agent",
    modelType: "test-model",
    lifecycle: "production" as const,
    deploymentEnvironment: "controlled-test",
    declaredCapabilities: ["TEST_ACTION"],
    permittedCapabilities: ["TEST_ACTION"],
    credentialIds: ["credential-001"],
    delegationIds: ["delegation-001"],
    issuedAt: "2026-01-01T00:00:00.000Z",
    expiresAt: "2027-01-01T00:00:00.000Z",
    publicKeyPem: passportKeys.publicKey.export({
      type: "spki",
      format: "pem",
    }) as string,
  };

  const passport = createAgentPassport(
    passportBase,
    passportKeys.privateKey,
  );

  const payload = {
    operation: "test",
    value: 42,
  };

  const decision: GovernanceDecisionReference = {
    decisionId: "decision-001",
    requestId: "request-001",
    decision: "ALLOW",
    authoritative: true,
    actorId: "actor-001",
    action: "TEST_ACTION",
    target: "target-001",
    payloadHash: hash(payload),
    constitutionVersion: "GIIA-CONST-0.1.1",
    issuedAt: "2026-09-29T10:00:00.000Z",
    expiresAt: "2026-09-29T11:00:00.000Z",
    nonce: "nonce-001",
    humanApprovalRequired: false,
    humanApprovalVerified: false,
    revocationState: "active",
    shutdownState: "clear",
  };

  const authorizationBase = {
    authorizationId: "external-auth-001",
    executorId: "external-executor-001",
    passportId: "passport-agent-001",
    decisionId: decision.decisionId,
    requestId: decision.requestId,
    actorId: decision.actorId,
    action: decision.action,
    target: decision.target,
    payloadHash: decision.payloadHash,
    constitutionVersion: decision.constitutionVersion,
    nonce: decision.nonce,
    issuedAt: decision.issuedAt,
    expiresAt: decision.expiresAt,
    signingAlgorithm: "Ed25519" as const,
    publicKeyPem: executorKeys.publicKey.export({
      type: "spki",
      format: "pem",
    }) as string,
  };

  const signatureBase64 = sign(
    null,
    Buffer.from(canonical(authorizationBase), "utf8"),
    executorKeys.privateKey,
  ).toString("base64");

  const authorization: ExternalEnforcementAuthorization = {
    ...authorizationBase,
    signatureBase64,
  };

  return {
    passport,
    decision,
    authorization,
    payload,
  };
}

test("valid external enforcement authorization is permitted", () => {
  const f = fixture();

  const result = verifyExternalEnforcement(
    f.decision,
    f.authorization,
    f.passport,
    f.payload,
    "TEST_ACTION",
    "2026-09-29T10:30:00.000Z",
  );

  assert.equal(result.decision, "PERMITTED");
});

test("GIIA ALLOW does not itself create execution authority", () => {
  const f = fixture();

  const broken = {
    ...f.authorization,
    signatureBase64: "",
  };

  const result = verifyExternalEnforcement(
    f.decision,
    broken,
    f.passport,
    f.payload,
    "TEST_ACTION",
    "2026-09-29T10:30:00.000Z",
  );

  assert.equal(result.decision, "BLOCKED");
  assert.equal(result.reason, "EXTERNAL_AUTHORIZATION_SIGNATURE_REQUIRED");
});

test("payload substitution is blocked", () => {
  const f = fixture();

  const result = verifyExternalEnforcement(
    f.decision,
    f.authorization,
    f.passport,
    { operation: "tampered" },
    "TEST_ACTION",
    "2026-09-29T10:30:00.000Z",
  );

  assert.equal(result.decision, "BLOCKED");
  assert.equal(result.reason, "PAYLOAD_HASH_MISMATCH");
});

test("action substitution is blocked", () => {
  const f = fixture();

  const result = verifyExternalEnforcement(
    f.decision,
    f.authorization,
    f.passport,
    f.payload,
    "OTHER_ACTION",
    "2026-09-29T10:30:00.000Z",
  );

  assert.equal(result.decision, "BLOCKED");
  assert.equal(result.reason, "CAPABILITY_NOT_DECLARED_AND_PERMITTED");
});

test("decision expiration blocks enforcement", () => {
  const f = fixture();

  const result = verifyExternalEnforcement(
    f.decision,
    f.authorization,
    f.passport,
    f.payload,
    "TEST_ACTION",
    "2026-09-29T12:00:00.000Z",
  );

  assert.equal(result.decision, "BLOCKED");
});

test("shutdown blocks enforcement", () => {
  const f = fixture();

  const result = verifyExternalEnforcement(
    {
      ...f.decision,
      shutdownState: "active",
    },
    f.authorization,
    f.passport,
    f.payload,
    "TEST_ACTION",
    "2026-09-29T10:30:00.000Z",
  );

  assert.equal(result.decision, "BLOCKED");
});

test("human approval requirement cannot be bypassed", () => {
  const f = fixture();

  const result = verifyExternalEnforcement(
    {
      ...f.decision,
      humanApprovalRequired: true,
      humanApprovalVerified: false,
    },
    f.authorization,
    f.passport,
    f.payload,
    "TEST_ACTION",
    "2026-09-29T10:30:00.000Z",
  );

  assert.equal(result.decision, "BLOCKED");
  assert.equal(result.reason, "REQUIRED_HUMAN_APPROVAL_MISSING");
});

test("passport identity substitution is blocked", () => {
  const f = fixture();

  const result = verifyExternalEnforcement(
    f.decision,
    f.authorization,
    {
      ...f.passport,
      agentId: "attacker-agent",
    } as AgentPassport,
    f.payload,
    "TEST_ACTION",
    "2026-09-29T10:30:00.000Z",
  );

  assert.equal(result.decision, "BLOCKED");
});

test("revoked agent passport is blocked", () => {
  const f = fixture();

  const result = verifyExternalEnforcement(
    f.decision,
    f.authorization,
    {
      ...f.passport,
      lifecycle: "revoked",
    } as AgentPassport,
    f.payload,
    "TEST_ACTION",
    "2026-09-29T10:30:00.000Z",
  );

  assert.equal(result.decision, "BLOCKED");
});

test("external authorization binding cannot be changed without a new signature", () => {
  const f = fixture();

  const result = verifyExternalEnforcement(
    f.decision,
    {
      ...f.authorization,
      target: "different-target",
    },
    f.passport,
    f.payload,
    "TEST_ACTION",
    "2026-09-29T10:30:00.000Z",
  );

  assert.equal(result.decision, "BLOCKED");
  assert.equal(result.reason, "ENFORCEMENT_BINDING_MISMATCH");
});
