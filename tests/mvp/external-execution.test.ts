import assert from "node:assert/strict";
import test from "node:test";
import { createHash, generateKeyPairSync, sign } from "node:crypto";

import {
  executeExternally,
  verifyExternalExecutionEvidence,
} from "../../external-mvp/executor.js";
import {
  MemoryExternalReplayStore,
} from "../../external-mvp/replay-store.js";

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
    .map(key => `${JSON.stringify(key)}:${canonical(record[key])}`)
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

  const passport = createAgentPassport(
    {
        agentId: "external-mvp-executor",
        passportId: "passport-mvp-executor",
        issuerId: "issuer-mvp",
      origin: "giia-mvp",
      jurisdiction: "NG",
      operatorId: "operator-mvp",
      ownerId: "owner-mvp",
      agentType: "governed-agent",
      modelType: "mvp-executor",
      lifecycle: "production",
      deploymentEnvironment: "controlled",
      declaredCapabilities: ["MVP_TEST_ACTION"],
      permittedCapabilities: ["MVP_TEST_ACTION"],
      credentialIds: ["credential-mvp"],
      delegationIds: ["delegation-mvp"],
      issuedAt: "2026-09-01T00:00:00.000Z",
      expiresAt: "2027-01-01T00:00:00.000Z",
      publicKeyPem: passportKeys.publicKey.export({
        type: "spki",
        format: "pem",
      }) as string,
    },
    passportKeys.privateKey,
  );

  const payload = {
    operation: "mvp-test",
    value: 1,
  };

  const decision = {
    decisionId: "mvp-decision-001",
    requestId: "mvp-request-001",
    decision: "ALLOW" as const,
    authoritative: true as const,
    actorId: "mvp-identity-001",
    action: "MVP_TEST_ACTION",
    target: "mvp-target-001",
    payloadHash: hash(payload),
    constitutionVersion: "GIIA-CONST-0.1.1",
    issuedAt: "2026-09-29T10:00:00.000Z",
    expiresAt: "2026-09-29T11:00:00.000Z",
    nonce: "mvp-nonce-001",
    humanApprovalRequired: false,
    humanApprovalVerified: false,
    revocationState: "active" as const,
    shutdownState: "clear" as const,
  };

  const authorizationBase = {
    authorizationId: "mvp-external-auth-001",
    executorId: "external-mvp-executor",
    decisionId: decision.decisionId,
    requestId: decision.requestId,
    actorId: decision.actorId,
    passportId: passport.passportId,
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

  const authorization = {
    ...authorizationBase,
    signatureBase64: sign(
      null,
      Buffer.from(canonical(authorizationBase), "utf8"),
      executorKeys.privateKey,
    ).toString("base64"),
  };

  return {
    passport,
    decision,
    authorization,
    payload,
  };
}

test("external executor executes only after independent GIIA verification", () => {
  const f = fixture();

  const result = executeExternally({
    decision: f.decision,
    authorization: f.authorization,
    passport: f.passport,
    payload: f.payload,
    capability: "MVP_TEST_ACTION",
    at: "2026-09-29T10:30:00.000Z",
    replayStore: new MemoryExternalReplayStore(),
  });

  assert.equal(result.executed, true);
  assert.equal(result.reason, "EXTERNAL_ACTION_EXECUTED");
  assert.ok(result.evidence);
  assert.equal(result.evidence?.outcome, "SUCCESS");
});

test("execution evidence is independently verifiable", () => {
  const f = fixture();

  const result = executeExternally({
    decision: f.decision,
    authorization: f.authorization,
    passport: f.passport,
    payload: f.payload,
    capability: "MVP_TEST_ACTION",
    at: "2026-09-29T10:30:00.000Z",
    replayStore: new MemoryExternalReplayStore(),
  });

  assert.ok(result.evidence);

  assert.deepEqual(
    verifyExternalExecutionEvidence(result.evidence!),
    {
      valid: true,
      reason: "EXECUTION_EVIDENCE_VERIFIED",
    },
  );
});

test("tampering execution-evidence fields fails closed", () => {
  const f = fixture();

  const result = executeExternally({
    decision: f.decision,
    authorization: f.authorization,
    passport: f.passport,
    payload: f.payload,
    capability: "MVP_TEST_ACTION",
    at: "2026-09-29T10:30:00.000Z",
    replayStore: new MemoryExternalReplayStore(),
  });

  assert.ok(result.evidence);

  const evidence = result.evidence!;

  const mutations = [
    { evidenceId: "tampered-evidence" },
    { decisionId: "tampered-decision" },
    { authorizationId: "tampered-authorization" },
    { executorId: "tampered-executor" },
    { action: "tampered-action" },
    { target: "tampered-target" },
    { payloadHash: "tampered-payload-hash" },
    { executedAt: "2026-09-29T10:31:00.000Z" },
    { outcome: "FAILURE" as const },
    { verificationReason: "tampered-reason" },
  ];

  for (const mutation of mutations) {
    const tampered = {
      ...evidence,
      ...mutation,
    };

    const verification =
      verifyExternalExecutionEvidence(tampered);

    assert.equal(
      verification.valid,
      false,
      `tampering should fail: ${Object.keys(mutation)[0]}`,
    );

    assert.equal(
      verification.reason,
      "EXECUTION_EVIDENCE_HASH_MISMATCH",
    );
  }
});

test("tampering execution-evidence hash fails closed", () => {
  const f = fixture();

  const result = executeExternally({
    decision: f.decision,
    authorization: f.authorization,
    passport: f.passport,
    payload: f.payload,
    capability: "MVP_TEST_ACTION",
    at: "2026-09-29T10:30:00.000Z",
    replayStore: new MemoryExternalReplayStore(),
  });

  assert.ok(result.evidence);

  const tampered = {
    ...result.evidence,
    evidenceHash: "0".repeat(64),
  };

  assert.deepEqual(
    verifyExternalExecutionEvidence(tampered),
    {
      valid: false,
      reason: "EXECUTION_EVIDENCE_HASH_MISMATCH",
    },
  );
});

test("tampered payload never executes", () => {
  const f = fixture();

  const result = executeExternally({
    decision: f.decision,
    authorization: f.authorization,
    passport: f.passport,
    payload: {
      operation: "mvp-test",
      value: 999,
    },
    capability: "MVP_TEST_ACTION",
    at: "2026-09-29T10:30:00.000Z",
    replayStore: new MemoryExternalReplayStore(),
  });

  assert.equal(result.executed, false);
  assert.equal(result.reason, "PAYLOAD_HASH_MISMATCH");
  assert.equal(result.evidence, null);
});

test("expired decision never executes", () => {
  const f = fixture();

  const result = executeExternally({
    decision: f.decision,
    authorization: f.authorization,
    passport: f.passport,
    payload: f.payload,
    capability: "MVP_TEST_ACTION",
    at: "2026-09-29T12:00:00.000Z",
    replayStore: new MemoryExternalReplayStore(),
  });

  assert.equal(result.executed, false);
  assert.equal(result.evidence, null);
});

test("authorization substitution never executes", () => {
  const f = fixture();

  const result = executeExternally({
    decision: f.decision,
    authorization: {
      ...f.authorization,
      target: "attacker-target",
    },
    passport: f.passport,
    payload: f.payload,
    capability: "MVP_TEST_ACTION",
    at: "2026-09-29T10:30:00.000Z",
    replayStore: new MemoryExternalReplayStore(),
  });

  assert.equal(result.executed, false);
  assert.equal(result.reason, "ENFORCEMENT_BINDING_MISMATCH");
  assert.equal(result.evidence, null);
});

test("capability substitution never executes", () => {
  const f = fixture();

  const result = executeExternally({
    decision: f.decision,
    authorization: f.authorization,
    passport: f.passport,
    payload: f.payload,
    capability: "FORBIDDEN_ACTION",
    at: "2026-09-29T10:30:00.000Z",
    replayStore: new MemoryExternalReplayStore(),
  });

  assert.equal(result.executed, false);
  assert.equal(
    result.reason,
    "CAPABILITY_NOT_DECLARED_AND_PERMITTED",
  );
  assert.equal(result.evidence, null);
});
