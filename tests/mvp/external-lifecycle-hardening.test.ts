import assert from "node:assert/strict";
import test from "node:test";
import { unlinkSync } from "node:fs";
import { createHash, generateKeyPairSync, sign } from "node:crypto";

import {
  executeExternally,
} from "../../external-mvp/executor.js";

import {
  DurableExternalReplayStore,
  MemoryExternalReplayStore,
} from "../../external-mvp/replay-store.js";

import {
  createAgentPassport,
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
    .map(
      key =>
        `${JSON.stringify(key)}:${canonical(record[key])}`,
    )
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
      agentId: "lifecycle-executor",
      passportId: "lifecycle-passport",
      issuerId: "issuer-mvp",
      origin: "giia-mvp",
      jurisdiction: "NG",
      operatorId: "operator-mvp",
      ownerId: "owner-mvp",
      agentType: "governed-agent",
      modelType: "lifecycle-executor",
      lifecycle: "production",
      deploymentEnvironment: "controlled",
      declaredCapabilities: ["READ"],
      permittedCapabilities: ["READ"],
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
    requestId: "lifecycle-request",
    action: "READ",
    resource: "resource-001",
  };

  const decision = {
    decisionId: "lifecycle-decision",
    requestId: "lifecycle-request",
    decision: "ALLOW" as const,
    authoritative: true as const,
    actorId: "mvp-identity-001",
    action: "READ",
    target: "resource-001",
    payloadHash: hash(payload),
    constitutionVersion: "GIIA-CONST-0.1.1",
    issuedAt: "2026-10-04T10:00:00.000Z",
    expiresAt: "2026-10-04T11:00:00.000Z",
    nonce: "lifecycle-nonce",
    humanApprovalRequired: false,
    humanApprovalVerified: false,
    revocationState: "active" as const,
    shutdownState: "clear" as const,
  };

  const authorizationBase = {
    authorizationId: "lifecycle-auth",
    executorId: "lifecycle-executor",
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

test("external authorization executes exactly once", () => {
  const f = fixture();
  const replayStore = new MemoryExternalReplayStore();

  const first = executeExternally({
    ...f,
    capability: "READ",
    at: "2026-10-04T10:10:00.000Z",
    replayStore,
  });

  assert.equal(first.executed, true);
  assert.ok(first.evidence);

  const second = executeExternally({
    ...f,
    capability: "READ",
    at: "2026-10-04T10:11:00.000Z",
    replayStore,
  });

  assert.equal(second.executed, false);
  assert.equal(second.reason, "EXTERNAL_AUTHORIZATION_REPLAYED");
  assert.equal(second.evidence, null);
});

test("revoked decision blocks external enforcement", () => {
  const f = fixture();

  const result = executeExternally({
    ...f,
    decision: {
      ...f.decision,
      revocationState: "revoked",
    },
    capability: "READ",
    at: "2026-10-04T10:10:00.000Z",
    replayStore: new MemoryExternalReplayStore(),
  });

  assert.equal(result.executed, false);
  assert.equal(result.reason, "GOVERNANCE_DECISION_REVOKED");
});

test("terminal shutdown blocks external enforcement", () => {
  const f = fixture();

  const result = executeExternally({
    ...f,
    decision: {
      ...f.decision,
      shutdownState: "active",
    },
    capability: "READ",
    at: "2026-10-04T10:10:00.000Z",
    replayStore: new MemoryExternalReplayStore(),
  });

  assert.equal(result.executed, false);
  assert.equal(result.reason, "TERMINAL_SHUTDOWN_ACTIVE");
});

test("required human approval blocks external enforcement", () => {
  const f = fixture();

  const result = executeExternally({
    ...f,
    decision: {
      ...f.decision,
      humanApprovalRequired: true,
      humanApprovalVerified: false,
    },
    capability: "READ",
    at: "2026-10-04T10:10:00.000Z",
    replayStore: new MemoryExternalReplayStore(),
  });

  assert.equal(result.executed, false);
  assert.equal(result.reason, "REQUIRED_HUMAN_APPROVAL_MISSING");
});

test("expired passport blocks external enforcement", () => {
  const f = fixture();
  const expiredPassportKeys = generateKeyPairSync("ed25519");

  const expiredPassport = createAgentPassport(
    {
      ...f.passport,
      issuedAt: "2026-01-01T00:00:00.000Z",
      expiresAt: "2026-10-04T10:05:00.000Z",
      publicKeyPem: expiredPassportKeys.publicKey.export({
        type: "spki",
        format: "pem",
      }) as string,
    },
    expiredPassportKeys.privateKey,
  );

  const result = executeExternally({
    ...f,
    passport: expiredPassport,
    capability: "READ",
    at: "2026-10-04T10:10:00.000Z",
    replayStore: new MemoryExternalReplayStore(),
  });

  assert.equal(result.executed, false);
  assert.equal(
    result.reason,
    "AGENT_PASSPORT_INVALID:PASSPORT_EXPIRED",
  );
  assert.equal(result.evidence, null);
});


test("durable replay state survives executor-store restart", () => {
  const f = fixture();
  const filePath = `runtime-data/test-external-replay-${process.pid}.json`;

  try {
    const firstStore = new DurableExternalReplayStore(filePath);

    const first = executeExternally({
      ...f,
      capability: "READ",
      at: "2026-10-04T10:10:00.000Z",
      replayStore: firstStore,
    });

    assert.equal(first.executed, true);
    assert.ok(first.evidence);

    const restartedStore = new DurableExternalReplayStore(filePath);

    assert.equal(
      restartedStore.has(f.authorization.authorizationId),
      true,
    );

    const second = executeExternally({
      ...f,
      capability: "READ",
      at: "2026-10-04T10:11:00.000Z",
      replayStore: restartedStore,
    });

    assert.equal(second.executed, false);
    assert.equal(
      second.reason,
      "EXTERNAL_AUTHORIZATION_REPLAYED",
    );
    assert.equal(second.evidence, null);
  } finally {
    try {
      unlinkSync(filePath);
    } catch {}
    try {
      unlinkSync(`${filePath}.tmp`);
    } catch {}
  }
});
