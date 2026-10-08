import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";

import {
  createAgentPassport,
  passportAllowsCapability,
  verifyAgentPassport,
} from "../../src/identity/agent-passport.js";

function fixture() {
  const keys = generateKeyPairSync("ed25519");

  const passport = createAgentPassport(
    {
      passportId: "passport-001",
      agentId: "agent-001",
      issuerId: "issuer-001",
      origin: "controlled-origin",
      jurisdiction: "NG",
      operatorId: "operator-001",
      ownerId: "owner-001",
      agentType: "test-agent",
      modelType: "test-model",
      lifecycle: "production",
      deploymentEnvironment: "controlled-test",
      declaredCapabilities: ["READ"],
      permittedCapabilities: ["READ"],
      credentialIds: ["credential-001"],
      delegationIds: ["delegation-001"],
      issuedAt: "2026-01-01T00:00:00.000Z",
      expiresAt: "2027-01-01T00:00:00.000Z",
      publicKeyPem: keys.publicKey.export({
        type: "spki",
        format: "pem",
      }) as string,
    },
    keys.privateKey,
  );

  return passport;
}

test("valid signed passport verifies", () => {
  const passport = fixture();

  const result = verifyAgentPassport(
    passport,
    "2026-09-29T10:30:00.000Z",
  );

  assert.equal(result.valid, true);
  assert.ok(result.passportHash);
});

test("passport signature tampering fails", () => {
  const passport = fixture();

  const result = verifyAgentPassport(
    {
      ...passport,
      operatorId: "attacker",
    },
    "2026-09-29T10:30:00.000Z",
  );

  assert.equal(result.valid, false);
});

test("revoked passport fails", () => {
  const passport = fixture();

  const result = verifyAgentPassport(
    {
      ...passport,
      lifecycle: "revoked",
    },
    "2026-09-29T10:30:00.000Z",
  );

  assert.equal(result.valid, false);
});

test("expired passport fails", () => {
  const passport = fixture();

  const result = verifyAgentPassport(
    passport,
    "2028-01-01T00:00:00.000Z",
  );

  assert.equal(result.valid, false);
});

test("declared capability alone is not enough", () => {
  const passport = fixture();

  assert.equal(
    passportAllowsCapability(passport, "WRITE"),
    false,
  );
});

test("capability requires both declaration and permission", () => {
  const passport = fixture();

  assert.equal(
    passportAllowsCapability(passport, "READ"),
    true,
  );
});
