import test from "node:test";
import assert from "node:assert/strict";

import {
  createDevelopmentGovernanceSigningProvider,
  createProductionGovernanceSigningProvider,
  GovernanceSecureSignerUnavailableError,
  governanceSigningPayloadDigest,
} from "../../src/security/governance-signing-provider.js";

test("production governance signer fails closed when secure provider is unavailable", async () => {
  const provider = createProductionGovernanceSigningProvider();

  assert.equal(provider.productionReady, false);
  assert.equal(provider.mode, "PRODUCTION_HARDWARE_THRESHOLD");

  await assert.rejects(
    provider.sign(new TextEncoder().encode("governance-decision")),
    (error: unknown) =>
      error instanceof GovernanceSecureSignerUnavailableError &&
      error.code === "GOVERNANCE_SECURE_SIGNER_UNAVAILABLE",
  );
});

test("production provider does not silently fall back to software signing", async () => {
  const provider = createProductionGovernanceSigningProvider();

  await assert.rejects(
    provider.sign(new TextEncoder().encode("fallback-attempt")),
    (error: unknown) =>
      error instanceof GovernanceSecureSignerUnavailableError &&
      error.code === "GOVERNANCE_SECURE_SIGNER_UNAVAILABLE",
  );
});

test("development signer is explicitly marked non-production", async () => {
  const provider = createDevelopmentGovernanceSigningProvider(
    async (payload) => payload,
  );

  assert.equal(provider.productionReady, false);
  assert.equal(provider.mode, "DEVELOPMENT_SOFTWARE_MULTISIG");
  assert.equal(provider.providerId, "SOFTWARE_ED25519_MULTISIG_DEV_ONLY");

  const payload = new TextEncoder().encode("development-only");
  const result = await provider.sign(payload);

  assert.deepEqual(result, payload);
});

test("empty development signing payload is rejected", async () => {
  const provider = createDevelopmentGovernanceSigningProvider(
    async (payload) => payload,
  );

  await assert.rejects(
    provider.sign(new Uint8Array()),
    /GOVERNANCE_SIGNING_PAYLOAD_REQUIRED/,
  );
});

test("governance signing payload digest is deterministic", () => {
  const payload = new TextEncoder().encode("canonical-governance-material");

  const first = governanceSigningPayloadDigest(payload);
  const second = governanceSigningPayloadDigest(payload);

  assert.equal(first, second);
  assert.match(first, /^[a-f0-9]{64}$/);
});
