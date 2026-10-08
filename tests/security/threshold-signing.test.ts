import assert from "node:assert/strict";
import test from "node:test";

import {
  createProductionThresholdSigner,
  DEVELOPMENT_ONLY_THRESHOLD_SIMULATOR,
  PRODUCTION_THRESHOLD_ALGORITHM,
  THRESHOLD_MEMBER_COUNT,
  THRESHOLD_QUORUM,
  type ThresholdHsmProvider,
} from "../../src/security/threshold-signing.js";

test("P0-E threshold configuration is exactly 3-of-5", () => {
  assert.equal(THRESHOLD_QUORUM, 3);
  assert.equal(THRESHOLD_MEMBER_COUNT, 5);
  assert.equal(PRODUCTION_THRESHOLD_ALGORITHM, "THRESHOLD-3-OF-5-HSM");
});

test("P0-E production threshold signer fails closed without HSM provider", () => {
  assert.throws(
    () => createProductionThresholdSigner(undefined),
    /P0_THRESHOLD_HSM_PROVIDER_REQUIRED/,
  );
});

test("P0-E development/non-threshold signer cannot enter production", () => {
  assert.throws(
    () =>
      createProductionThresholdSigner(
        DEVELOPMENT_ONLY_THRESHOLD_SIMULATOR as unknown as ThresholdHsmProvider,
      ),
    /P0_THRESHOLD_PROVIDER_NOT_PRODUCTION/,
  );
});

test("P0-E wrong production algorithm is rejected", () => {
  const provider = {
    production: true,
    algorithm: "ED25519-MULTISIG-3-OF-5",
    async sign() {
      throw new Error("should never be called");
    },
  } as unknown as ThresholdHsmProvider;

  assert.throws(
    () => createProductionThresholdSigner(provider),
    /P0_THRESHOLD_ALGORITHM_INVALID/,
  );
});

test("P0-E provider result must bind to requested key", async () => {
  const provider: ThresholdHsmProvider = {
    production: true,
    algorithm: PRODUCTION_THRESHOLD_ALGORITHM,
    async sign() {
      return {
        algorithm: PRODUCTION_THRESHOLD_ALGORITHM,
        keyId: "different-key",
        authoritySetFingerprint: "fp",
        signatureBase64: "signature",
      };
    },
  };

  const signer = createProductionThresholdSigner(provider);

  await assert.rejects(
    signer.sign({
      signingDomain: "GIIA-DECISION",
      messageDigest: "digest",
      keyId: "production-threshold-key",
      authoritySetFingerprint: "fp",
    }),
    /P0_THRESHOLD_RESULT_KEY_MISMATCH/,
  );
});

test("P0-E provider result must bind to pinned authority fingerprint", async () => {
  const provider: ThresholdHsmProvider = {
    production: true,
    algorithm: PRODUCTION_THRESHOLD_ALGORITHM,
    async sign() {
      return {
        algorithm: PRODUCTION_THRESHOLD_ALGORITHM,
        keyId: "production-threshold-key",
        authoritySetFingerprint: "attacker-fingerprint",
        signatureBase64: "signature",
      };
    },
  };

  const signer = createProductionThresholdSigner(provider);

  await assert.rejects(
    signer.sign({
      signingDomain: "GIIA-DECISION",
      messageDigest: "digest",
      keyId: "production-threshold-key",
      authoritySetFingerprint: "trusted-fingerprint",
    }),
    /P0_THRESHOLD_RESULT_TRUST_ROOT_MISMATCH/,
  );
});

test("P0-E provider result must contain a genuine threshold signature", async () => {
  const provider: ThresholdHsmProvider = {
    production: true,
    algorithm: PRODUCTION_THRESHOLD_ALGORITHM,
    async sign() {
      return {
        algorithm: PRODUCTION_THRESHOLD_ALGORITHM,
        keyId: "production-threshold-key",
        authoritySetFingerprint: "trusted-fingerprint",
        signatureBase64: "",
      };
    },
  };

  const signer = createProductionThresholdSigner(provider);

  await assert.rejects(
    signer.sign({
      signingDomain: "GIIA-DECISION",
      messageDigest: "digest",
      keyId: "production-threshold-key",
      authoritySetFingerprint: "trusted-fingerprint",
    }),
    /P0_THRESHOLD_SIGNATURE_MISSING/,
  );
});

test("P0-E valid production provider is accepted", async () => {
  const provider: ThresholdHsmProvider = {
    production: true,
    algorithm: PRODUCTION_THRESHOLD_ALGORITHM,
    async sign(request) {
      return {
        algorithm: PRODUCTION_THRESHOLD_ALGORITHM,
        keyId: request.keyId,
        authoritySetFingerprint: request.authoritySetFingerprint,
        signatureBase64: "REAL_PROVIDER_SIGNATURE_PLACEHOLDER",
      };
    },
  };

  const signer = createProductionThresholdSigner(provider);

  const result = await signer.sign({
    signingDomain: "GIIA-DECISION",
    messageDigest: "digest",
    keyId: "production-threshold-key",
    authoritySetFingerprint: "trusted-fingerprint",
  });

  assert.equal(result.algorithm, PRODUCTION_THRESHOLD_ALGORITHM);
  assert.equal(result.keyId, "production-threshold-key");
  assert.equal(result.authoritySetFingerprint, "trusted-fingerprint");
});
